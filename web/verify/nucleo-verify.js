"use strict";
var NucleoVerify = (() => {
  var __defProp = Object.defineProperty;
  var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
  var __getOwnPropNames = Object.getOwnPropertyNames;
  var __hasOwnProp = Object.prototype.hasOwnProperty;
  var __export = (target, all) => {
    for (var name in all)
      __defProp(target, name, { get: all[name], enumerable: true });
  };
  var __copyProps = (to, from, except, desc) => {
    if (from && typeof from === "object" || typeof from === "function") {
      for (let key of __getOwnPropNames(from))
        if (!__hasOwnProp.call(to, key) && key !== except)
          __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
    }
    return to;
  };
  var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);

  // src/index.ts
  var index_exports = {};
  __export(index_exports, {
    ALG_COSIGNATURE_V1: () => ALG_COSIGNATURE_V1,
    ALG_ED25519: () => ALG_ED25519,
    MAGIC: () => MAGIC2,
    NO_PROVABLE_TIME: () => NO_PROVABLE_TIME,
    SEPARATOR: () => SEPARATOR,
    ed25519Available: () => ed25519Available,
    equal: () => equal,
    fromBase64: () => fromBase64,
    fromHex: () => fromHex,
    keyId: () => keyId,
    leafHash: () => leafHash,
    nodeHash: () => nodeHash,
    parseCheckpoint: () => parseCheckpoint,
    parseNote: () => parseNote,
    parseProof: () => parseProof,
    parseReceipt: () => parseReceipt,
    receiptText: () => receiptText,
    sha256: () => sha256,
    toBase64: () => toBase64,
    toHex: () => toHex,
    utf8: () => utf8,
    verifyEd25519: () => verifyEd25519,
    verifyInclusion: () => verifyInclusion,
    verifyReceipt: () => verifyReceipt
  });

  // src/bytes.ts
  function utf8(s) {
    return new TextEncoder().encode(s);
  }
  function fromHex(s) {
    if (s.length % 2 !== 0) throw new Error(`hex de longitud impar: ${s.length}`);
    const out = new Uint8Array(s.length / 2);
    for (let i = 0; i < out.length; i++) {
      const byte = Number.parseInt(s.slice(i * 2, i * 2 + 2), 16);
      if (Number.isNaN(byte)) throw new Error(`hex inv\xE1lido en la posici\xF3n ${i * 2}`);
      out[i] = byte;
    }
    return out;
  }
  function toHex(b) {
    let out = "";
    for (const x of b) out += x.toString(16).padStart(2, "0");
    return out;
  }
  function fromBase64(s) {
    const bin = atob(s);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }
  function toBase64(b) {
    let bin = "";
    for (const x of b) bin += String.fromCharCode(x);
    return btoa(bin);
  }
  function concat(...parts) {
    let n = 0;
    for (const p of parts) n += p.length;
    const out = new Uint8Array(n);
    let at = 0;
    for (const p of parts) {
      out.set(p, at);
      at += p.length;
    }
    return out;
  }
  function equal(a, b) {
    if (a.length !== b.length) return false;
    for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
    return true;
  }
  function readUint64BE(b, at) {
    let v = 0n;
    for (let i = 0; i < 8; i++) v = v * 256n + BigInt(b[at + i] ?? 0);
    return v;
  }

  // src/checkpoint.ts
  function parseCheckpoint(text) {
    if (!text.endsWith("\n")) throw new Error("el checkpoint no termina en salto de l\xEDnea");
    const lines = text.slice(0, -1).split("\n");
    if (lines.length !== 3) {
      throw new Error(`el checkpoint tiene ${lines.length} l\xEDneas, se esperaban 3`);
    }
    const [origin, sizeLine, rootLine] = lines;
    if (origin.length === 0) throw new Error("origin vac\xEDo");
    if (!/^(0|[1-9][0-9]*)$/.test(sizeLine)) {
      throw new Error(`tama\xF1o no can\xF3nico: ${JSON.stringify(sizeLine)}`);
    }
    const rootHash = fromBase64(rootLine);
    if (rootHash.length !== 32) {
      throw new Error(`la ra\xEDz mide ${rootHash.length} bytes, se esperaban 32`);
    }
    if (toBase64(rootHash) !== rootLine) {
      throw new Error("la ra\xEDz no est\xE1 en base64 can\xF3nico");
    }
    return { origin, size: BigInt(sizeLine), rootHash };
  }

  // src/cosignature.ts
  var COSIGNATURE_SIZE = 72;
  function parseCosignature(blob) {
    if (blob.length !== COSIGNATURE_SIZE) return null;
    return { timestamp: readUint64BE(blob, 0), signature: blob.slice(8) };
  }
  function cosignedMessage(timestamp, noteText) {
    return concat(utf8(`cosignature/v1
time ${timestamp.toString()}
`), noteText);
  }

  // src/crypto.ts
  function subtle() {
    const c = globalThis.crypto;
    if (!c?.subtle) {
      throw new Error(
        "este entorno no expone WebCrypto (SubtleCrypto). Hace falta Node >= 18.4 o un navegador moderno, y una p\xE1gina servida por https o desde localhost."
      );
    }
    return c.subtle;
  }
  async function sha256(data) {
    const buf = await subtle().digest("SHA-256", data);
    return new Uint8Array(buf);
  }
  async function verifyEd25519(publicKey, signature, message) {
    if (publicKey.length !== 32 || signature.length !== 64) return false;
    try {
      const key = await subtle().importKey(
        "raw",
        publicKey,
        { name: "Ed25519" },
        false,
        ["verify"]
      );
      return await subtle().verify(
        { name: "Ed25519" },
        key,
        signature,
        message
      );
    } catch {
      return false;
    }
  }
  async function ed25519Available() {
    try {
      await subtle().importKey("raw", new Uint8Array(32), { name: "Ed25519" }, false, [
        "verify"
      ]);
      return true;
    } catch {
      return false;
    }
  }

  // src/jcs.ts
  function jsonKeysAreSorted(raw) {
    let obj;
    try {
      obj = JSON.parse(raw);
    } catch {
      return false;
    }
    if (typeof obj !== "object" || obj === null || Array.isArray(obj)) return false;
    const keys = Object.keys(obj);
    for (let i = 1; i < keys.length; i++) {
      if (compareUTF16(keys[i - 1], keys[i]) >= 0) return false;
    }
    return true;
  }
  function compareUTF16(a, b) {
    const n = Math.min(a.length, b.length);
    for (let i = 0; i < n; i++) {
      const d = a.charCodeAt(i) - b.charCodeAt(i);
      if (d !== 0) return d;
    }
    return a.length - b.length;
  }

  // src/merkle.ts
  async function leafHash(sha2562, data) {
    return sha2562(concat(new Uint8Array([0]), data));
  }
  async function nodeHash(sha2562, left, right) {
    return sha2562(concat(new Uint8Array([1]), left, right));
  }
  async function verifyInclusion(sha2562, leafData, m, n, proof, root) {
    if (m < 0n || n <= 0n || m >= n) return false;
    let fn = m;
    let sn = n - 1n;
    let r = await leafHash(sha2562, leafData);
    for (const p of proof) {
      if (sn === 0n) return false;
      if (fn % 2n === 1n || fn === sn) {
        r = await nodeHash(sha2562, p, r);
        while (fn % 2n === 0n && fn !== 0n) {
          fn /= 2n;
          sn /= 2n;
        }
      } else {
        r = await nodeHash(sha2562, r, p);
      }
      fn /= 2n;
      sn /= 2n;
    }
    if (sn !== 0n) return false;
    return equal(r, root);
  }

  // src/note.ts
  var SIG_PREFIX = "\u2014 ";
  function parseNote(msg) {
    const at = msg.lastIndexOf("\n\n");
    if (at < 0) throw new Error("la nota no separa cuerpo y firmas");
    const text = msg.slice(0, at + 1);
    const sigBlock = msg.slice(at + 2);
    const sigs = [];
    for (const line of sigBlock.split("\n")) {
      if (!line.startsWith(SIG_PREFIX)) continue;
      const sp = line.lastIndexOf(" ");
      if (sp < 0) continue;
      const name = line.slice(SIG_PREFIX.length, sp);
      let blob;
      try {
        blob = fromBase64(line.slice(sp + 1));
      } catch {
        continue;
      }
      if (blob.length < 5) continue;
      const keyId2 = uint32BE(blob, 0);
      sigs.push({ name, keyId: keyId2, signature: blob.slice(4), line });
    }
    if (sigs.length === 0) throw new Error("la nota no trae ninguna l\xEDnea de firma");
    return { text, textBytes: utf8(text), sigs };
  }
  async function keyId(sha2562, name, alg, publicKey) {
    const prefix = utf8(name + "\n");
    const buf = new Uint8Array(prefix.length + 1 + publicKey.length);
    buf.set(prefix, 0);
    buf[prefix.length] = alg;
    buf.set(publicKey, prefix.length + 1);
    const h = await sha2562(buf);
    return uint32BE(h, 0);
  }
  function uint32BE(b, at) {
    return b[at] * 2 ** 24 + b[at + 1] * 2 ** 16 + b[at + 2] * 2 ** 8 + b[at + 3];
  }
  var ALG_ED25519 = 1;
  var ALG_COSIGNATURE_V1 = 4;

  // src/proof.ts
  var MAGIC = "c2sp.org/tlog-proof@v1";
  function parseProof(data) {
    const lines = data.split("\n");
    if (lines[0] !== MAGIC) {
      throw new Error(`se esperaba ${MAGIC} en la primera l\xEDnea`);
    }
    const indexLine = lines[1];
    if (indexLine === void 0 || !/^(0|[1-9][0-9]*)$/.test(indexLine)) {
      throw new Error(`\xEDndice no can\xF3nico: ${JSON.stringify(indexLine)}`);
    }
    const index = BigInt(indexLine);
    const inclusionProof = [];
    let i = 2;
    for (; i < lines.length; i++) {
      const l = lines[i];
      if (l === "") break;
      const node = fromBase64(l);
      if (node.length !== 32) {
        throw new Error(`nodo de ${node.length} bytes, se esperaban 32`);
      }
      inclusionProof.push(node);
    }
    if (i >= lines.length) throw new Error("falta la l\xEDnea vac\xEDa antes del checkpoint");
    const checkpointNote = lines.slice(i + 1).join("\n");
    if (checkpointNote === "") throw new Error("falta la nota del checkpoint");
    return { index, inclusionProof, checkpointNote };
  }

  // src/receipt.ts
  var MAGIC2 = "nucleo.org/receipt@v1";
  var SEPARATOR = "--- prueba verificable ---";
  var NO_PROVABLE_TIME = "SIN TIEMPO DEMOSTRABLE";
  async function verifyReceipt(receipt, policy) {
    try {
      return await verificar(receipt, policy);
    } catch (e) {
      return {
        valid: false,
        declaredTime: null,
        provableTime: null,
        blockIndex: null,
        recipient: null,
        cosigners: [],
        ignoredSignatures: [],
        reasons: [`error inesperado al verificar: ${mensaje(e)}`],
        checkpoint: null
      };
    }
  }
  function mensaje(e) {
    if (e instanceof Error) return e.message;
    return String(e);
  }
  function parsePolicy(p) {
    if (typeof p !== "object" || p === null) throw new Error("no es un objeto");
    if (typeof p.origin !== "string" || p.origin === "") {
      throw new Error("falta el origin");
    }
    if (typeof p.logKey !== "string") throw new Error("logKey no es una cadena");
    const logKey = clave(p.logKey, "logKey");
    const witnesses = [];
    const w = p.witnesses ?? {};
    if (typeof w !== "object" || w === null) throw new Error("witnesses no es un objeto");
    for (const [name, hex] of Object.entries(w)) {
      if (typeof hex !== "string") throw new Error(`la clave del testigo ${name} no es una cadena`);
      witnesses.push({ name, key: clave(hex, `la clave del testigo ${name}`) });
    }
    if (p.quorum !== void 0 && (!Number.isInteger(p.quorum) || p.quorum < 0)) {
      throw new Error(`quorum inv\xE1lido: ${String(p.quorum)}`);
    }
    return { logKey, witnesses };
  }
  function clave(hex, cual) {
    let raw;
    try {
      raw = fromHex(hex);
    } catch (e) {
      throw new Error(`${cual} no es hexadecimal v\xE1lido: ${mensaje(e)}`);
    }
    if (raw.length !== 32) {
      throw new Error(`${cual} mide ${raw.length} bytes y una clave Ed25519 mide 32`);
    }
    return raw;
  }
  async function verificar(receipt, policy) {
    const reasons = [];
    const fail = (why) => ({
      valid: false,
      declaredTime: null,
      provableTime: null,
      blockIndex: null,
      recipient: null,
      cosigners: [],
      ignoredSignatures: [],
      reasons: [...reasons, why],
      checkpoint: null
    });
    let p;
    try {
      p = parseReceipt(receipt);
    } catch (e) {
      return fail(`el recibo no se pudo leer: ${mensaje(e)}`);
    }
    let claves;
    try {
      claves = parsePolicy(policy);
    } catch (e) {
      return fail(`la pol\xEDtica no se pudo leer: ${mensaje(e)}`);
    }
    const cosigners = [];
    const ignored = [];
    if (p.checkpoint.origin !== policy.origin) {
      reasons.push(
        `el recibo es del log ${JSON.stringify(p.checkpoint.origin)} y la pol\xEDtica espera ${JSON.stringify(policy.origin)}`
      );
    }
    if (!jsonKeysAreSorted(p.headerJSON)) {
      reasons.push("el header del bloque no est\xE1 en forma can\xF3nica JCS");
    }
    const entryHash = await sha256(utf8(p.headerJSON));
    const logKey = claves.logKey;
    const logId = await keyId(sha256, policy.origin, ALG_ED25519, logKey);
    let logSigned = false;
    const witnesses = /* @__PURE__ */ new Map();
    for (const w of claves.witnesses) {
      witnesses.set(await keyId(sha256, w.name, ALG_COSIGNATURE_V1, w.key), w);
    }
    let earliest = null;
    for (const sig of p.note.sigs) {
      if (sig.name === policy.origin && sig.keyId === logId) {
        if (!await verifyEd25519(logKey, sig.signature, p.note.textBytes)) {
          reasons.push("la firma del log no verifica");
          continue;
        }
        logSigned = true;
        continue;
      }
      const w = witnesses.get(sig.keyId);
      if (!w || w.name !== sig.name) {
        ignored.push(sig.name);
        continue;
      }
      const cs = parseCosignature(sig.signature);
      if (!cs) {
        reasons.push(
          `la cosignature de ${sig.name} mide ${sig.signature.length} bytes y una tlog-cosignature@v1 mide ${COSIGNATURE_SIZE}`
        );
        continue;
      }
      const msg = cosignedMessage(cs.timestamp, p.note.textBytes);
      if (!await verifyEd25519(w.key, cs.signature, msg)) {
        reasons.push(`la cosignature de ${sig.name} no verifica`);
        continue;
      }
      cosigners.push(sig.name);
      if (earliest === null || cs.timestamp < earliest) earliest = cs.timestamp;
    }
    if (!logSigned) reasons.push("el checkpoint no est\xE1 firmado por la clave del log");
    const quorum = policy.quorum ?? 0;
    if (cosigners.length < quorum) {
      reasons.push(`qu\xF3rum de testigos no alcanzado: ${cosigners.length} de ${quorum}`);
    }
    const ok = await verifyInclusion(
      sha256,
      entryHash,
      p.proof.index,
      p.checkpoint.size,
      p.proof.inclusionProof,
      p.checkpoint.rootHash
    );
    if (!ok) reasons.push("la prueba de inclusi\xF3n no verifica contra la ra\xEDz del checkpoint");
    if (p.proof.index !== p.headerIndex) {
      reasons.push(
        `el \xEDndice de la prueba (${p.proof.index}) no es el del header (${p.headerIndex})`
      );
    }
    const provable = earliest === null ? null : unixToRFC3339(earliest);
    const expected = renderHeader(p, provable);
    if (expected !== p.text) {
      reasons.push(
        "el texto del recibo no coincide con lo que dice la prueba: el encabezado fue alterado o el tiempo demostrable no lo respalda ning\xFAn testigo aceptado"
      );
    }
    return {
      valid: reasons.length === 0,
      declaredTime: p.header.timestamp,
      provableTime: reasons.length === 0 ? provable : null,
      blockIndex: p.headerIndex,
      recipient: p.recipient,
      cosigners,
      ignoredSignatures: ignored,
      reasons,
      checkpoint: {
        origin: p.checkpoint.origin,
        size: p.checkpoint.size.toString(),
        rootHash: toHex(p.checkpoint.rootHash)
      }
    };
  }
  function parseReceipt(receipt) {
    const at = receipt.indexOf(SEPARATOR + "\n");
    if (at < 0) throw new Error(`falta el separador ${JSON.stringify(SEPARATOR)}`);
    const text = receipt.slice(0, at);
    const machine = receipt.slice(at + SEPARATOR.length + 1);
    if (!text.startsWith(MAGIC2 + "\n")) {
      throw new Error(`se esperaba ${MAGIC2} en la primera l\xEDnea`);
    }
    const recipient = field(text, "destinatario      : ");
    const nl = machine.indexOf("\n");
    if (nl < 0) throw new Error("falta el header can\xF3nico");
    const headerJSON = machine.slice(0, nl);
    const header = JSON.parse(headerJSON);
    const proof = parseProof(machine.slice(nl + 1));
    const note = parseNote(proof.checkpointNote);
    const checkpoint = parseCheckpoint(note.text);
    return { recipient, headerJSON, header, headerIndex: headerIndexOf(headerJSON), proof, note, checkpoint, text };
  }
  function headerIndexOf(headerJSON) {
    const m = /"index"\s*:\s*(\d+)/.exec(headerJSON);
    if (!m) throw new Error("el header no lleva un \xEDndice entero");
    return BigInt(m[1]);
  }
  function field(text, prefix) {
    for (const line of text.split("\n")) {
      if (line.startsWith(prefix)) return line.slice(prefix.length);
    }
    throw new Error(`falta la l\xEDnea ${JSON.stringify(prefix.trim())}`);
  }
  function renderHeader(p, provable) {
    const lines = [
      MAGIC2,
      `destinatario      : ${p.recipient}`,
      `emisor (tenant)   : ${p.header.tenant}`,
      `tipo de registro  : ${p.header.type}`,
      `hash del contenido: ${p.header.payload_hash}`,
      `bloque            : ${p.headerIndex}`,
      "",
      `TIEMPO DECLARADO  : ${p.header.timestamp}  (declarado por el sistema emisor)`,
      provable === null ? `TIEMPO DEMOSTRABLE: ${NO_PROVABLE_TIME}` : `TIEMPO DEMOSTRABLE: ${provable}  (atestiguado por testigos)`,
      "",
      ""
    ];
    return lines.join("\n");
  }
  function unixToRFC3339(unix) {
    const d = new Date(Number(unix) * 1e3);
    const p2 = (n) => n.toString().padStart(2, "0");
    return `${d.getUTCFullYear()}-${p2(d.getUTCMonth() + 1)}-${p2(d.getUTCDate())}T${p2(d.getUTCHours())}:${p2(d.getUTCMinutes())}:${p2(d.getUTCSeconds())}Z`;
  }
  function receiptText(receipt) {
    const at = receipt.indexOf(SEPARATOR);
    return at < 0 ? "" : receipt.slice(0, at).replace(/\n+$/, "");
  }
  return __toCommonJS(index_exports);
})();
