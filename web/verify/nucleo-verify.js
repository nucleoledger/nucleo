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
    MAX_POLICY_BYTES: () => MAX_POLICY_BYTES,
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
    parsePolicyText: () => parsePolicyText,
    parseProof: () => parseProof,
    parseReceipt: () => parseReceipt,
    receiptText: () => receiptText,
    sha256: () => sha256,
    toBase64: () => toBase64,
    toHex: () => toHex,
    utf8: () => utf8,
    validatePolicy: () => validatePolicy,
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
  var MAX_SIGS = 100;
  var ESPACIOS = /* @__PURE__ */ new Set([
    9,
    10,
    11,
    12,
    13,
    32,
    133,
    160,
    5760,
    8192,
    8193,
    8194,
    8195,
    8196,
    8197,
    8198,
    8199,
    8200,
    8201,
    8202,
    8232,
    8233,
    8239,
    8287,
    12288
  ]);
  function nombreValido(name) {
    if (name === "" || name.includes("+")) return false;
    for (const ch of name) {
      if (ESPACIOS.has(ch.codePointAt(0))) return false;
    }
    return true;
  }
  function base64Canonico(s) {
    if (s === "" || s.length % 4 !== 0 || !/^[A-Za-z0-9+/]*={0,2}$/.test(s)) {
      throw new Error("base64 no est\xE1ndar");
    }
    const b = fromBase64(s);
    if (toBase64(b) !== s) throw new Error("base64 no can\xF3nico");
    return b;
  }
  function parseNote(msg) {
    for (const ch of msg) {
      const cp = ch.codePointAt(0);
      if (cp < 32 && cp !== 10 || cp >= 55296 && cp <= 57343) {
        throw new Error("la nota contiene caracteres de control o UTF-16 inv\xE1lido");
      }
    }
    const at = msg.lastIndexOf("\n\n");
    if (at < 0) throw new Error("la nota no separa cuerpo y firmas");
    const text = msg.slice(0, at + 1);
    const sigBlock = msg.slice(at + 2);
    if (sigBlock === "" || !sigBlock.endsWith("\n")) {
      throw new Error("el bloque de firmas est\xE1 vac\xEDo o no termina en salto de l\xEDnea");
    }
    const sigs = [];
    for (const line of sigBlock.slice(0, -1).split("\n")) {
      if (!line.startsWith(SIG_PREFIX)) throw new Error("l\xEDnea de firma sin el prefijo de signed-note");
      const rest = line.slice(SIG_PREFIX.length);
      const sp = rest.indexOf(" ");
      if (sp < 0) throw new Error("l\xEDnea de firma sin nombre y firma");
      const name = rest.slice(0, sp);
      if (!nombreValido(name)) throw new Error(`nombre de firma inv\xE1lido: ${JSON.stringify(name)}`);
      let blob;
      try {
        blob = base64Canonico(rest.slice(sp + 1));
      } catch (e) {
        throw new Error(`firma de ${name}: ${e instanceof Error ? e.message : String(e)}`);
      }
      if (blob.length < 5) throw new Error(`firma de ${name}: menos de 5 bytes`);
      if (sigs.length === MAX_SIGS) throw new Error(`m\xE1s de ${MAX_SIGS} l\xEDneas de firma`);
      sigs.push({ name, keyId: uint32BE(blob, 0), signature: blob.slice(4), line });
    }
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
      if (toBase64(node) !== l) throw new Error(`nodo de la prueba en base64 no can\xF3nico: ${JSON.stringify(l)}`);
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

  // src/policy.ts
  var MAX_POLICY_BYTES = 65536;
  var MIEMBROS = ["origin", "logKey", "signerKey", "witnesses", "quorum"];
  function parsePolicyText(text) {
    if (utf8(text).length > MAX_POLICY_BYTES) {
      throw new Error(`la pol\xEDtica mide m\xE1s de ${MAX_POLICY_BYTES} bytes`);
    }
    if (text.charCodeAt(0) === 65279) throw new Error("la pol\xEDtica empieza con BOM");
    for (let i = 0; i < text.length; i++) {
      const c = text.charCodeAt(i);
      if (c >= 55296 && c <= 56319) {
        const d = text.charCodeAt(i + 1);
        if (!(d >= 56320 && d <= 57343)) throw new Error("la pol\xEDtica no es Unicode v\xE1lido");
        i++;
      } else if (c >= 56320 && c <= 57343) {
        throw new Error("la pol\xEDtica no es Unicode v\xE1lido");
      }
    }
    const p = new Lector(text);
    p.espacios();
    if (p.s[p.i] !== "{") throw new Error("el documento tiene que ser un objeto JSON");
    const obj = p.objeto(1);
    p.espacios();
    if (p.i !== p.s.length) throw new Error(`hay contenido despu\xE9s del objeto (posici\xF3n ${p.i})`);
    return construir(obj);
  }
  var Lector = class {
    constructor(s) {
      this.s = s;
    }
    i = 0;
    err(msg) {
      return new Error(`${msg} (posici\xF3n ${this.i})`);
    }
    espacios() {
      while (this.i < this.s.length) {
        const c = this.s[this.i];
        if (c === " " || c === "	" || c === "\n" || c === "\r") this.i++;
        else return;
      }
    }
    objeto(profundidad) {
      if (profundidad > 2) throw this.err("objeto anidado donde la pol\xEDtica no admite ninguno");
      this.i++;
      const out = [];
      const vistos = /* @__PURE__ */ new Set();
      this.espacios();
      if (this.s[this.i] === "}") {
        this.i++;
        return out;
      }
      for (; ; ) {
        this.espacios();
        if (this.s[this.i] !== '"') throw this.err("se esperaba el nombre de un miembro");
        const nombre = this.cadena();
        if (vistos.has(nombre)) throw this.err(`el miembro ${JSON.stringify(nombre)} est\xE1 repetido`);
        vistos.add(nombre);
        this.espacios();
        if (this.s[this.i] !== ":") throw this.err("se esperaba ':'");
        this.i++;
        this.espacios();
        out.push({ nombre, valor: this.valor(profundidad) });
        this.espacios();
        const c = this.s[this.i];
        if (c === ",") this.i++;
        else if (c === "}") {
          this.i++;
          return out;
        } else if (c === void 0) throw this.err("objeto sin cerrar");
        else throw this.err("se esperaba ',' o '}'");
      }
    }
    valor(profundidad) {
      const c = this.s[this.i];
      if (c === void 0) throw this.err("falta un valor");
      if (c === '"') return { tipo: "s", cadena: this.cadena() };
      if (c === "{") return { tipo: "o", miembros: this.objeto(profundidad + 1) };
      if (c === "-" || c >= "0" && c <= "9") return { tipo: "n", numero: this.numero() };
      throw this.err("valor no admitido en una pol\xEDtica (solo cadenas, n\xFAmeros y el objeto de testigos)");
    }
    /** cadena lee una cadena JSON; rechaza surrogates sueltos escritos con \u. */
    cadena() {
      this.i++;
      let out = "";
      for (; ; ) {
        if (this.i >= this.s.length) throw this.err("cadena sin cerrar");
        const c = this.s[this.i];
        const code = c.charCodeAt(0);
        if (c === '"') {
          this.i++;
          return out;
        }
        if (code < 32) throw this.err("car\xE1cter de control sin escapar dentro de una cadena");
        if (c !== "\\") {
          out += c;
          this.i++;
          continue;
        }
        this.i++;
        const e = this.s[this.i];
        this.i++;
        switch (e) {
          case '"':
          case "\\":
          case "/":
            out += e;
            break;
          case "b":
            out += "\b";
            break;
          case "f":
            out += "\f";
            break;
          case "n":
            out += "\n";
            break;
          case "r":
            out += "\r";
            break;
          case "t":
            out += "	";
            break;
          case "u": {
            const u = this.hex4();
            if (u >= 55296 && u <= 56319) {
              if (this.s[this.i] !== "\\" || this.s[this.i + 1] !== "u") {
                throw this.err("surrogate UTF-16 alto sin su pareja");
              }
              this.i += 2;
              const bajo = this.hex4();
              if (bajo < 56320 || bajo > 57343) throw this.err("surrogate UTF-16 alto sin su pareja");
              out += String.fromCharCode(u, bajo);
            } else if (u >= 56320 && u <= 57343) {
              throw this.err("surrogate UTF-16 bajo suelto");
            } else {
              out += String.fromCharCode(u);
            }
            break;
          }
          default:
            throw this.err(`escape desconocido \\${e ?? ""}`);
        }
      }
    }
    hex4() {
      const h = this.s.slice(this.i, this.i + 4);
      if (!/^[0-9a-fA-F]{4}$/.test(h)) throw this.err("escape \\u con d\xEDgitos no hexadecimales");
      this.i += 4;
      return parseInt(h, 16);
    }
    /** numero lee un número con la gramática de RFC 8259 y devuelve el literal. */
    numero() {
      const ini = this.i;
      const digitos = () => {
        let n = 0;
        while (this.i < this.s.length && this.s[this.i] >= "0" && this.s[this.i] <= "9") {
          this.i++;
          n++;
        }
        return n;
      };
      if (this.s[this.i] === "-") this.i++;
      if (this.s[this.i] === "0") this.i++;
      else if (digitos() === 0) throw this.err("n\xFAmero mal formado");
      if (this.s[this.i] === ".") {
        this.i++;
        if (digitos() === 0) throw this.err("n\xFAmero mal formado");
      }
      if (this.s[this.i] === "e" || this.s[this.i] === "E") {
        this.i++;
        if (this.s[this.i] === "+" || this.s[this.i] === "-") this.i++;
        if (digitos() === 0) throw this.err("n\xFAmero mal formado");
      }
      return this.s.slice(ini, this.i);
    }
  };
  var HEX_CLAVE = /^[0-9a-f]{64}$/;
  function construir(obj) {
    const tiene = /* @__PURE__ */ new Set();
    let origin = "";
    let logKey = "";
    let signerKey;
    const witnesses = {};
    let quorum = "";
    let nTestigos = 0;
    for (const { nombre, valor } of obj) {
      if (!MIEMBROS.includes(nombre)) {
        const variante = MIEMBROS.find((k) => k.toLowerCase() === asciiMinusculas(nombre));
        if (variante) throw new Error(`el miembro ${JSON.stringify(nombre)} es una variante de may\xFAsculas de ${JSON.stringify(variante)}`);
        throw new Error(`miembro desconocido ${JSON.stringify(nombre)}`);
      }
      tiene.add(nombre);
      switch (nombre) {
        case "origin":
          if (valor.tipo !== "s" || valor.cadena === "") throw new Error("origin tiene que ser una cadena no vac\xEDa");
          origin = valor.cadena;
          break;
        case "logKey":
        case "signerKey":
          if (valor.tipo !== "s" || !HEX_CLAVE.test(valor.cadena)) {
            throw new Error(`${nombre} tiene que ser una clave de 64 caracteres hexadecimales en min\xFAsculas`);
          }
          if (nombre === "logKey") logKey = valor.cadena;
          else signerKey = valor.cadena;
          break;
        case "witnesses": {
          if (valor.tipo !== "o") throw new Error("witnesses tiene que ser un objeto");
          if (valor.miembros.length === 0) throw new Error("no trae ning\xFAn testigo; sin testigos no verifica nada");
          const porClave = /* @__PURE__ */ new Map();
          for (const w of valor.miembros) {
            if (w.nombre === "") throw new Error("un testigo sin nombre");
            if (w.valor.tipo !== "s" || !HEX_CLAVE.test(w.valor.cadena)) {
              throw new Error(`la clave del testigo ${JSON.stringify(w.nombre)} tiene que ser de 64 caracteres hexadecimales en min\xFAsculas`);
            }
            const otro = porClave.get(w.valor.cadena);
            if (otro !== void 0) {
              throw new Error(`la misma clave est\xE1 bajo dos nombres (${JSON.stringify(otro)} y ${JSON.stringify(w.nombre)})`);
            }
            porClave.set(w.valor.cadena, w.nombre);
            witnesses[w.nombre] = w.valor.cadena;
          }
          nTestigos = valor.miembros.length;
          break;
        }
        case "quorum":
          if (valor.tipo !== "n") throw new Error("quorum tiene que ser un n\xFAmero entero");
          quorum = valor.numero;
          break;
      }
    }
    for (const req of ["origin", "logKey", "witnesses", "quorum"]) {
      if (!tiene.has(req)) throw new Error(`falta el miembro ${JSON.stringify(req)}`);
    }
    if (!/^(0|[1-9][0-9]*)$/.test(quorum)) throw new Error(`quorum ${quorum} no es un entero sin fracci\xF3n ni exponente`);
    const q = quorum.length > 9 ? Infinity : Number(quorum);
    if (q < 1 || q > nTestigos) throw new Error(`quorum ${quorum} con ${nTestigos} testigos`);
    const out = { origin, logKey, witnesses, quorum: q };
    if (signerKey !== void 0) out.signerKey = signerKey;
    return out;
  }
  function validatePolicy(p) {
    if (typeof p !== "object" || p === null || Array.isArray(p)) throw new Error("la pol\xEDtica no es un objeto");
    let texto;
    try {
      texto = JSON.stringify(p);
    } catch (e) {
      throw new Error(`la pol\xEDtica no se puede serializar: ${e instanceof Error ? e.message : String(e)}`);
    }
    return parsePolicyText(texto);
  }
  function asciiMinusculas(s) {
    return s.replace(/[A-Z]/g, (c) => String.fromCharCode(c.charCodeAt(0) + 32));
  }

  // src/receipt.ts
  var MAGIC2 = "nucleo.org/receipt@v2";
  var MAGIC_V1 = "nucleo.org/receipt@v1";
  var BLOCK_SIG_SIZE = 64;
  var SEPARATOR = "--- prueba verificable ---";
  var NO_PROVABLE_TIME = "SIN TIEMPO DEMOSTRABLE";
  var RECIPIENT_NOTE = "  (firmado por el emisor)";
  var RECEIPT_SIG_PREFIX = "\u2014 ";
  var LEGAL_NOTICE = [
    "ADVERTENCIA LEGAL",
    "Este recibo es evidencia t\xE9cnica de integridad y tiempo. No constituye por s\xED",
    "mismo un acto p\xFAblico, una certificaci\xF3n notarial ni un pronunciamiento de",
    "autoridad. Su valor probatorio lo determina un perito o un juez."
  ];
  async function verifyReceipt(receipt, policy) {
    try {
      return await verificar(receipt, policy);
    } catch (e) {
      return {
        valid: false,
        declaredTime: null,
        provableTime: null,
        blockIndex: null,
        blockSignatureVerified: null,
        receiptSignatureVerified: null,
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
    const v = validatePolicy(p);
    if (v.signerKey === void 0) {
      throw new Error("falta signerKey: la clave del firmante de bloques tiene que venir en la pol\xEDtica (ADR-017)");
    }
    return {
      origin: v.origin,
      logKey: clave(v.logKey, "logKey"),
      signerKey: clave(v.signerKey, "signerKey"),
      witnesses: Object.entries(v.witnesses).map(([name, hex]) => ({ name, key: clave(hex, `la clave del testigo ${name}`) })),
      quorum: v.quorum
    };
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
      blockSignatureVerified: null,
      receiptSignatureVerified: null,
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
    const blockHash = await sha256(utf8(p.headerJSON));
    const leafData = concat(blockHash, p.blockSig);
    let blockSignatureVerified = null;
    let receiptSignatureVerified = null;
    if ((p.header.signer_pubkey ?? "").toLowerCase() !== toHex(claves.signerKey)) {
      reasons.push("el bloque no est\xE1 firmado por la clave del emisor que fija la pol\xEDtica (signerKey)");
    }
    const signerPub = fromHex(p.header.signer_pubkey ?? "");
    if (signerPub === null || signerPub.length !== 32) {
      reasons.push("signer_pubkey del header no es una clave Ed25519");
    } else {
      blockSignatureVerified = await verifyEd25519(signerPub, p.blockSig, blockHash);
      if (!blockSignatureVerified) {
        reasons.push("la firma del bloque no verifica con la clave signer_pubkey del header");
      }
      if (p.receiptSig === null) {
        reasons.push("el recibo no lleva firma del emisor");
      } else {
        const digest = await sha256(utf8(p.signedBytes));
        receiptSignatureVerified = await verifyEd25519(signerPub, p.receiptSig, digest);
        if (!receiptSignatureVerified) {
          reasons.push("la firma del emisor sobre el recibo no verifica: el recibo fue alterado");
        }
      }
    }
    const logKey = claves.logKey;
    const logId = await keyId(sha256, policy.origin, ALG_ED25519, logKey);
    let logSigned = false;
    const idDe = (name, id) => `${name}
${id}`;
    const witnesses = /* @__PURE__ */ new Map();
    for (const w of claves.witnesses) {
      witnesses.set(idDe(w.name, await keyId(sha256, w.name, ALG_COSIGNATURE_V1, w.key)), w);
    }
    const contados = /* @__PURE__ */ new Set();
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
      const w = witnesses.get(idDe(sig.name, sig.keyId));
      if (!w) {
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
      if (!contados.has(idDe(sig.name, sig.keyId))) {
        contados.add(idDe(sig.name, sig.keyId));
        cosigners.push(sig.name);
      }
      if (earliest === null || cs.timestamp < earliest) earliest = cs.timestamp;
    }
    if (!logSigned) reasons.push("el checkpoint no est\xE1 firmado por la clave del log");
    const quorum = claves.quorum;
    if (cosigners.length < quorum) {
      reasons.push(`qu\xF3rum de testigos no alcanzado: ${cosigners.length} de ${quorum}`);
    }
    const ok = await verifyInclusion(
      sha256,
      leafData,
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
      blockSignatureVerified,
      receiptSignatureVerified,
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
    if (text.startsWith(MAGIC_V1 + "\n")) {
      throw new Error(
        `este recibo es ${MAGIC_V1}, con la regla de hoja leaf/v1; este verificador implementa ${MAGIC2} (leaf/v2). Ver PROTOCOL.md \xA72.1 y ADR-014`
      );
    }
    if (!text.startsWith(MAGIC2 + "\n")) {
      throw new Error(`se esperaba ${MAGIC2} en la primera l\xEDnea`);
    }
    const recipient = field(text, "destinatario      : ").replace(
      new RegExp(`${RECIPIENT_NOTE.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}$`),
      ""
    );
    const nl = machine.indexOf("\n");
    if (nl < 0) throw new Error("falta el header can\xF3nico");
    const headerJSON = machine.slice(0, nl);
    const header = JSON.parse(headerJSON);
    const rest = machine.slice(nl + 1);
    const nl2 = rest.indexOf("\n");
    if (nl2 < 0) throw new Error("falta la firma del bloque");
    const blockSigLine = rest.slice(0, nl2);
    const blockSig = fromBase64(blockSigLine);
    if (toBase64(blockSig) !== blockSigLine) {
      throw new Error("la firma del bloque no est\xE1 en base64 can\xF3nico");
    }
    if (blockSig.length !== BLOCK_SIG_SIZE) {
      throw new Error(
        `la firma del bloque mide ${blockSig.length} bytes y una Ed25519 mide ${BLOCK_SIG_SIZE}`
      );
    }
    let afterSig = rest.slice(nl2 + 1);
    let receiptSig = null;
    let signedBytes = receipt;
    if (afterSig.startsWith(RECEIPT_SIG_PREFIX)) {
      const nl3 = afterSig.indexOf("\n");
      if (nl3 < 0) throw new Error("la l\xEDnea de la firma del emisor no termina");
      const line = afterSig.slice(0, nl3);
      const sp = line.lastIndexOf(" ");
      if (sp < 0) throw new Error("la l\xEDnea de la firma del emisor no trae nombre y firma");
      const name = line.slice(RECEIPT_SIG_PREFIX.length, sp);
      if (name !== header.tenant) {
        throw new Error(
          `la firma del emisor dice ser de ${JSON.stringify(name)} y el header declara ${JSON.stringify(header.tenant)}`
        );
      }
      receiptSig = fromBase64(line.slice(sp + 1));
      if (toBase64(receiptSig) !== line.slice(sp + 1)) {
        throw new Error("la firma del emisor no est\xE1 en base64 can\xF3nico");
      }
      if (receiptSig.length !== BLOCK_SIG_SIZE) {
        throw new Error(`la firma del emisor mide ${receiptSig.length} bytes y una Ed25519 mide ${BLOCK_SIG_SIZE}`);
      }
      const entera = line + "\n";
      const at2 = receipt.lastIndexOf(entera);
      if (at2 < 0) throw new Error("no se pudo aislar la l\xEDnea de la firma del emisor");
      signedBytes = receipt.slice(0, at2) + receipt.slice(at2 + entera.length);
      afterSig = afterSig.slice(nl3 + 1);
    }
    const proof = parseProof(afterSig);
    const note = parseNote(proof.checkpointNote);
    const checkpoint = parseCheckpoint(note.text);
    return {
      recipient,
      headerJSON,
      blockSig,
      receiptSig,
      signedBytes,
      header,
      headerIndex: headerIndexOf(headerJSON),
      proof,
      note,
      checkpoint,
      text
    };
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
      `destinatario      : ${p.recipient}${RECIPIENT_NOTE}`,
      `emisor (tenant)   : ${p.header.tenant}`,
      `tipo de registro  : ${p.header.type}`,
      `hash del contenido: ${p.header.payload_hash}`,
      `bloque            : ${p.headerIndex}`,
      "",
      `TIEMPO DECLARADO  : ${p.header.timestamp}  (declarado por el sistema emisor)`,
      provable === null ? `TIEMPO DEMOSTRABLE: ${NO_PROVABLE_TIME}` : `TIEMPO DEMOSTRABLE: ${provable}  (atestiguado por testigos)`,
      "",
      ...LEGAL_NOTICE,
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
