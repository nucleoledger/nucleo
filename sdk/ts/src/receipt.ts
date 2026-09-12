// Recibos de Núcleo: la prueba de tlog-proof envuelta en un encabezado legible.
//
// Este fichero implementa la regla que hace fiable ese encabezado: el texto se
// DERIVA de la prueba, y verificar consiste, entre otras cosas, en volver a
// derivarlo y comprobar que coincide byte a byte. Un recibo con prueba impecable
// y texto retocado —otra fecha, otro emisor, otro importe— se rechaza.

import { concat, equal, fromBase64, fromHex, toBase64, toHex, utf8 } from "./bytes.js";
import { parseCheckpoint, type Checkpoint } from "./checkpoint.js";
import { cosignedMessage, parseCosignature, COSIGNATURE_SIZE } from "./cosignature.js";
import { sha256, verifyEd25519 } from "./crypto.js";
import { jsonKeysAreSorted } from "./jcs.js";
import { leafHash, verifyInclusion } from "./merkle.js";
import { ALG_COSIGNATURE_V1, ALG_ED25519, keyId, parseNote, type Note } from "./note.js";
import { parseProof, type TlogProof } from "./proof.js";

/** MAGIC es la primera línea de un recibo. */
/**
 * MAGIC fija a la vez el formato del recibo y la REGLA DE HOJA con la que se
 * verifica (PROTOCOL.md §3.1). Un verificador nunca tiene que adivinar con qué
 * regla recomponer la hoja: lo lee en la primera línea.
 */
export const MAGIC = "nucleo.org/receipt@v2";

/** MAGIC_V1 es el magic histórico, para reconocerlo y dar un error que lo explique. */
export const MAGIC_V1 = "nucleo.org/receipt@v1";

/** BLOCK_SIG_SIZE es lo que mide una firma Ed25519. */
export const BLOCK_SIG_SIZE = 64;

/** SEPARATOR abre la parte de máquina. */
export const SEPARATOR = "--- prueba verificable ---";

/** NO_PROVABLE_TIME es lo que se imprime cuando no hay tiempo demostrable. */
export const NO_PROVABLE_TIME = "SIN TIEMPO DEMOSTRABLE";

/**
 * LEGAL_NOTICE es la advertencia legal que el emisor pone DENTRO del recibo.
 *
 * Tiene que ser byte a byte la misma que la constante LegalNotice de Go: viaja
 * en el texto legible, y renderHeader vuelve a componerla para compararla con lo
 * que llegó. Un recibo al que le hayan quitado la advertencia —o le hayan
 * cambiado una palabra— no verifica.
 *
 * Eso es lo que la hace útil. Una advertencia que se puede borrar con un editor
 * de texto no protege a nadie; esta no se puede borrar sin romper el recibo.
 */
/**
 * RECIPIENT_NOTE es la etiqueta que acompaña al nombre del destinatario, en su
 * misma línea.
 *
 * El destinatario no está cubierto por ninguna firma: lo elige quien emite el
 * recibo. La prueba demuestra que el registro existía, no a quién se le entregó.
 * La etiqueta va junto al nombre porque es ahí donde alguien va a leerlo como si
 * fuera prueba de emisión a esa persona.
 *
 * Tiene que coincidir byte a byte con RecipientNote de Go. Los dos espacios del
 * principio son parte de la constante.
 */
export const RECIPIENT_NOTE = "  (firmado por el emisor)";

/** RECEIPT_SIG_PREFIX abre la línea de la firma del emisor. */
export const RECEIPT_SIG_PREFIX = "— ";

export const LEGAL_NOTICE = [
  "ADVERTENCIA LEGAL",
  "Este recibo es evidencia técnica de integridad y tiempo. No constituye por sí",
  "mismo un acto público, una certificación notarial ni un pronunciamiento de",
  "autoridad. Su valor probatorio lo determina un perito o un juez.",
];

/** Policy es lo que quien verifica debe conocer de antemano. */
export interface Policy {
  /** origin del log que se espera. */
  origin: string;
  /** logKey en hexadecimal: la pública Ed25519 del log. */
  logKey: string;
  /** witnesses acepta nombre → pública en hexadecimal. */
  witnesses?: Record<string, string>;
  /** quorum es el mínimo de cosignatures válidas exigidas. */
  quorum?: number;
}

/** Header es el header del bloque tal como viaja en el recibo. */
export interface BlockHeader {
  /**
   * index tal como lo devuelve JSON.parse. NO se usa para verificar: por encima
   * de 2^53 pierde precisión en silencio. La comparación se hace con
   * Parsed.headerIndex, leído del texto canónico como BigInt.
   */
  index: number;
  prev_hash: string;
  timestamp: string;
  tenant: string;
  type: string;
  payload_hash: string;
  payload_cid: string;
  signer_pubkey: string;
}

/** Result es lo que el verificador puede afirmar. */
export interface Result {
  /** valid resume todo: solo es true si nada falló. */
  valid: boolean;
  /** declaredTime lo puso el emisor. NO prueba nada. */
  declaredTime: string | null;
  /** provableTime es el menor timestamp de las cosignatures aceptadas. */
  provableTime: string | null;
  /**
   * blockIndex es la posición del registro en el log.
   *
   * Es un bigint, no un number, porque un índice de árbol puede pasar de 2^53 y
   * un `number` lo redondearía sin avisar. Quien lo serialice a JSON debe
   * convertirlo con String(): JSON.stringify no sabe qué hacer con un bigint y
   * lanza, lo cual es incómodo pero honesto.
   */
  blockIndex: bigint | null;
  /** recipient es a quién iba dirigido. No está firmado: es dirección, no prueba. */
  recipient: string | null;
  /** cosigners son los testigos cuya cosignature verificó. */
  cosigners: string[];
  /** ignoredSignatures son las firmas de claves desconocidas, que se ignoran. */
  ignoredSignatures: string[];
  /** reasons explica, en español, por qué falla. Vacío si valid. */
  reasons: string[];
  /** checkpoint es el que respalda el recibo, si se pudo leer. */
  checkpoint: { origin: string; size: string; rootHash: string } | null;
  /**
   * blockSignatureVerified dice si la firma del bloque verifica contra la clave
   * que declara el header.
   *
   * Es una ruta que un recibo v1 NO daba: llevaba signer_pubkey y no llevaba la
   * firma, así que quien recibía el recibo veía de quién decía ser y no tenía nada
   * con lo que comprobarlo. Es null si no se pudo llegar a comprobarlo.
   *
   * No es redundante con la prueba de inclusión. La inclusión demuestra que el log
   * se comprometió con estos bytes; la firma demuestra que la clave del emisor los
   * firmó. Una raíz cosignada dice qué publicó el log; una firma dice quién lo
   * escribió.
   */
  blockSignatureVerified: boolean | null;
  /**
   * receiptSignatureVerified dice si la firma del emisor sobre el recibo COMPLETO
   * verifica. Es la que cubre al destinatario (ADR-015).
   *
   * La clave sale del propio recibo —signer_pubkey, dentro del header— y el header
   * entra en la hoja de Merkle desde leaf/v2, así que una raíz cosignada por
   * testigos la clava. Por eso esto no necesita ninguna PKI nueva: se verifica con
   * lo que ya hay en el recibo y en la política.
   */
  receiptSignatureVerified: boolean | null;
}

/** parsed guarda lo que se pudo leer del recibo antes de verificarlo. */
interface Parsed {
  recipient: string;
  headerJSON: string;
  blockSig: Uint8Array;
  receiptSig: Uint8Array | null;
  /** signedBytes es el recibo SIN su línea de firma: lo que el emisor firmó. */
  signedBytes: string;
  header: BlockHeader;
  /** headerIndex es el índice leído del texto canónico, sin pasar por Number. */
  headerIndex: bigint;
  proof: TlogProof;
  note: Note;
  checkpoint: Checkpoint;
  text: string;
}

/**
 * verifyReceipt comprueba un recibo completo contra una política.
 *
 * Nunca lanza: devuelve un Result con las razones. Un verificador que lanza
 * obliga a envolver cada llamada en un try, y basta un olvido para que un
 * recibo malo parezca bueno.
 */
export async function verifyReceipt(receipt: string, policy: Policy): Promise<Result> {
  try {
    return await verificar(receipt, policy);
  } catch (e) {
    // Red de seguridad. Si algo dentro lanza pese a todo —un fallo de
    // WebCrypto, un caso que no se previó—, quien llama recibe un veredicto
    // negativo con la razón, no una excepción. La promesa de esta función es
    // que nunca lanza, y una promesa con excepciones no es una promesa.
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
      checkpoint: null,
    };
  }
}

/** ClavesDePolitica es la política ya convertida a bytes. */
interface ClavesDePolitica {
  logKey: Uint8Array;
  witnesses: Array<{ name: string; key: Uint8Array }>;
}

/** mensaje saca un texto legible de cualquier cosa que se haya lanzado. */
function mensaje(e: unknown): string {
  if (e instanceof Error) return e.message;
  return String(e);
}

/**
 * parsePolicy valida la política y la convierte a bytes.
 *
 * Comprueba los tamaños además del hexadecimal: una clave Ed25519 mide 32 bytes
 * exactos, y una de 31 no es "casi válida", es otra cosa. Detectarlo aquí da un
 * mensaje que dice qué clave está mal; dejarlo pasar daría un "la firma no
 * verifica" que manda a buscar el problema al sitio equivocado.
 */
function parsePolicy(p: Policy): ClavesDePolitica {
  if (typeof p !== "object" || p === null) throw new Error("no es un objeto");
  if (typeof p.origin !== "string" || p.origin === "") {
    throw new Error("falta el origin");
  }
  if (typeof p.logKey !== "string") throw new Error("logKey no es una cadena");
  const logKey = clave(p.logKey, "logKey");

  const witnesses: Array<{ name: string; key: Uint8Array }> = [];
  const w = p.witnesses ?? {};
  if (typeof w !== "object" || w === null) throw new Error("witnesses no es un objeto");
  for (const [name, hex] of Object.entries(w)) {
    if (typeof hex !== "string") throw new Error(`la clave del testigo ${name} no es una cadena`);
    witnesses.push({ name, key: clave(hex, `la clave del testigo ${name}`) });
  }
  if (p.quorum !== undefined && (!Number.isInteger(p.quorum) || p.quorum < 0)) {
    throw new Error(`quorum inválido: ${String(p.quorum)}`);
  }
  return { logKey, witnesses };
}

/** clave convierte un hexadecimal de 32 bytes, o explica por qué no puede. */
function clave(hex: string, cual: string): Uint8Array {
  let raw: Uint8Array;
  try {
    raw = fromHex(hex);
  } catch (e) {
    throw new Error(`${cual} no es hexadecimal válido: ${mensaje(e)}`);
  }
  if (raw.length !== 32) {
    throw new Error(`${cual} mide ${raw.length} bytes y una clave Ed25519 mide 32`);
  }
  return raw;
}

async function verificar(receipt: string, policy: Policy): Promise<Result> {
  const reasons: string[] = [];
  const fail = (why: string): Result => ({
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
    checkpoint: null,
  });

  let p: Parsed;
  try {
    p = parseReceipt(receipt);
  } catch (e) {
    return fail(`el recibo no se pudo leer: ${mensaje(e)}`);
  }

  // La POLÍTICA también es entrada, y viene de fuera igual que el recibo: de un
  // fichero de configuración, de un formulario, de un JSON pegado a mano. Una
  // clave con un carácter de más hacía que fromHex lanzara, y una función que
  // promete no lanzar tiene que cumplirlo con TODAS sus entradas, no solo con
  // la que se espera que venga rota.
  let claves: ClavesDePolitica;
  try {
    claves = parsePolicy(policy);
  } catch (e) {
    return fail(`la política no se pudo leer: ${mensaje(e)}`);
  }

  const cosigners: string[] = [];
  const ignored: string[] = [];

  // 1. El origin del checkpoint tiene que ser el de la política.
  if (p.checkpoint.origin !== policy.origin) {
    reasons.push(
      `el recibo es del log ${JSON.stringify(p.checkpoint.origin)} y la política espera ${JSON.stringify(policy.origin)}`,
    );
  }

  // 2. El header tiene que estar en forma canónica JCS: es lo que se firmó.
  if (!jsonKeysAreSorted(p.headerJSON)) {
    reasons.push("el header del bloque no está en forma canónica JCS");
  }

  // 3. La hoja sale del header Y de la firma (leaf/v2, PROTOCOL.md §2.1). El
  // destinatario sigue pudiendo atar SU documento al registro —recomputa el hash de
  // su contenido y comprueba que es el payload_hash de este header— y ahora además
  // puede comprobar quién lo firmó.
  const blockHash = await sha256(utf8(p.headerJSON));
  const leafData = concat(blockHash, p.blockSig);

  // 3b. La firma del bloque contra signer_pubkey. Se comprueba aunque la inclusión
  // vaya a comprobarse después: son dos afirmaciones distintas y quien lee el
  // veredicto merece saber cuál de las dos falló.
  let blockSignatureVerified: boolean | null = null;
  let receiptSignatureVerified: boolean | null = null;
  const signerPub = fromHex(p.header.signer_pubkey ?? "");
  if (signerPub === null || signerPub.length !== 32) {
    reasons.push("signer_pubkey del header no es una clave Ed25519");
  } else {
    blockSignatureVerified = await verifyEd25519(signerPub, p.blockSig, blockHash);
    if (!blockSignatureVerified) {
      reasons.push("la firma del bloque no verifica con la clave signer_pubkey del header");
    }

    // 3c. Y la firma del emisor sobre el recibo ENTERO, destinatario incluido
    // (ADR-015). Es la que hace que el nombre del destinatario deje de ser una línea
    // que cualquiera con el fichero puede reescribir.
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

  // 4. Firmas de la nota del checkpoint.
  const logKey = claves.logKey;
  const logId = await keyId(sha256, policy.origin, ALG_ED25519, logKey);
  let logSigned = false;

  const witnesses = new Map<number, { name: string; key: Uint8Array }>();
  for (const w of claves.witnesses) {
    witnesses.set(await keyId(sha256, w.name, ALG_COSIGNATURE_V1, w.key), w);
  }

  let earliest: bigint | null = null;
  for (const sig of p.note.sigs) {
    if (sig.name === policy.origin && sig.keyId === logId) {
      // Una firma de una clave CONOCIDA que no verifica invalida la nota
      // entera. No es lo mismo que una firma desconocida.
      if (!(await verifyEd25519(logKey, sig.signature, p.note.textBytes))) {
        reasons.push("la firma del log no verifica");
        continue;
      }
      logSigned = true;
      continue;
    }
    const w = witnesses.get(sig.keyId);
    if (!w || w.name !== sig.name) {
      // Firmas de claves desconocidas: ML-DSA-44 del log, cosignatures de
      // otros testigos. Se IGNORAN, como manda c2sp.org/signed-note. Es lo que
      // permite que un mismo recibo circule entre partes que confían en
      // testigos distintos.
      ignored.push(sig.name);
      continue;
    }
    const cs = parseCosignature(sig.signature);
    if (!cs) {
      reasons.push(
        `la cosignature de ${sig.name} mide ${sig.signature.length} bytes y una tlog-cosignature@v1 mide ${COSIGNATURE_SIZE}`,
      );
      continue;
    }
    const msg = cosignedMessage(cs.timestamp, p.note.textBytes);
    if (!(await verifyEd25519(w.key, cs.signature, msg))) {
      reasons.push(`la cosignature de ${sig.name} no verifica`);
      continue;
    }
    cosigners.push(sig.name);
    if (earliest === null || cs.timestamp < earliest) earliest = cs.timestamp;
  }

  if (!logSigned) reasons.push("el checkpoint no está firmado por la clave del log");

  const quorum = policy.quorum ?? 0;
  if (cosigners.length < quorum) {
    reasons.push(`quórum de testigos no alcanzado: ${cosigners.length} de ${quorum}`);
  }

  // 5. El camino de inclusión.
  // Todo en BigInt: el tamaño del checkpoint ya lo es, y el índice se leyó del
  // texto canónico sin pasar por Number.
  const ok = await verifyInclusion(
    sha256,
    leafData,
    p.proof.index,
    p.checkpoint.size,
    p.proof.inclusionProof,
    p.checkpoint.rootHash,
  );
  if (!ok) reasons.push("la prueba de inclusión no verifica contra la raíz del checkpoint");
  if (p.proof.index !== p.headerIndex) {
    reasons.push(
      `el índice de la prueba (${p.proof.index}) no es el del header (${p.headerIndex})`,
    );
  }

  // 6. El encabezado legible tiene que derivarse de todo lo anterior.
  const provable = earliest === null ? null : unixToRFC3339(earliest);
  const expected = renderHeader(p, provable);
  if (expected !== p.text) {
    reasons.push(
      "el texto del recibo no coincide con lo que dice la prueba: el encabezado fue alterado o el tiempo demostrable no lo respalda ningún testigo aceptado",
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
      rootHash: toHex(p.checkpoint.rootHash),
    },
  };
}

/** parseReceipt separa el recibo en sus partes. */
export function parseReceipt(receipt: string): Parsed {
  const at = receipt.indexOf(SEPARATOR + "\n");
  if (at < 0) throw new Error(`falta el separador ${JSON.stringify(SEPARATOR)}`);
  const text = receipt.slice(0, at);
  const machine = receipt.slice(at + SEPARATOR.length + 1);

  if (text.startsWith(MAGIC_V1 + "\n")) {
    // Se reconoce el recibo viejo para poder decir QUÉ pasa. Sin esto el error
    // hablaría de una firma que falta, y quien lo leyera buscaría el problema donde
    // no está.
    throw new Error(
      `este recibo es ${MAGIC_V1}, con la regla de hoja leaf/v1; este verificador ` +
        `implementa ${MAGIC} (leaf/v2). Ver PROTOCOL.md §2.1 y ADR-014`,
    );
  }
  if (!text.startsWith(MAGIC + "\n")) {
    throw new Error(`se esperaba ${MAGIC} en la primera línea`);
  }
  // Se quita la etiqueta para devolver el nombre limpio. Si no viniera, el nombre
  // queda tal cual, renderHeader la volverá a añadir y la comparación del texto
  // rechaza el recibo: un recibo que enseña el nombre sin decir qué es no pasa.
  const recipient = field(text, "destinatario      : ").replace(
    new RegExp(`${RECIPIENT_NOTE.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}$`),
    "",
  );

  const nl = machine.indexOf("\n");
  if (nl < 0) throw new Error("falta el header canónico");
  const headerJSON = machine.slice(0, nl);
  const header = JSON.parse(headerJSON) as BlockHeader;

  // Tras el header, la firma del bloque en base64 (PROTOCOL.md §3.1). Va aquí y no
  // al final porque la cola del recibo es la nota del checkpoint: cualquier línea
  // pegada después acabaría dentro de la nota, leída como una línea de firma más.
  const rest = machine.slice(nl + 1);
  const nl2 = rest.indexOf("\n");
  if (nl2 < 0) throw new Error("falta la firma del bloque");
  const blockSigLine = rest.slice(0, nl2);
  const blockSig = fromBase64(blockSigLine);
  // Canónico o nada: la línea tiene que ser EXACTAMENTE la codificación de lo que
  // decodifica. El diferencial Go↔TS (C.4) encontró en su primera ejecución que
  // un \r al final de la línea de la firma del emisor pasaba aquí y no en Go —el
  // decodificador tolera basura que la re-codificación no reproduce—. Un recibo
  // con dos representaciones no es un recibo que se pueda archivar y comparar.
  if (toBase64(blockSig) !== blockSigLine) {
    throw new Error("la firma del bloque no está en base64 canónico");
  }
  if (blockSig.length !== BLOCK_SIG_SIZE) {
    throw new Error(
      `la firma del bloque mide ${blockSig.length} bytes y una Ed25519 mide ${BLOCK_SIG_SIZE}`,
    );
  }

  // Y tras ella, la firma del emisor sobre el recibo entero (ADR-015). El formato
  // la exige; se lee como opcional para poder decir "no lleva firma del emisor" en
  // vez de que el parser de la prueba se queje de un magic que no entiende.
  let afterSig = rest.slice(nl2 + 1);
  let receiptSig: Uint8Array | null = null;
  let signedBytes = receipt;
  if (afterSig.startsWith(RECEIPT_SIG_PREFIX)) {
    const nl3 = afterSig.indexOf("\n");
    if (nl3 < 0) throw new Error("la línea de la firma del emisor no termina");
    const line = afterSig.slice(0, nl3);
    const sp = line.lastIndexOf(" ");
    if (sp < 0) throw new Error("la línea de la firma del emisor no trae nombre y firma");
    const name = line.slice(RECEIPT_SIG_PREFIX.length, sp);
    if (name !== header.tenant) {
      throw new Error(
        `la firma del emisor dice ser de ${JSON.stringify(name)} y el header declara ${JSON.stringify(header.tenant)}`,
      );
    }
    receiptSig = fromBase64(line.slice(sp + 1));
    if (toBase64(receiptSig) !== line.slice(sp + 1)) {
      throw new Error("la firma del emisor no está en base64 canónico");
    }
    if (receiptSig.length !== BLOCK_SIG_SIZE) {
      throw new Error(`la firma del emisor mide ${receiptSig.length} bytes y una Ed25519 mide ${BLOCK_SIG_SIZE}`);
    }
    // Lo firmado es el recibo SIN esta línea. Se quita de la cadena en vez de
    // volver a renderizar el documento: son los mismos bytes y no hay dos caminos
    // que puedan divergir.
    const entera = line + "\n";
    const at = receipt.lastIndexOf(entera);
    if (at < 0) throw new Error("no se pudo aislar la línea de la firma del emisor");
    signedBytes = receipt.slice(0, at) + receipt.slice(at + entera.length);
    afterSig = afterSig.slice(nl3 + 1);
  }

  const proof = parseProof(afterSig);
  const note = parseNote(proof.checkpointNote);
  const checkpoint = parseCheckpoint(note.text);

  return {
    recipient, headerJSON, blockSig, receiptSig, signedBytes, header,
    headerIndex: headerIndexOf(headerJSON), proof, note, checkpoint, text,
  };
}

/**
 * headerIndexOf lee el índice del header canónico como BigInt, del TEXTO.
 *
 * No se usa el valor que devuelve JSON.parse porque los números de JavaScript
 * son de doble precisión: un índice por encima de 2^53 se redondea al parsear,
 * en silencio, y la comparación con el índice de la prueba compararía dos
 * valores ya corrompidos —que además coincidirían, dando por bueno un recibo
 * que no lo es—.
 *
 * El header está en forma canónica JCS, donde las claves van ordenadas y sin
 * espacios, así que "index" es siempre el primer campo y su valor son dígitos.
 */
function headerIndexOf(headerJSON: string): bigint {
  const m = /"index"\s*:\s*(\d+)/.exec(headerJSON);
  if (!m) throw new Error("el header no lleva un índice entero");
  return BigInt(m[1]!);
}

/** field extrae el valor de una línea del encabezado. */
function field(text: string, prefix: string): string {
  for (const line of text.split("\n")) {
    if (line.startsWith(prefix)) return line.slice(prefix.length);
  }
  throw new Error(`falta la línea ${JSON.stringify(prefix.trim())}`);
}

/**
 * renderHeader reconstruye el encabezado a partir de la prueba.
 *
 * Tiene que producir EXACTAMENTE los mismos bytes que el emisor en Go. Es el
 * punto donde las dos implementaciones se tienen que encontrar, y por eso los
 * vectores golden existen: si alguien cambia un espacio en un lado, el otro lo
 * nota.
 */
function renderHeader(p: Parsed, provable: string | null): string {
  const lines = [
    MAGIC,
    `destinatario      : ${p.recipient}${RECIPIENT_NOTE}`,
    `emisor (tenant)   : ${p.header.tenant}`,
    `tipo de registro  : ${p.header.type}`,
    `hash del contenido: ${p.header.payload_hash}`,
    `bloque            : ${p.headerIndex}`,
    "",
    `TIEMPO DECLARADO  : ${p.header.timestamp}  (declarado por el sistema emisor)`,
    provable === null
      ? `TIEMPO DEMOSTRABLE: ${NO_PROVABLE_TIME}`
      : `TIEMPO DEMOSTRABLE: ${provable}  (atestiguado por testigos)`,
    "",
    ...LEGAL_NOTICE,
    "",
    "",
  ];
  return lines.join("\n");
}

/** unixToRFC3339 formatea un instante Unix como lo hace el emisor. */
function unixToRFC3339(unix: bigint): string {
  const d = new Date(Number(unix) * 1000);
  const p2 = (n: number) => n.toString().padStart(2, "0");
  return (
    `${d.getUTCFullYear()}-${p2(d.getUTCMonth() + 1)}-${p2(d.getUTCDate())}` +
    `T${p2(d.getUTCHours())}:${p2(d.getUTCMinutes())}:${p2(d.getUTCSeconds())}Z`
  );
}

/** receiptText devuelve solo el encabezado legible, para mostrarlo. */
export function receiptText(receipt: string): string {
  const at = receipt.indexOf(SEPARATOR);
  return at < 0 ? "" : receipt.slice(0, at).replace(/\n+$/, "");
}

export { fromHex, toHex, fromBase64, equal, leafHash };
