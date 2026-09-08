// Recibos de Núcleo: la prueba de tlog-proof envuelta en un encabezado legible.
//
// Este fichero implementa la regla que hace fiable ese encabezado: el texto se
// DERIVA de la prueba, y verificar consiste, entre otras cosas, en volver a
// derivarlo y comprobar que coincide byte a byte. Un recibo con prueba impecable
// y texto retocado —otra fecha, otro emisor, otro importe— se rechaza.

import { equal, fromBase64, fromHex, toHex, utf8 } from "./bytes.js";
import { parseCheckpoint, type Checkpoint } from "./checkpoint.js";
import { cosignedMessage, parseCosignature, COSIGNATURE_SIZE } from "./cosignature.js";
import { sha256, verifyEd25519 } from "./crypto.js";
import { jsonKeysAreSorted } from "./jcs.js";
import { leafHash, verifyInclusion } from "./merkle.js";
import { ALG_COSIGNATURE_V1, ALG_ED25519, keyId, parseNote, type Note } from "./note.js";
import { parseProof, type TlogProof } from "./proof.js";

/** MAGIC es la primera línea de un recibo. */
export const MAGIC = "nucleo.org/receipt@v1";

/** SEPARATOR abre la parte de máquina. */
export const SEPARATOR = "--- prueba verificable ---";

/** NO_PROVABLE_TIME es lo que se imprime cuando no hay tiempo demostrable. */
export const NO_PROVABLE_TIME = "SIN TIEMPO DEMOSTRABLE";

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
}

/** parsed guarda lo que se pudo leer del recibo antes de verificarlo. */
interface Parsed {
  recipient: string;
  headerJSON: string;
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
  const reasons: string[] = [];
  const fail = (why: string): Result => ({
    valid: false,
    declaredTime: null,
    provableTime: null,
    blockIndex: null,
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
    return fail(`el recibo no se pudo leer: ${(e as Error).message}`);
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

  // 3. La hoja de Merkle sale del header, no del recibo. Así el destinatario
  // puede atar SU documento al registro: recomputa el hash de su contenido y
  // comprueba que es el payload_hash que hay dentro de este header.
  const entryHash = await sha256(utf8(p.headerJSON));

  // 4. Firmas de la nota del checkpoint.
  const logKey = fromHex(policy.logKey);
  const logId = await keyId(sha256, policy.origin, ALG_ED25519, logKey);
  let logSigned = false;

  const witnesses = new Map<number, { name: string; key: Uint8Array }>();
  for (const [name, hex] of Object.entries(policy.witnesses ?? {})) {
    const key = fromHex(hex);
    witnesses.set(await keyId(sha256, name, ALG_COSIGNATURE_V1, key), { name, key });
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
    entryHash,
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

  if (!text.startsWith(MAGIC + "\n")) {
    throw new Error(`se esperaba ${MAGIC} en la primera línea`);
  }
  const recipient = field(text, "destinatario      : ");

  const nl = machine.indexOf("\n");
  if (nl < 0) throw new Error("falta el header canónico");
  const headerJSON = machine.slice(0, nl);
  const header = JSON.parse(headerJSON) as BlockHeader;

  const proof = parseProof(machine.slice(nl + 1));
  const note = parseNote(proof.checkpointNote);
  const checkpoint = parseCheckpoint(note.text);

  return { recipient, headerJSON, header, headerIndex: headerIndexOf(headerJSON), proof, note, checkpoint, text };
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
    `destinatario      : ${p.recipient}`,
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
