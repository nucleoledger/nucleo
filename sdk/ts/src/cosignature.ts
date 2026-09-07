// Cosignatures de c2sp.org/tlog-cosignature@v1.
//
// El blob son 72 bytes: un u64 big-endian con el instante Unix, seguido de la
// firma Ed25519 de 64 bytes. Lo firmado NO es el cuerpo de la nota a secas,
// sino "cosignature/v1\ntime <unix>\n" seguido del cuerpo: el testigo firma
// QUÉ vio y CUÁNDO lo vio, y las dos cosas van dentro del mismo mensaje para
// que no se puedan separar.

import { concat, readUint64BE, utf8 } from "./bytes.js";

/** COSIGNATURE_SIZE es el tamaño del blob de una cosignature v1. */
export const COSIGNATURE_SIZE = 72;

/** Cosignature es una cosignature ya separada. */
export interface Cosignature {
  timestamp: bigint;
  signature: Uint8Array;
}

/** parseCosignature separa el timestamp de la firma. */
export function parseCosignature(blob: Uint8Array): Cosignature | null {
  if (blob.length !== COSIGNATURE_SIZE) return null;
  return { timestamp: readUint64BE(blob, 0), signature: blob.slice(8) };
}

/** cosignedMessage arma el mensaje que el testigo firmó. */
export function cosignedMessage(timestamp: bigint, noteText: Uint8Array): Uint8Array {
  return concat(utf8(`cosignature/v1\ntime ${timestamp.toString()}\n`), noteText);
}
