// Checkpoints de c2sp.org/tlog-checkpoint: origin, tamaño del árbol y raíz.

import { fromBase64, toBase64 } from "./bytes.js";

/** Checkpoint es el cuerpo de la nota. */
export interface Checkpoint {
  origin: string;
  size: bigint;
  rootHash: Uint8Array;
}

/**
 * parseCheckpoint lee el cuerpo de un checkpoint.
 *
 * Es estricto con la codificación: exige exactamente tres líneas, decimal sin
 * ceros a la izquierda y base64 canónico. Núcleo emite el formato mínimo y su
 * parser rechaza líneas de extensión (PROTOCOL.md §3, fallo cerrado); aceptar
 * variantes aquí abriría dos formas de escribir el mismo checkpoint, y dos
 * formas es una de más cuando lo que se compara son bytes firmados.
 */
export function parseCheckpoint(text: string): Checkpoint {
  if (!text.endsWith("\n")) throw new Error("el checkpoint no termina en salto de línea");
  const lines = text.slice(0, -1).split("\n");
  if (lines.length !== 3) {
    throw new Error(`el checkpoint tiene ${lines.length} líneas, se esperaban 3`);
  }
  const [origin, sizeLine, rootLine] = lines as [string, string, string];
  if (origin.length === 0) throw new Error("origin vacío");
  if (!/^(0|[1-9][0-9]*)$/.test(sizeLine)) {
    throw new Error(`tamaño no canónico: ${JSON.stringify(sizeLine)}`);
  }
  const rootHash = fromBase64(rootLine);
  if (rootHash.length !== 32) {
    throw new Error(`la raíz mide ${rootHash.length} bytes, se esperaban 32`);
  }
  if (toBase64(rootHash) !== rootLine) {
    throw new Error("la raíz no está en base64 canónico");
  }
  return { origin, size: BigInt(sizeLine), rootHash };
}
