// Recibos de c2sp.org/tlog-proof: índice, camino de inclusión y checkpoint.

import { fromBase64 } from "./bytes.js";

/** MAGIC es la primera línea de un tlog-proof. */
export const MAGIC = "c2sp.org/tlog-proof@v1";

/** TlogProof es la parte verificable del recibo. */
export interface TlogProof {
  /** index es BigInt: un índice de árbol puede pasar de 2^53. */
  index: bigint;
  inclusionProof: Uint8Array[];
  checkpointNote: string;
}

/** parseProof lee un tlog-proof. */
export function parseProof(data: string): TlogProof {
  const lines = data.split("\n");
  if (lines[0] !== MAGIC) {
    throw new Error(`se esperaba ${MAGIC} en la primera línea`);
  }
  const indexLine = lines[1];
  if (indexLine === undefined || !/^(0|[1-9][0-9]*)$/.test(indexLine)) {
    throw new Error(`índice no canónico: ${JSON.stringify(indexLine)}`);
  }
  const index = BigInt(indexLine);

  const inclusionProof: Uint8Array[] = [];
  let i = 2;
  for (; i < lines.length; i++) {
    const l = lines[i]!;
    if (l === "") break;
    const node = fromBase64(l);
    if (node.length !== 32) {
      throw new Error(`nodo de ${node.length} bytes, se esperaban 32`);
    }
    inclusionProof.push(node);
  }
  if (i >= lines.length) throw new Error("falta la línea vacía antes del checkpoint");

  const checkpointNote = lines.slice(i + 1).join("\n");
  if (checkpointNote === "") throw new Error("falta la nota del checkpoint");
  return { index, inclusionProof, checkpointNote };
}
