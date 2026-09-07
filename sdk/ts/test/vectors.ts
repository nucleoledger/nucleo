// Rutas a testdata/vectors/, que son LOS MISMOS ficheros que lee Go.
//
// No se copian ni se generan aquí a propósito. Si el verificador de TypeScript
// tuviera su propia copia, las dos implementaciones podrían divergir sin que
// nadie se enterara, y unos vectores compartidos que no se comparten no
// verifican nada.

import { readFileSync, readdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));

/** VECTORS es la raíz de los vectores compartidos. */
export const VECTORS = join(here, "..", "..", "..", "testdata", "vectors");

export function readVector(...parts: string[]): string {
  return readFileSync(join(VECTORS, ...parts), "utf8");
}

export function readJSON<T>(...parts: string[]): T {
  return JSON.parse(readVector(...parts)) as T;
}

export function listVectors(dir: string): string[] {
  return readdirSync(join(VECTORS, dir)).filter((f) => f.endsWith(".json")).sort();
}
