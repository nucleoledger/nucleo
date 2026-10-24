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

// esperado es el veredicto que este SDK tiene que dar HOY. Con "requires": "0.8-draft",
// el de una política sin log_mldsa_key: toPolicy no la copia y el SDK no la lee hasta el
// Sprint D, que es cuando pasa a comprobar verdicts.ts.
export function esperado(v: { name: string; valid: boolean; requires?: string;
  verdicts?: { without_log_mldsa_key: { valid: boolean } } }): boolean {
  if (v.requires === undefined) return v.valid;
  if (v.requires === "0.8-draft" && v.verdicts) return v.verdicts.without_log_mldsa_key.valid;
  throw new Error(`${v.name}: requires ${v.requires}, una versión que este test no conoce`);
}
