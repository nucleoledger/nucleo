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

/** Veredicto es lo que un vector de recibo declara para un verificador (ADR-034 §F). */
export interface Veredicto {
  valid: boolean;
  reason?: string;
  log_mldsa?: string;
}

/** VectorDeRecibo es lo que estas funciones leen de un vector de recibo. */
export interface VectorDeRecibo {
  name: string;
  valid: boolean;
  requires?: string;
  policy: { origin: string; log_key: string; signer_key: string; witnesses: Record<string, string>; quorum: number;
    log_mldsa_key?: string };
  verdicts?: { ts: Veredicto; php: Veredicto; go: Veredicto; without_log_mldsa_key: Veredicto };
}

// veredictoTS es el veredicto que este SDK —y el bundle de la página, que es el mismo
// código— tiene que dar con la política del vector, log_mldsa_key incluida. Sin
// "requires", el de siempre; con "requires": "0.8-draft", el que el vector declara para
// "ts" (Sprint 32, Sprint D: hasta entonces era el de una política sin la clave).
export function veredictoTS(v: VectorDeRecibo): Veredicto {
  if (v.requires === undefined) return { valid: v.valid };
  if (v.requires === "0.8-draft" && v.verdicts) return v.verdicts.ts;
  throw new Error(`${v.name}: requires ${v.requires}, una versión que este test no conoce`);
}

/** esperado es solo el "valid" de veredictoTS. */
export function esperado(v: VectorDeRecibo): boolean {
  return veredictoTS(v).valid;
}

/** politicaDe es la política del vector en el formato de cable, con logMLDSAKey si la trae. */
export function politicaDe(v: VectorDeRecibo, conClaveMLDSA = true): {
  origin: string; logKey: string; signerKey: string; witnesses: Record<string, string>; quorum: number; logMLDSAKey?: string;
} {
  const p = {
    origin: v.policy.origin,
    logKey: v.policy.log_key,
    signerKey: v.policy.signer_key,
    witnesses: v.policy.witnesses,
    quorum: v.policy.quorum,
  };
  return conClaveMLDSA && v.policy.log_mldsa_key ? { ...p, logMLDSAKey: v.policy.log_mldsa_key } : p;
}

// motivoMLDSA traduce las razones de un rechazo al motivo de los vectores, solo para los
// dos de ML-DSA. Son frases fijas del verificador: si cambian, este test lo nota.
export function motivoMLDSA(reasons: readonly string[]): string | undefined {
  if (reasons.some((r) => r.startsWith("la firma post-cuántica del log (ML-DSA-44) de la clave que fija la política mide "))) {
    return "mldsa_signature_invalid";
  }
  if (reasons.includes("la política fija la clave ML-DSA-44 del log (logMLDSAKey) y el checkpoint no trae su firma")) {
    return "mldsa_signature_missing";
  }
  return undefined;
}
