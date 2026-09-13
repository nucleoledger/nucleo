import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { runInNewContext } from "node:vm";
import { describe, expect, it } from "vitest";
import { parsePolicyText, validatePolicy } from "../src/index.js";
import { listVectors, readJSON } from "./vectors.js";

// Los vectores de testdata/vectors/policy/ (PROTOCOL.md §3.2, ADR-018), escritos a
// mano desde la tabla. Los mismos ficheros los lee internal/policy en Go. Se pasan
// por la biblioteca Y por el bundle que carga la página: es el bundle el que lee lo
// que la contraparte pega en el formulario.

interface PolicyVector {
  name: string;
  description: string;
  text: string;
  valid: boolean;
  reason: string;
}

const here = dirname(fileURLToPath(import.meta.url));
const bundlePath = join(here, "..", "..", "..", "web", "verify", "nucleo-verify.js");

function bundleParse(): (t: string) => unknown {
  const sandbox: Record<string, unknown> = { crypto: globalThis.crypto, console, TextEncoder, TextDecoder, atob, btoa };
  sandbox["globalThis"] = sandbox;
  runInNewContext(readFileSync(bundlePath, "utf8"), sandbox, { filename: "nucleo-verify.js" });
  const api = sandbox["NucleoVerify"] as Record<string, unknown>;
  return api["parsePolicyText"] as (t: string) => unknown;
}

const acepta = (f: (t: string) => unknown, t: string): boolean => {
  try {
    f(t);
    return true;
  } catch {
    return false;
  }
};

describe("vectores de política", () => {
  const files = listVectors("policy");
  const delBundle = bundleParse();

  it("hay al menos 60 vectores, válidos e inválidos", () => {
    expect(files.length).toBeGreaterThanOrEqual(60);
  });

  for (const file of files) {
    const v = readJSON<PolicyVector>("policy", file);
    it(`${v.name}: ${v.description}`, () => {
      expect(acepta(parsePolicyText, v.text), "biblioteca").toBe(v.valid);
      expect(acepta(delBundle, v.text), "bundle de la página").toBe(v.valid);
      if (v.valid) {
        // Y la misma política, ya como objeto, pasa también por validatePolicy.
        expect(acepta((t) => validatePolicy(JSON.parse(t)), v.text), "validatePolicy").toBe(true);
      }
    });
  }
});

describe("validatePolicy con objetos", () => {
  const buena = readJSON<PolicyVector>("policy", "valida-con-signerkey.json");
  const obj = JSON.parse(buena.text) as Record<string, unknown>;

  it("rechaza lo que el formato rechaza aunque venga como objeto", () => {
    for (const [nombre, rota] of Object.entries({
      "sin quorum": { ...obj, quorum: undefined },
      "quorum 0": { ...obj, quorum: 0 },
      "sin testigos": { ...obj, witnesses: {} },
      "variante de mayúsculas": { ...obj, signerkey: obj["signerKey"] },
      "miembro desconocido": { ...obj, extra: 1 },
      "clave en mayúsculas": { ...obj, logKey: String(obj["logKey"]).toUpperCase() },
      "NaN": { ...obj, quorum: Number.NaN },
    })) {
      expect(() => validatePolicy(rota), nombre).toThrow();
    }
  });
});
