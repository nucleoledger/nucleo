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

// H5 de la cuarta auditoría: "__proto__" es un nombre de testigo válido para
// c2sp.org/signed-note y una trampa clásica de JavaScript. Asignarlo a un objeto normal
// no crea un miembro: cambia el prototipo. El testigo desaparecía del mapa sin un solo
// error, y una política de dos testigos pasaba a tener uno.
describe("un testigo llamado __proto__", () => {
  const K1 = "5e423033044f56a13a686799487bcbfa63dd1e39204cec27dd39a26daa615628";
  const K2 = "dd7e84d010aed28a416e928f50c4c09ac0f94a8f5b346548168bddb61cdb7263";
  // El texto se escribe a mano: un literal de objeto con __proto__: ... también cambia
  // el prototipo, así que JSON.stringify jamás produciría este documento. Lo produce
  // cualquiera que escriba la política con un editor, que es de donde viene.
  const texto =
    `{"origin":"nucleoledger.com/mi-empresa","logKey":"${K1}",` +
    `"witnesses":{"__proto__":"${K2}","witness.example/w1":"${K1}"},"quorum":2}`;

  it("sobrevive al parseo, con su clave y sin tocar el prototipo", () => {
    const p = parsePolicyText(texto);
    expect(Object.keys(p.witnesses).sort()).toEqual(["__proto__", "witness.example/w1"]);
    expect(p.witnesses["__proto__"]).toBe(K2);
    expect(Object.getPrototypeOf(p.witnesses)).toBeNull();
    expect(({} as Record<string, unknown>)["x"]).toBeUndefined();
  });

  it("sobrevive al round-trip por texto", () => {
    const ida = parsePolicyText(texto);
    // Se vuelve a serializar a mano por la misma razón.
    const wit = Object.entries(ida.witnesses).map(([k, v]) => `${JSON.stringify(k)}:${JSON.stringify(v)}`).join(",");
    const vuelta = parsePolicyText(
      `{"origin":${JSON.stringify(ida.origin)},"logKey":${JSON.stringify(ida.logKey)},` +
        `"witnesses":{${wit}},"quorum":${ida.quorum}}`,
    );
    expect(Object.keys(vuelta.witnesses).sort()).toEqual(["__proto__", "witness.example/w1"]);
    expect(vuelta.witnesses["__proto__"]).toBe(K2);
  });
});
