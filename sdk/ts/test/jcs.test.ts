import { describe, expect, it } from "vitest";
import { isCanonicalJCS } from "../src/jcs.js";
import { listVectors, readJSON } from "./vectors.js";

// El verificador no canonicaliza: COMPRUEBA que lo recibido ya sea canónico.
// Lo que hay que probar, por tanto, es el orden de claves de RFC 8785, que es
// por unidades de código UTF-16 y no por puntos de código.

describe("orden de claves JCS", () => {
  it("acepta un header de bloque en orden canónico", () => {
    const header =
      '{"index":2,"payload_cid":"blob://x","payload_hash":"aa","prev_hash":"bb",' +
      '"signer_pubkey":"cc","tenant":"179","timestamp":"2026-01-01T00:00:00Z","type":"t"}';
    expect(isCanonicalJCS(header)).toBe(true);
  });

  it("rechaza el mismo contenido con las claves en otro orden", () => {
    const header =
      '{"index":2,"tenant":"179","payload_cid":"blob://x","payload_hash":"aa",' +
      '"prev_hash":"bb","signer_pubkey":"cc","timestamp":"2026-01-01T00:00:00Z","type":"t"}';
    expect(isCanonicalJCS(header)).toBe(false);
  });

  it("ordena por unidades de código UTF-16, no por puntos de código", () => {
    // U+FB33 (דּ) va ANTES que U+10000 (𐀀) en UTF-16, porque el segundo se
    // codifica como el par sustituto D800 DC00 y 0xD800 < 0xFB33. Ordenar por
    // punto de código daría el orden contrario. Es el caso del ejemplo de
    // RFC 8785 §3.2.3, y el que separa una implementación correcta de una que
    // "parece" correcta con claves ASCII.
    expect(isCanonicalJCS('{"\u{10000}":1,"\uFB33":2}')).toBe(true);
    expect(isCanonicalJCS('{"\uFB33":1,"\u{10000}":2}')).toBe(false);
  });

  it("rechaza lo que no sea un objeto", () => {
    expect(isCanonicalJCS("[1,2]")).toBe(false);
    expect(isCanonicalJCS("no es json")).toBe(false);
  });
});

// H4.2 de la cuarta auditoría: la comprobación de canonicidad era solo el ORDEN de las
// claves, con JSON.parse y Object.keys. Estas son las tres cosas que dejaba pasar y que
// Go rechaza porque compara bytes.
describe("canonicidad JCS completa", () => {
  const canonico = '{"a":"x","b":1,"c":"\\n"}';

  it("acepta la forma canónica", () => {
    expect(isCanonicalJCS(canonico)).toBe(true);
  });

  it("rechaza lo que el orden de claves no veía", () => {
    for (const [nombre, raw] of Object.entries({
      "miembro repetido": '{"a":"x","a":"y","b":1,"c":"\\n"}',
      "espacio entre tokens": '{"a": "x","b":1,"c":"\\n"}',
      "salto de línea": '{\n"a":"x","b":1,"c":"\\n"}',
      "escape alternativo en el valor": '{"a":"\\u0078","b":1,"c":"\\n"}',
      "escape alternativo en la clave": '{"\\u0061":"x","b":1,"c":"\\n"}',
      "escape largo de un control": '{"a":"x","b":1,"c":"\\u000a"}',
      "claves desordenadas": '{"b":1,"a":"x","c":"\\n"}',
      "entero con cero a la izquierda": '{"a":"x","b":01,"c":"\\n"}',
      "entero con exponente": '{"a":"x","b":1e0,"c":"\\n"}',
      "fracción": '{"a":"x","b":1.0,"c":"\\n"}',
      "coma final": '{"a":"x","b":1,"c":"\\n",}',
      "sobra texto detrás": canonico + " ",
      "no es JSON": "{",
    })) {
      expect(isCanonicalJCS(raw), nombre).toBe(false);
    }
  });

  it("los headers de los vectores golden son canónicos", () => {
    for (const f of listVectors("receipt")) {
      const v = readJSON<{ receipt: string }>("receipt", f);
      const maquina = v.receipt.split("--- prueba verificable ---\n")[1]!;
      expect(isCanonicalJCS(maquina.split("\n")[0]!), f).toBe(true);
    }
  });
});
