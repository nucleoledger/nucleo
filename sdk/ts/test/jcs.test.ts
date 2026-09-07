import { describe, expect, it } from "vitest";
import { jsonKeysAreSorted } from "../src/jcs.js";

// El verificador no canonicaliza: COMPRUEBA que lo recibido ya sea canónico.
// Lo que hay que probar, por tanto, es el orden de claves de RFC 8785, que es
// por unidades de código UTF-16 y no por puntos de código.

describe("orden de claves JCS", () => {
  it("acepta un header de bloque en orden canónico", () => {
    const header =
      '{"index":2,"payload_cid":"blob://x","payload_hash":"aa","prev_hash":"bb",' +
      '"signer_pubkey":"cc","tenant":"179","timestamp":"2026-01-01T00:00:00Z","type":"t"}';
    expect(jsonKeysAreSorted(header)).toBe(true);
  });

  it("rechaza el mismo contenido con las claves en otro orden", () => {
    const header =
      '{"index":2,"tenant":"179","payload_cid":"blob://x","payload_hash":"aa",' +
      '"prev_hash":"bb","signer_pubkey":"cc","timestamp":"2026-01-01T00:00:00Z","type":"t"}';
    expect(jsonKeysAreSorted(header)).toBe(false);
  });

  it("ordena por unidades de código UTF-16, no por puntos de código", () => {
    // U+FB33 (דּ) va ANTES que U+10000 (𐀀) en UTF-16, porque el segundo se
    // codifica como el par sustituto D800 DC00 y 0xD800 < 0xFB33. Ordenar por
    // punto de código daría el orden contrario. Es el caso del ejemplo de
    // RFC 8785 §3.2.3, y el que separa una implementación correcta de una que
    // "parece" correcta con claves ASCII.
    expect(jsonKeysAreSorted('{"\u{10000}":1,"\uFB33":2}')).toBe(true);
    expect(jsonKeysAreSorted('{"\uFB33":1,"\u{10000}":2}')).toBe(false);
  });

  it("rechaza lo que no sea un objeto", () => {
    expect(jsonKeysAreSorted("[1,2]")).toBe(false);
    expect(jsonKeysAreSorted("no es json")).toBe(false);
  });
});
