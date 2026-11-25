import { describe, expect, it } from "vitest";
import { base64Canonical, fromBase64 } from "../src/bytes.js";

// El base64 de cable (Sprint 38b): la misma regla que checkpoint.DecodeBase64Canonical en
// Go y Bytes::base64Canonical en PHP. Los vectores de RFC 4648 §10 van escritos aquí desde
// la RFC.

const ascii = (b: Uint8Array | null) => (b === null ? null : new TextDecoder().decode(b));

describe("base64 canónico", () => {
  it("decodifica los vectores de RFC 4648 §10", () => {
    const rfc: Record<string, string> = {
      "Zg==": "f", "Zm8=": "fo", "Zm9v": "foo", "Zm9vYg==": "foob", "Zm9vYmE=": "fooba", "Zm9vYmFy": "foobar",
    };
    for (const [b64, want] of Object.entries(rfc)) {
      expect(ascii(base64Canonical(b64)), b64).toBe(want);
      expect(ascii(fromBase64(b64)), b64).toBe(want);
    }
  });

  const malos: Record<string, string> = {
    vacía: "",
    "sin relleno": "Zg",
    "relleno de más": "Zg===",
    "bits de relleno a uno": "Zh==",
    "bits de relleno, un '='": "Zm9=",
    "'=' en medio": "Zg==Zm9v",
    "alfabeto URL": "-_-_",
    "el caso del ci #104": "00000000000000000000000000000\r00000000000000=",
  };
  for (const ws of ["\r", "\n", " ", "\t", "\f", "\v"]) {
    malos[`${JSON.stringify(ws)} en medio`] = `Zm9v${ws}YmFy`;
    malos[`${JSON.stringify(ws)} al final (longitud %4)`] = `Zm9vYmF${ws}`;
    malos[`${JSON.stringify(ws)} al principio`] = `${ws}Zm9vYmFy`;
  }
  for (const [nombre, b64] of Object.entries(malos)) {
    it(`rechaza: ${nombre}`, () => {
      // atob a secas aceptaba los espacios en blanco: esto es lo que ya no pasa.
      expect(base64Canonical(b64)).toBeNull();
      expect(() => fromBase64(b64)).toThrow("base64 no canónico");
    });
  }
});
