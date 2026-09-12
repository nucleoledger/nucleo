import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { runInNewContext } from "node:vm";
import { describe, expect, it } from "vitest";
import { listVectors, readJSON } from "./vectors.js";
import { LEGAL_NOTICE } from "../src/receipt.js";

// Verificación ANTI-TEATRO.
//
// La página web sirve un bundle de esta biblioteca. Si nadie lo prueba, nada
// impide que el fichero empaquetado se quede viejo, o que alguien lo edite a
// mano, y la página acabaría enseñando un ✔ producido por código que ninguna
// suite mira. Este test carga EXACTAMENTE el fichero que carga el HTML y le
// pasa los mismos vectores golden.

const here = dirname(fileURLToPath(import.meta.url));
const bundlePath = join(here, "..", "..", "..", "web", "verify", "nucleo-verify.js");
const htmlPath = join(here, "..", "..", "..", "web", "verify", "index.html");
const ejemploPath = join(here, "..", "..", "..", "web", "verify", "ejemplo.js");

interface Vector {
  name: string;
  receipt: string;
  policy: { origin: string; log_key: string; witnesses: Record<string, string>; quorum: number };
  valid: boolean;
  provable_time?: string;
  block_index: number;
}

/** loadBundle evalúa el bundle en un contexto limpio, como haría el navegador. */
function loadBundle(): Record<string, unknown> {
  const code = readFileSync(bundlePath, "utf8");
  const sandbox: Record<string, unknown> = { crypto: globalThis.crypto, console, TextEncoder, TextDecoder, atob, btoa };
  sandbox["globalThis"] = sandbox;
  runInNewContext(code, sandbox, { filename: "nucleo-verify.js" });
  const api = sandbox["NucleoVerify"];
  if (!api) throw new Error("el bundle no expone NucleoVerify");
  return api as Record<string, unknown>;
}

describe("el bundle que sirve la página web", () => {
  it("existe y expone verifyReceipt", () => {
    const api = loadBundle();
    expect(typeof api["verifyReceipt"]).toBe("function");
  });

  it("el HTML carga ese mismo fichero, y ninguna otra copia", () => {
    const html = readFileSync(htmlPath, "utf8");
    expect(html).toContain('<script src="nucleo-verify.js">');
    // La página no debe traer su propia criptografía. Se buscan LLAMADAS, no
    // la palabra: el pie menciona Ed25519 para decir qué navegadores hacen
    // falta, y eso es prosa. Un test que confunda mencionar con implementar
    // obliga a reescribir el texto para que pase, que es exactamente al revés.
    for (const señal of ["crypto.subtle", "importKey(", "digest(", "function sha256"]) {
      expect(html, `el HTML parece implementar criptografía: ${señal}`).not.toContain(señal);
    }
  });

  it("el ejemplo embebido se carga ANTES del script que lo usa", () => {
    const html = readFileSync(htmlPath, "utf8");
    const ejemplo = html.indexOf('src="ejemplo.js"');
    const usa = html.indexOf("window.NUCLEO_EJEMPLO");
    expect(ejemplo).toBeGreaterThan(-1);
    expect(usa).toBeGreaterThan(ejemplo);
  });

  for (const file of listVectors("receipt")) {
    const v = readJSON<Vector>("receipt", file);
    it(`${v.name}: el bundle da el mismo veredicto que la biblioteca`, async () => {
      const api = loadBundle();
      const verify = api["verifyReceipt"] as (r: string, p: unknown) => Promise<{ valid: boolean; provableTime: string | null; blockIndex: bigint | null }>;
      const result = await verify(v.receipt, {
        origin: v.policy.origin,
        logKey: v.policy.log_key,
        witnesses: v.policy.witnesses,
        quorum: v.policy.quorum,
      });
      expect(result.valid).toBe(v.valid);
      if (v.valid) {
        expect(result.provableTime).toBe(v.provable_time ?? null);
        expect(result.blockIndex).toBe(BigInt(v.block_index));
      }
    });
  }

  // La tercera implementación del rechazo: la que de verdad va a usar la contraparte
  // es el BUNDLE, no la biblioteca. Que la biblioteca rechace un recibo redirigido no
  // prueba que la página lo rechace: podría servir un bundle viejo. Este test va
  // contra el mismo fichero que carga el HTML.
  it("el bundle rechaza un recibo con el destinatario retocado", async () => {
    const v = readJSON<Vector>("receipt", "valido-1-cosignature.json");
    const api = loadBundle();
    const verify = api["verifyReceipt"] as (
      r: string,
      p: unknown,
    ) => Promise<{ valid: boolean; receiptSignatureVerified: boolean | null; reasons: string[] }>;
    const pol = {
      origin: v.policy.origin,
      logKey: v.policy.log_key,
      witnesses: v.policy.witnesses,
      quorum: v.policy.quorum,
    };

    const bueno = await verify(v.receipt, pol);
    expect(bueno.valid, bueno.reasons.join(" | ")).toBe(true);
    expect(bueno.receiptSignatureVerified).toBe(true);

    const original = "María Pérez (cédula 1712345678)";
    const redirigido = v.receipt.replace(original, "Juan Gómez".padEnd(original.length));
    expect(redirigido).not.toBe(v.receipt);
    const malo = await verify(redirigido, pol);
    expect(malo.valid).toBe(false);
    expect(malo.receiptSignatureVerified).toBe(false);
  });

  {
  }

  it("el recibo de ejemplo de la página verifica con su política", async () => {
    const api = loadBundle();
    const sandbox: Record<string, unknown> = { window: {} };
    sandbox["globalThis"] = sandbox;
    runInNewContext(readFileSync(ejemploPath, "utf8"), sandbox, { filename: "ejemplo.js" });
    const ej = (sandbox["window"] as Record<string, unknown>)["NUCLEO_EJEMPLO"] as {
      receipt: string;
      policy: unknown;
    };
    const verify = api["verifyReceipt"] as (r: string, p: unknown) => Promise<{ valid: boolean }>;
    const result = await verify(ej.receipt, ej.policy);
    expect(result.valid, "el ejemplo que ofrece la página debe verificar").toBe(true);
  });
});

// La advertencia legal tiene dos copias por necesidad: una viaja dentro del
// recibo (y la cubre la igualdad byte a byte de Parse), y otra la pinta la
// página para quien mira el veredicto sin leer el texto. Dos copias divergen
// solas; esto es lo que lo impide.
describe("la advertencia legal", () => {
  const html = readFileSync(htmlPath, "utf8");

  /** aplana deja una sola línea con espacios simples, para comparar redacciones. */
  const aplana = (x: string) => x.replace(/\s+/g, " ").trim();

  it("la página la enseña, con la MISMA redacción que el recibo", () => {
    // El título y la prosa se comparan por separado porque en el HTML los separa
    // un <strong>. La prosa sí tiene que aparecer entera y seguida: es la parte
    // que dice qué NO es este documento, y basta con partirla para suavizarla.
    const [titulo, ...prosa] = LEGAL_NOTICE;
    expect(aplana(html)).toContain(titulo);
    expect(aplana(html)).toContain(aplana(prosa.join(" ")));
  });

  it("no es letra pequeña: tiene su propio estilo, no el de las notas", () => {
    // Si alguien la degradara a .nota acabaría en gris al pie de la tarjeta,
    // que es exactamente donde nadie la lee.
    expect(html).toMatch(/class="legal"/);
    expect(html).toMatch(/\.legal\s*\{/);
  });

  it("se enseña también cuando el veredicto es válido", () => {
    // El caso peligroso no es el rechazo: es el ✔ que alguien imprime y presenta.
    const tarjeta = html.slice(html.indexOf("Recibo válido"));
    expect(tarjeta).toContain("AVISO_LEGAL");
  });
});

// C.5 del Sprint 7c: la etiqueta "(firmado por el emisor)" solo puede aparecer
// junto a un nombre cuya firma VERIFICÓ. La auditoría adversarial enseñó la fila
// del destinatario con un nombre reescrito y esa etiqueta al lado, debajo de un
// veredicto que decía lo contrario. Como la página compone la fila en JavaScript
// inline, lo que se prueba aquí es el código de esa fila tal como está escrito.
describe("la fila del destinatario en la página", () => {
  const html = readFileSync(htmlPath, "utf8");
  const fila = html.slice(html.indexOf('["destinatario"'), html.indexOf('["firma del recibo"'));

  it("condiciona la etiqueta a receiptSignatureVerified === true", () => {
    expect(fila).toContain("receiptSignatureVerified === true");
    expect(fila).toContain('"  (firmado por el emisor)"');
  });

  it("marca visualmente el nombre cuando la firma NO verifica", () => {
    expect(fila).toContain("NO VERIFICADO");
    expect(fila).toContain("✘");
  });

  it("no hay ninguna otra forma de pintar la etiqueta sin la condición", () => {
    // Se cuenta el LITERAL que se concatena al nombre —con sus dos espacios y sus
    // comillas—, no la frase suelta, que también aparece en comentarios. Si alguien
    // añadiera una segunda concatenación incondicional, este test la vería.
    const apariciones = html.split('"  (firmado por el emisor)"').length - 1;
    expect(apariciones).toBe(1);
  });
});
