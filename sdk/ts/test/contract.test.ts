import { describe, expect, it } from "vitest";
import { verifyReceipt, type Policy } from "../src/index.js";
import { readJSON } from "./vectors.js";

// Hallazgo LOW de la auditoría pre-pública: verifyReceipt promete no lanzar
// nunca, y la política no estaba cubierta por esa promesa. Una clave con un
// carácter de más hacía que fromHex lanzara antes de llegar a ninguna
// comprobación.
//
// Importa más de lo que parece. La promesa existe para que quien llama no tenga
// que envolver cada invocación en un try; si la promesa tiene excepciones, un
// try olvidado convierte un recibo malo en una excepción no capturada. En una
// página web eso es un botón que no hace nada; en un servidor, un 500 en vez de
// un "recibo inválido".

interface Vector {
  receipt: string;
  policy: { origin: string; log_key: string; witnesses: Record<string, string>; quorum: number };
}

const bueno = readJSON<Vector>("receipt", "valido-1-cosignature.json");
const politicaBuena: Policy = {
  origin: bueno.policy.origin,
  logKey: bueno.policy.log_key,
  witnesses: bueno.policy.witnesses,
  quorum: bueno.policy.quorum,
};

/** noLanza ejecuta y exige un veredicto, nunca una excepción. */
async function noLanza(receipt: unknown, policy: unknown, que: string) {
  const r = await verifyReceipt(receipt as string, policy as Policy);
  expect(r.valid, que).toBe(false);
  expect(r.reasons.length, `${que}: sin razones`).toBeGreaterThan(0);
  expect(r.provableTime, `${que}: tiempo demostrable en un rechazo`).toBeNull();
  // Y el resultado se puede serializar salvo por blockIndex, que es bigint.
  expect(() => JSON.stringify({ ...r, blockIndex: String(r.blockIndex) })).not.toThrow();
}

describe("verifyReceipt nunca lanza", () => {
  it("con la política rota de mil maneras", async () => {
    const politicas: Array<[string, unknown]> = [
      ["logKey con hex impar", { ...politicaBuena, logKey: "abc" }],
      ["logKey con basura", { ...politicaBuena, logKey: "zzzz".repeat(16) }],
      ["logKey corta", { ...politicaBuena, logKey: "aa".repeat(31) }],
      ["logKey larga", { ...politicaBuena, logKey: "aa".repeat(33) }],
      ["logKey vacía", { ...politicaBuena, logKey: "" }],
      ["logKey no es cadena", { ...politicaBuena, logKey: 42 }],
      ["logKey ausente", { origin: politicaBuena.origin }],
      ["origin vacío", { ...politicaBuena, origin: "" }],
      ["origin ausente", { logKey: politicaBuena.logKey }],
      ["testigo con hex roto", { ...politicaBuena, witnesses: { "w/1": "no-es-hex" } }],
      ["testigo con clave corta", { ...politicaBuena, witnesses: { "w/1": "aa" } }],
      ["testigo no es cadena", { ...politicaBuena, witnesses: { "w/1": null } }],
      ["witnesses no es objeto", { ...politicaBuena, witnesses: "nope" }],
      ["quorum negativo", { ...politicaBuena, quorum: -1 }],
      ["quorum no entero", { ...politicaBuena, quorum: 1.5 }],
      ["política nula", null],
      ["política indefinida", undefined],
      ["política es una cadena", "no soy una política"],
      ["política es un número", 7],
      ["política vacía", {}],
    ];
    for (const [que, p] of politicas) {
      await noLanza(bueno.receipt, p, que);
    }
  });

  it("con el recibo roto de mil maneras", async () => {
    const recibos: Array<[string, unknown]> = [
      ["vacío", ""],
      ["truncado", bueno.receipt.slice(0, 50)],
      ["solo el separador", "--- prueba verificable ---\n"],
      ["sin magic", bueno.receipt.replace("nucleo.org/receipt@v1", "otra/cosa@v9")],
      ["header no es JSON", bueno.receipt.replace(/\{"index".*?\}/, "{no json}")],
      ["base64 roto en la prueba", bueno.receipt.replace(/^[A-Za-z0-9+/]{43}=$/m, "@@@@")],
      ["nulo", null],
      ["indefinido", undefined],
      ["un número", 12345],
      ["un objeto", { receipt: "x" }],
      ["un array", []],
      ["solo saltos de línea", "\n\n\n\n"],
      ["muy largo", "x".repeat(200000)],
      ["encabezado con un espacio de más", bueno.receipt.replace("bloque", "blo que")],
    ];
    for (const [que, r] of recibos) {
      await noLanza(r, politicaBuena, que);
    }
  });

  it("con las dos cosas rotas a la vez", async () => {
    await noLanza(null, null, "todo nulo");
    await noLanza(undefined, undefined, "todo indefinido");
    await noLanza(12345, { logKey: [] }, "tipos absurdos");
  });

  it("control negativo: el recibo bueno con la política buena SÍ verifica", async () => {
    const r = await verifyReceipt(bueno.receipt, politicaBuena);
    expect(r.valid, r.reasons.join(" | ")).toBe(true);
  });

  it("una política válida pero equivocada da razones, no excepciones", async () => {
    const r = await verifyReceipt(bueno.receipt, {
      ...politicaBuena,
      logKey: "11".repeat(32),
    });
    expect(r.valid).toBe(false);
    expect(r.reasons.join(" ")).toContain("no está firmado por la clave del log");
  });

  it("el mensaje distingue una política ilegible de una prueba que falla", async () => {
    const rota = await verifyReceipt(bueno.receipt, { ...politicaBuena, logKey: "zz" });
    expect(rota.reasons[0]).toContain("la política no se pudo leer");

    const equivocada = await verifyReceipt(bueno.receipt, {
      ...politicaBuena,
      logKey: "11".repeat(32),
    });
    expect(equivocada.reasons[0]).not.toContain("no se pudo leer");
  });
});
