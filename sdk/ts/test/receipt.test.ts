import { describe, expect, it } from "vitest";
import { verifyReceipt, type Policy } from "../src/index.js";
import { ed25519Available } from "../src/crypto.js";
import { listVectors, readJSON } from "./vectors.js";

interface Vector {
  name: string;
  description: string;
  receipt: string;
  policy: { origin: string; log_key: string; witnesses: Record<string, string>; quorum: number };
  // leaf_data es la hoja de leaf/v2 en hex: hash ‖ signature (PROTOCOL.md §2.1).
  leaf_data: string;
  leaf_rule: string;
  block_signature: string;
  valid: boolean;
  reason?: string;
  declared_time: string;
  provable_time?: string;
  block_index: number;
}

function toPolicy(v: Vector): Policy {
  return {
    origin: v.policy.origin,
    logKey: v.policy.log_key,
    witnesses: v.policy.witnesses,
    quorum: v.policy.quorum,
  };
}

describe("entorno", () => {
  it("expone Ed25519 en WebCrypto", async () => {
    expect(await ed25519Available()).toBe(true);
  });
});

describe("vectores de recibo generados por Go", () => {
  const files = listVectors("receipt");

  it("hay tres vectores", () => {
    expect(files).toHaveLength(3);
  });

  for (const file of files) {
    const v = readJSON<Vector>("receipt", file);

    it(`${v.name}: ${v.description}`, async () => {
      const result = await verifyReceipt(v.receipt, toPolicy(v));

      expect(result.valid, `razones: ${result.reasons.join(" | ")}`).toBe(v.valid);

      if (!v.valid) {
        // Un rechazo sin explicación es inútil para quien lo recibe.
        expect(result.reasons.length).toBeGreaterThan(0);
        expect(result.provableTime).toBeNull();
        return;
      }

      // EL RECIBO GENERADO POR GO VERIFICA EN TS, BYTE A BYTE.
      expect(result.blockIndex).toBe(BigInt(v.block_index));
      expect(result.declaredTime).toBe(v.declared_time);
      expect(result.provableTime).toBe(v.provable_time ?? null);
      expect(result.cosigners.length).toBeGreaterThan(0);
    });
  }
});

describe("razones de rechazo", () => {
  const valid = readJSON<Vector>("receipt", "valido-1-cosignature.json");

  it("el encabezado alterado se rechaza por no derivarse de la prueba", async () => {
    const altered = readJSON<Vector>("receipt", "alterado-encabezado.json");
    const r = await verifyReceipt(altered.receipt, toPolicy(altered));
    expect(r.valid).toBe(false);
    expect(r.reasons.join(" ")).toContain("no coincide con lo que dice la prueba");
  });

  it("la cosignature de una llave no confiable no aporta tiempo demostrable", async () => {
    const untrusted = readJSON<Vector>("receipt", "cosignature-no-confiable.json");
    const r = await verifyReceipt(untrusted.receipt, toPolicy(untrusted));
    expect(r.valid).toBe(false);
    expect(r.provableTime).toBeNull();
    // La firma del testigo no se rechaza por inválida: simplemente se ignora,
    // y por eso el encabezado deja de cuadrar.
    expect(r.ignoredSignatures.length).toBeGreaterThan(0);
  });

  it("una política con otro origin se rechaza", async () => {
    const r = await verifyReceipt(valid.receipt, { ...toPolicy(valid), origin: "otro.example/log" });
    expect(r.valid).toBe(false);
    expect(r.reasons.join(" ")).toContain("otro.example/log");
  });

  it("una clave de log equivocada se rechaza", async () => {
    const r = await verifyReceipt(valid.receipt, { ...toPolicy(valid), logKey: "11".repeat(32) });
    expect(r.valid).toBe(false);
    expect(r.reasons.join(" ")).toContain("no está firmado por la clave del log");
  });

  it("un recibo truncado se rechaza sin lanzar", async () => {
    const r = await verifyReceipt(valid.receipt.slice(0, 100), toPolicy(valid));
    expect(r.valid).toBe(false);
    expect(r.reasons[0]).toContain("no se pudo leer");
  });

  it("un byte cambiado en la prueba se rechaza", async () => {
    const broken = valid.receipt.replace("c2sp.org/tlog-proof@v1", "c2sp.org/tlog-proof@v2");
    const r = await verifyReceipt(broken, toPolicy(valid));
    expect(r.valid).toBe(false);
  });
});

describe("firmas desconocidas", () => {
  it("se ignoran sin invalidar el recibo", async () => {
    const valid = readJSON<Vector>("receipt", "valido-1-cosignature.json");
    const r = await verifyReceipt(valid.receipt, toPolicy(valid));
    expect(r.valid).toBe(true);
    // El recibo trae la firma Ed25519 del log y la cosignature del testigo; con
    // una política que conoce las dos no debería quedar ninguna ignorada.
    expect(r.ignoredSignatures).toEqual([]);
  });
});

// La firma del bloque es la ruta que un recibo v1 no daba. Aquí se comprueba que el
// verificador de TypeScript la usa de verdad, contra los MISMOS vectores que Go.
describe("la firma del bloque (leaf/v2)", () => {
  for (const name of listVectors("receipt")) {
    const v = readJSON<Vector>("receipt", name);
    it(`${name}: el vector declara leaf/v2 y trae la firma`, () => {
      expect(v.leaf_rule).toBe("leaf/v2");
      // 96 bytes en hex: 32 del hash y 64 de la firma.
      expect(v.leaf_data.length).toBe(192);
      expect(v.block_signature.length).toBe(128);
      // Y la hoja es exactamente la concatenación, en ese orden.
      expect(v.leaf_data.endsWith(v.block_signature)).toBe(true);
    });
  }

  it("un recibo válido reporta la firma del bloque verificada", async () => {
    const v = readJSON<Vector>("receipt", "valido-1-cosignature.json");
    const r = await verifyReceipt(v.receipt, toPolicy(v));
    expect(r.valid, r.reasons.join(" | ")).toBe(true);
    expect(r.blockSignatureVerified).toBe(true);
  });

  it("si se cambia la firma del bloque, el recibo NO verifica y se dice por qué", async () => {
    const v = readJSON<Vector>("receipt", "valido-1-cosignature.json");
    // Se sustituye la línea de la firma por otra de 64 bytes bien formada. El
    // recibo sigue teniendo la forma correcta: lo que falla es la criptografía.
    const lineas = v.receipt.split("\n");
    const i = lineas.findIndex((l) => /^[A-Za-z0-9+/]{86}==$/.test(l));
    expect(i, "no se encontró la línea de la firma del bloque").toBeGreaterThan(0);
    lineas[i] = btoa(String.fromCharCode(...new Uint8Array(64)));
    const r = await verifyReceipt(lineas.join("\n"), toPolicy(v));
    expect(r.valid).toBe(false);
    expect(r.blockSignatureVerified).toBe(false);
    expect(r.reasons.join(" ")).toContain("la firma del bloque no verifica");
  });

  it("un recibo de la versión vieja se rechaza diciendo que es v1", async () => {
    const v = readJSON<Vector>("receipt", "valido-1-cosignature.json");
    const viejo = v.receipt.replace("nucleo.org/receipt@v2", "nucleo.org/receipt@v1");
    const r = await verifyReceipt(viejo, toPolicy(v));
    expect(r.valid).toBe(false);
    expect(r.reasons.join(" ")).toContain("leaf/v1");
  });
});

// Tests ADVERSARIALES de la firma del emisor (ADR-015), en la implementación que
// de verdad va a usar la contraparte: la que corre en su navegador.
//
// Todo lo que se prueba aquí es lo que alguien con el fichero del recibo en la mano
// podría intentar. Los mismos casos existen en Go (internal/receipt); que las dos
// implementaciones coincidan en RECHAZAR es tan importante como que coincidan en
// aceptar, y los vectores compartidos solo cubren lo segundo.
describe("la firma del emisor, atacada", () => {
  const v = readJSON<Vector>("receipt", "valido-1-cosignature.json");

  it("control: el recibo íntegro verifica y reporta las dos firmas", async () => {
    const r = await verifyReceipt(v.receipt, toPolicy(v));
    expect(r.valid, r.reasons.join(" | ")).toBe(true);
    expect(r.receiptSignatureVerified).toBe(true);
    expect(r.blockSignatureVerified).toBe(true);
  });

  it("el destinatario retocado invalida el recibo", async () => {
    const original = "María Pérez (cédula 1712345678)";
    expect(v.receipt).toContain(original);
    const redirigido = v.receipt.replace(original, "Juan Gómez".padEnd(original.length));
    expect(redirigido).not.toBe(v.receipt);

    const r = await verifyReceipt(redirigido, toPolicy(v));
    expect(r.valid).toBe(false);
    expect(r.receiptSignatureVerified).toBe(false);
    expect(r.reasons.join(" ")).toContain("la firma del emisor sobre el recibo no verifica");
  });

  it("sin la línea de firma, el recibo se rechaza", async () => {
    const lineas = v.receipt.split("\n");
    const i = lineas.findIndex((l) => l.startsWith("— 1790012345001 "));
    expect(i, "no se encontró la línea de la firma del emisor").toBeGreaterThan(0);
    lineas.splice(i, 1);
    const r = await verifyReceipt(lineas.join("\n"), toPolicy(v));
    expect(r.valid).toBe(false);
    expect(r.receiptSignatureVerified).toBeNull();
    expect(r.reasons.join(" ")).toContain("no lleva firma del emisor");
  });

  it("una firma de otra clave no cuela", async () => {
    // 64 bytes bien formados que no son la firma del emisor. La clave con la que se
    // comprueba sale del header, así que no hay forma de "traer la tuya".
    const lineas = v.receipt.split("\n");
    const i = lineas.findIndex((l) => l.startsWith("— 1790012345001 "));
    lineas[i] = "— 1790012345001 " + btoa(String.fromCharCode(...new Uint8Array(64).fill(7)));
    const r = await verifyReceipt(lineas.join("\n"), toPolicy(v));
    expect(r.valid).toBe(false);
    expect(r.receiptSignatureVerified).toBe(false);
  });

  it("la línea de firma que dice otro emisor se rechaza", async () => {
    const r = await verifyReceipt(
      v.receipt.replace("— 1790012345001 ", "— 9999999999001 "),
      toPolicy(v),
    );
    expect(r.valid).toBe(false);
    expect(r.reasons.join(" ")).toContain("dice ser de");
  });

  it("suavizar la advertencia legal invalida la firma", async () => {
    // La advertencia ya estaba cubierta por la igualdad del texto. Ahora lo está
    // además por una firma, y son garantías distintas: una dice "no coincide con la
    // prueba", la otra dice "el emisor no firmó esto".
    const suave = v.receipt.replace("No constituye por sí", "Constituye  por sí");
    expect(suave).not.toBe(v.receipt);
    const r = await verifyReceipt(suave, toPolicy(v));
    expect(r.valid).toBe(false);
  });
});
