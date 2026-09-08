import { describe, expect, it } from "vitest";
import { verifyReceipt, type Policy } from "../src/index.js";
import { ed25519Available } from "../src/crypto.js";
import { listVectors, readJSON } from "./vectors.js";

interface Vector {
  name: string;
  description: string;
  receipt: string;
  policy: { origin: string; log_key: string; witnesses: Record<string, string>; quorum: number };
  entry_hash: string;
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
