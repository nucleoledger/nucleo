import { describe, expect, it } from "vitest";
import { fromHex, toHex } from "../src/bytes.js";
import { sha256 } from "../src/crypto.js";
import { leafHash, nodeHash, verifyInclusion } from "../src/merkle.js";
import { readJSON } from "./vectors.js";

// Los vectores OFICIALES de RFC 6962, los mismos ficheros que lee Go. Es la
// pieza que hace que las dos implementaciones se puedan comparar: si TS y Go
// coinciden con la RFC, coinciden entre sí, y no por casualidad.

interface Leaves {
  leaves_hex: string[];
}
interface Roots {
  empty_root_hex: string;
  roots_hex: string[];
}
interface Inclusion {
  proofs: { leaf_index: number; tree_size: number; proof_hex: string[] }[];
}

const leaves = readJSON<Leaves>("merkle", "rfc6962", "leaves.json");
const roots = readJSON<Roots>("merkle", "rfc6962", "roots.json");
const inclusion = readJSON<Inclusion>("merkle", "rfc6962", "inclusion.json");

/** root recalcula MTH(D[n]) como lo define RFC 6962 §2.1. */
async function root(data: Uint8Array[]): Promise<Uint8Array> {
  if (data.length === 0) return sha256(new Uint8Array(0));
  if (data.length === 1) return leafHash(sha256, data[0]!);
  let k = 1;
  while (k * 2 < data.length) k *= 2;
  return nodeHash(sha256, await root(data.slice(0, k)), await root(data.slice(k)));
}

describe("vectores oficiales RFC 6962", () => {
  const data = leaves.leaves_hex.map(fromHex);

  it("la raíz del árbol vacío es SHA-256 de la cadena vacía", async () => {
    expect(toHex(await root([]))).toBe(roots.empty_root_hex);
  });

  it("MTH(D[n]) coincide para n = 1..8", async () => {
    for (let n = 1; n <= roots.roots_hex.length; n++) {
      expect(toHex(await root(data.slice(0, n))), `n=${n}`).toBe(roots.roots_hex[n - 1]);
    }
  });

  for (const p of inclusion.proofs) {
    it(`prueba de inclusión (${p.leaf_index}, ${p.tree_size}) verifica`, async () => {
      const r = await root(data.slice(0, p.tree_size));
      const ok = await verifyInclusion(
        sha256,
        data[p.leaf_index]!,
        BigInt(p.leaf_index),
        BigInt(p.tree_size),
        p.proof_hex.map(fromHex),
        r,
      );
      expect(ok).toBe(true);
    });

    it(`prueba de inclusión (${p.leaf_index}, ${p.tree_size}) se rechaza contra otra raíz`, async () => {
      const wrong = fromHex(roots.empty_root_hex);
      const ok = await verifyInclusion(
        sha256,
        data[p.leaf_index]!,
        BigInt(p.leaf_index),
        BigInt(p.tree_size),
        p.proof_hex.map(fromHex),
        wrong,
      );
      expect(ok).toBe(false);
    });
  }

  it("una prueba con un nodo de más se rechaza", async () => {
    const p = inclusion.proofs.find((x) => x.tree_size === 8 && x.leaf_index === 5)!;
    const r = await root(data.slice(0, 8));
    const padded = [...p.proof_hex.map(fromHex), new Uint8Array(32)];
    expect(await verifyInclusion(sha256, data[5]!, 5n, 8n, padded, r)).toBe(false);
  });
});
