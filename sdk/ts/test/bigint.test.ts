import { describe, expect, it } from "vitest";
import { readUint64BE } from "../src/bytes.js";
import { verifyInclusion } from "../src/merkle.js";
import { sha256 } from "../src/crypto.js";
import { parseProof } from "../src/proof.js";
import { parseCheckpoint } from "../src/checkpoint.js";
import { toBase64 } from "../src/bytes.js";

// Hallazgo MEDIO de la auditoría pre-pública: la aritmética del camino de
// verificación operaba en `number` y con operadores de bits de JavaScript, que
// convierten sus operandos a enteros de 32 bits CON SIGNO. Un índice o un tamaño
// de árbol por encima de 2³¹ producía otro número, en silencio, sin excepción.
//
// Estos tests prueban la ARITMÉTICA, no un árbol real: construir un árbol de
// cuatro mil millones de hojas para comprobarlo sería absurdo. Lo que se compara
// es la secuencia de decisiones del bucle contra una referencia independiente,
// escrita aquí en BigInt puro.

/**
 * referencia reproduce el recorrido de RFC 9162 §2.1.3.2 en BigInt, sin mirar
 * la implementación: solo la descripción del algoritmo. Devuelve la traza de
 * decisiones ("izquierda"/"derecha") y cuántos nodos consume.
 */
function referencia(m: bigint, n: bigint, nodos: number): string[] {
  const traza: string[] = [];
  let fn = m;
  let sn = n - 1n;
  for (let i = 0; i < nodos; i++) {
    if (sn === 0n) {
      traza.push("sobra");
      break;
    }
    if (fn % 2n === 1n || fn === sn) {
      traza.push("derecha");
      while (fn % 2n === 0n && fn !== 0n) {
        fn /= 2n;
        sn /= 2n;
      }
    } else {
      traza.push("izquierda");
    }
    fn /= 2n;
    sn /= 2n;
  }
  traza.push(sn === 0n ? "completo" : "incompleto");
  return traza;
}

/**
 * conNumber repite el mismo recorrido con la aritmética ANTIGUA: `number` y
 * operadores de bits. Existe para demostrar que el defecto era real, no
 * hipotético.
 */
function conNumber(m: number, n: number, nodos: number): string[] {
  const traza: string[] = [];
  let fn = m;
  let sn = n - 1;
  for (let i = 0; i < nodos; i++) {
    if (sn === 0) {
      traza.push("sobra");
      break;
    }
    if ((fn & 1) === 1 || fn === sn) {
      traza.push("derecha");
      while ((fn & 1) === 0 && fn !== 0) {
        fn >>= 1;
        sn >>= 1;
      }
    } else {
      traza.push("izquierda");
    }
    fn >>= 1;
    sn >>= 1;
  }
  traza.push(sn === 0 ? "completo" : "incompleto");
  return traza;
}

describe("el defecto que se corrigió era real", () => {
  it("la aritmética de 32 bits diverge por encima de 2^31", () => {
    // Un árbol de 2^32 hojas, comprobando la última. Con bits de 32, `sn`
    // empieza en 2^32-1, que ya no cabe en un int32 con signo.
    const n = 2n ** 32n;
    const m = n - 1n;
    const conBigInt = referencia(m, n, 40);
    const conBits = conNumber(Number(m), Number(n), 40);
    expect(conBigInt).not.toEqual(conBits);
  });

  it("por debajo de 2^31 las dos coinciden, que es por lo que nadie lo notó", () => {
    for (const [m, n] of [
      [0n, 1n],
      [5n, 8n],
      [1n, 5n],
      [999n, 1000n],
      [123456n, 1000000n],
    ] as const) {
      expect(referencia(m, n, 40), `m=${m} n=${n}`).toEqual(
        conNumber(Number(m), Number(n), 40),
      );
    }
  });
});

describe("verifyInclusion opera en BigInt", () => {
  // Se le pasan índices y tamaños enormes con una prueba que no verifica: lo
  // que se comprueba es que NO explota, no truncue y devuelva false — no que
  // acepte, porque no hay árbol real detrás.
  const enormes: Array<[bigint, bigint]> = [
    [2n ** 31n, 2n ** 32n],
    [2n ** 32n + 7n, 2n ** 40n],
    [2n ** 52n, 2n ** 53n + 1n],
    [2n ** 63n - 1n, 2n ** 63n],
  ];

  for (const [m, n] of enormes) {
    it(`m=${m} n=${n} no trunca ni lanza`, async () => {
      const proof = Array.from({ length: 64 }, () => new Uint8Array(32));
      const ok = await verifyInclusion(sha256, new Uint8Array(32), m, n, proof, new Uint8Array(32));
      expect(ok).toBe(false);
    });
  }

  it("rechaza índices fuera de rango sin depender del tamaño", async () => {
    const p: Uint8Array[] = [];
    const root = new Uint8Array(32);
    expect(await verifyInclusion(sha256, new Uint8Array(32), -1n, 8n, p, root)).toBe(false);
    expect(await verifyInclusion(sha256, new Uint8Array(32), 8n, 8n, p, root)).toBe(false);
    expect(await verifyInclusion(sha256, new Uint8Array(32), 0n, 0n, p, root)).toBe(false);
    // Y el caso que un `number` haría pasar por válido: índice = tamaño, ambos
    // por encima de 2^53.
    const grande = 2n ** 60n;
    expect(await verifyInclusion(sha256, new Uint8Array(32), grande, grande, p, root)).toBe(false);
  });
});

describe("los tamaños e índices se leen como BigInt", () => {
  it("un tamaño de checkpoint mayor que 2^53 no pierde precisión", () => {
    const size = 2n ** 53n + 1n; // el primer entero que un double no representa
    // No se puede escribir 9007199254740993 como literal numérico para
    // demostrarlo: el propio literal se redondea al parsearse. Lo que sí se
    // puede demostrar es que 2^53 y 2^53+1 colapsan en el MISMO double.
    expect(Number(size)).toBe(Number(2n ** 53n));
    expect(size).not.toBe(2n ** 53n);
    const c = parseCheckpoint(`example.com/log\n${size}\n${toBase64(new Uint8Array(32))}\n`);
    expect(c.size).toBe(size);
  });

  it("un índice de tlog-proof mayor que 2^53 no pierde precisión", () => {
    const index = 9007199254740993n;
    const p = parseProof(
      `c2sp.org/tlog-proof@v1\n${index}\n\nexample.com/log\n1\n${toBase64(new Uint8Array(32))}\n\n— x AAAAAAA=\n`,
    );
    expect(p.index).toBe(index);
  });

  it("readUint64BE llega hasta 2^64-1 sin redondear", () => {
    const b = new Uint8Array(8).fill(0xff);
    expect(readUint64BE(b, 0)).toBe(2n ** 64n - 1n);
    const b2 = new Uint8Array([0, 0x20, 0, 0, 0, 0, 0, 1]);
    expect(readUint64BE(b2, 0)).toBe(2n ** 53n + 1n);
  });
});

describe("no queda ningún operador de bits en el paquete", () => {
  it("es una propiedad comprobable con un grep", async () => {
    const { readFileSync, readdirSync } = await import("node:fs");
    const { dirname, join } = await import("node:path");
    const { fileURLToPath } = await import("node:url");
    const src = join(dirname(fileURLToPath(import.meta.url)), "..", "src");

    for (const f of readdirSync(src).filter((x) => x.endsWith(".ts"))) {
      const code = readFileSync(join(src, f), "utf8")
        // Se quitan los comentarios: hablan DE los operadores.
        .replace(/\/\*[\s\S]*?\*\//g, "")
        .replace(/^\s*\/\/.*$/gm, "");
      for (const op of [">>", "<<", ">>>"]) {
        expect(code, `${f} usa el operador ${op}`).not.toContain(op);
      }
      // `&` y `|` aparecen en tipos de TypeScript (uniones e intersecciones),
      // así que se busca el patrón aritmético concreto.
      expect(code, `${f} usa & como máscara de bits`).not.toMatch(/[a-zA-Z0-9_)\]]\s*&\s*\d/);
    }
  });
});
