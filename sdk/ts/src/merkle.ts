// Verificación de pruebas de inclusión de RFC 9162 §2.1.3.2.
//
// Los prefijos de dominio son los de RFC 6962: 0x00 para hojas y 0x01 para
// nodos internos. Sin ellos, un atacante podría presentar el hash de un nodo
// interno como si fuera una hoja.

import { concat, equal } from "./bytes.js";

/** leafHash calcula MTH de una hoja: SHA-256(0x00 || dato). */
export async function leafHash(
  sha256: (b: Uint8Array) => Promise<Uint8Array>,
  data: Uint8Array,
): Promise<Uint8Array> {
  return sha256(concat(new Uint8Array([0x00]), data));
}

/** nodeHash combina dos hijos: SHA-256(0x01 || izquierdo || derecho). */
export async function nodeHash(
  sha256: (b: Uint8Array) => Promise<Uint8Array>,
  left: Uint8Array,
  right: Uint8Array,
): Promise<Uint8Array> {
  return sha256(concat(new Uint8Array([0x01]), left, right));
}

/**
 * verifyInclusion comprueba que leafData está en el índice m de un árbol de
 * tamaño n con la raíz dada (RFC 9162 §2.1.3.2).
 *
 * leafData es el DATO de la hoja, no su hash: la función le aplica el prefijo
 * de dominio 0x00 por dentro. En Núcleo el dato de hoja es el hash del bloque,
 * SHA-256(JCS(header)), así que la hoja del árbol acaba siendo
 * SHA-256(0x00 || SHA-256(JCS(header))).
 *
 * El convenio es el mismo que el de ledger.VerifyInclusion en Go, y a
 * propósito: dos implementaciones que difieran en dónde se aplica el prefijo
 * producen raíces distintas para el mismo árbol, y el fallo aparece lejos de su
 * causa. Aquí se descubrió justamente así, con los vectores compartidos.
 */
export async function verifyInclusion(
  sha256: (b: Uint8Array) => Promise<Uint8Array>,
  leafData: Uint8Array,
  m: number,
  n: number,
  proof: Uint8Array[],
  root: Uint8Array,
): Promise<boolean> {
  if (m < 0 || n <= 0 || m >= n) return false;

  let fn = m;
  let sn = n - 1;
  let r = await leafHash(sha256, leafData);

  for (const p of proof) {
    // Sobrar nodos es tan inválido como faltar: una prueba con relleno
    // permitiría fabricar variantes de una prueba legítima.
    if (sn === 0) return false;
    if ((fn & 1) === 1 || fn === sn) {
      r = await nodeHash(sha256, p, r);
      while ((fn & 1) === 0 && fn !== 0) {
        fn >>= 1;
        sn >>= 1;
      }
    } else {
      r = await nodeHash(sha256, r, p);
    }
    fn >>= 1;
    sn >>= 1;
  }
  if (sn !== 0) return false;
  return equal(r, root);
}
