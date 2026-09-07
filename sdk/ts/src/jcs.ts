// Canonicalización JCS (RFC 8785), lo mínimo que el verificador necesita.
//
// No se canonicaliza nada aquí: se COMPRUEBA que los bytes recibidos ya sean la
// forma canónica. Es la misma decisión que tomó el lado Go —los bytes exactos
// son lo firmado— y evita reimplementar la serialización de números de RFC 8785,
// que es la parte difícil y la que más se equivoca.

/**
 * jsonKeysAreSorted comprueba que las claves del objeto de primer nivel estén
 * en el orden que exige JCS: por sus unidades de código UTF-16.
 *
 * Los headers de bloque de Núcleo son objetos planos de campos escalares
 * (PROTOCOL.md §2 lo fija así justamente para que comprobar esto sea trivial en
 * cualquier lenguaje), de modo que no hace falta recorrer nada anidado.
 */
export function jsonKeysAreSorted(raw: string): boolean {
  let obj: unknown;
  try {
    obj = JSON.parse(raw);
  } catch {
    return false;
  }
  if (typeof obj !== "object" || obj === null || Array.isArray(obj)) return false;
  const keys = Object.keys(obj as Record<string, unknown>);
  for (let i = 1; i < keys.length; i++) {
    if (compareUTF16(keys[i - 1]!, keys[i]!) >= 0) return false;
  }
  return true;
}

/** compareUTF16 ordena por unidades de código, como manda RFC 8785. */
function compareUTF16(a: string, b: string): number {
  const n = Math.min(a.length, b.length);
  for (let i = 0; i < n; i++) {
    const d = a.charCodeAt(i) - b.charCodeAt(i);
    if (d !== 0) return d;
  }
  return a.length - b.length;
}
