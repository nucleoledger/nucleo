// Utilidades de bytes. Sin dependencias: todo sale de la plataforma.

/** Convierte una cadena UTF-8 a bytes. */
export function utf8(s: string): Uint8Array {
  return new TextEncoder().encode(s);
}

/** Convierte bytes a cadena UTF-8. */
export function fromUtf8(b: Uint8Array): string {
  return new TextDecoder("utf-8", { fatal: false }).decode(b);
}

/** Decodifica hexadecimal en minúscula o mayúscula. */
export function fromHex(s: string): Uint8Array {
  if (s.length % 2 !== 0) throw new Error(`hex de longitud impar: ${s.length}`);
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) {
    const byte = Number.parseInt(s.slice(i * 2, i * 2 + 2), 16);
    if (Number.isNaN(byte)) throw new Error(`hex inválido en la posición ${i * 2}`);
    out[i] = byte;
  }
  return out;
}

/** Codifica bytes en hexadecimal minúsculo. */
export function toHex(b: Uint8Array): string {
  let out = "";
  for (const x of b) out += x.toString(16).padStart(2, "0");
  return out;
}

/** Decodifica base64 estándar (RFC 4648 §4). */
export function fromBase64(s: string): Uint8Array {
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

/** Codifica bytes en base64 estándar. */
export function toBase64(b: Uint8Array): string {
  let bin = "";
  for (const x of b) bin += String.fromCharCode(x);
  return btoa(bin);
}

/** Concatena varios tramos de bytes. */
export function concat(...parts: Uint8Array[]): Uint8Array {
  let n = 0;
  for (const p of parts) n += p.length;
  const out = new Uint8Array(n);
  let at = 0;
  for (const p of parts) {
    out.set(p, at);
    at += p.length;
  }
  return out;
}

/** Compara dos tramos byte a byte. */
export function equal(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

/**
 * Lee un u64 big-endian. Devuelve bigint porque un u64 no cabe en un number.
 *
 * Con multiplicación en vez de desplazamiento de bits. Sobre BigInt las dos
 * cosas son exactas, pero en este paquete no hay NI UN operador de bits, y esa
 * es una propiedad que se puede comprobar con un grep. Mezclar los seguros
 * (BigInt) con los que truncan a 32 bits (Number) obligaría a mirar el tipo de
 * cada operando para saber si una línea es correcta.
 */
export function readUint64BE(b: Uint8Array, at: number): bigint {
  let v = 0n;
  for (let i = 0; i < 8; i++) v = v * 256n + BigInt(b[at + i] ?? 0);
  return v;
}
