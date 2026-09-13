// Notas firmadas de c2sp.org/signed-note.
//
// Una nota es un texto que termina en salto de línea, una línea en blanco, y una
// o más líneas de firma con la forma:
//
//     — <nombre> base64(key ID de 4 bytes || firma)
//
// El texto se separa de las firmas por la ÚLTIMA línea en blanco, porque el
// texto puede contener líneas vacías.

import { fromBase64, toBase64, utf8 } from "./bytes.js";

/** Sig es una línea de firma sin interpretar. */
export interface Sig {
  /** name es el nombre de la clave. */
  name: string;
  /** keyId son los 4 primeros bytes del blob, en big-endian. */
  keyId: number;
  /** signature es el resto del blob: la firma propiamente dicha. */
  signature: Uint8Array;
  /** line es la línea completa, tal cual venía. */
  line: string;
}

/** Note es una nota firmada ya separada en texto y firmas. */
export interface Note {
  /** text es el cuerpo firmado, CON su salto de línea final. */
  text: string;
  /** textBytes son los bytes exactos que se firmaron. */
  textBytes: Uint8Array;
  /** sigs son las líneas de firma, en el orden en que aparecen. */
  sigs: Sig[];
}

/** El carácter que abre una línea de firma: em-dash U+2014 seguido de espacio. */
const SIG_PREFIX = "— ";

/** MAX_SIGS es el máximo de líneas de firma de una nota (PROTOCOL.md §3.3). */
export const MAX_SIGS = 100;

/**
 * ESPACIOS son los puntos de código con la propiedad Unicode White_Space, que es lo
 * que `unicode.IsSpace` de Go —y por tanto x/mod— considera espacio. Enumerados a
 * mano y no con /\s/: la clase de JavaScript incluye U+FEFF, que para Go no es
 * espacio, y esa diferencia es exactamente el tipo de divergencia que el diferencial
 * existe para cazar.
 */
const ESPACIOS = new Set([
  0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x20, 0x85, 0xa0, 0x1680, 0x2000, 0x2001, 0x2002, 0x2003, 0x2004,
  0x2005, 0x2006, 0x2007, 0x2008, 0x2009, 0x200a, 0x2028, 0x2029, 0x202f, 0x205f, 0x3000,
]);

/** nombreValido es la regla 3 de PROTOCOL.md §3.3, la de isValidName de x/mod. */
function nombreValido(name: string): boolean {
  if (name === "" || name.includes("+")) return false;
  for (const ch of name) {
    if (ESPACIOS.has(ch.codePointAt(0)!)) return false;
  }
  return true;
}

/**
 * base64Canonico decodifica base64 estándar y exige que sea la codificación
 * canónica de lo que decodifica (regla 4). atob acepta relleno ausente y bits de
 * relleno distintos de cero: dos textos para los mismos bytes.
 */
function base64Canonico(s: string): Uint8Array {
  if (s === "" || s.length % 4 !== 0 || !/^[A-Za-z0-9+/]*={0,2}$/.test(s)) {
    throw new Error("base64 no estándar");
  }
  const b = fromBase64(s);
  if (toBase64(b) !== s) throw new Error("base64 no canónico");
  return b;
}

/**
 * parseNote separa una nota firmada con las reglas de PROTOCOL.md §3.3 (ADR-018 B).
 *
 * Se corta por la ÚLTIMA línea en blanco y no por la primera: el cuerpo puede
 * llevar líneas vacías, y cortar por la primera partiría la nota en el sitio
 * equivocado ante un texto que las use.
 *
 * Es estricta línea a línea. Antes saltaba en silencio lo que no entendía —una
 * línea sin prefijo, un base64 roto, un nombre con espacios— y Go, que delega en
 * x/mod, lo rechazaba: el segundo catálogo del diferencial, con mutaciones que el
 * emisor vuelve a firmar, encontró 38 recibos que TS aceptaba y Go no.
 */
export function parseNote(msg: string): Note {
  for (const ch of msg) {
    const cp = ch.codePointAt(0)!;
    if ((cp < 0x20 && cp !== 0x0a) || (cp >= 0xd800 && cp <= 0xdfff)) {
      throw new Error("la nota contiene caracteres de control o UTF-16 inválido");
    }
  }
  const at = msg.lastIndexOf("\n\n");
  if (at < 0) throw new Error("la nota no separa cuerpo y firmas");

  const text = msg.slice(0, at + 1);
  const sigBlock = msg.slice(at + 2);
  if (sigBlock === "" || !sigBlock.endsWith("\n")) {
    throw new Error("el bloque de firmas está vacío o no termina en salto de línea");
  }

  const sigs: Sig[] = [];
  for (const line of sigBlock.slice(0, -1).split("\n")) {
    if (!line.startsWith(SIG_PREFIX)) throw new Error("línea de firma sin el prefijo de signed-note");
    const rest = line.slice(SIG_PREFIX.length);
    const sp = rest.indexOf(" ");
    if (sp < 0) throw new Error("línea de firma sin nombre y firma");
    const name = rest.slice(0, sp);
    if (!nombreValido(name)) throw new Error(`nombre de firma inválido: ${JSON.stringify(name)}`);
    let blob: Uint8Array;
    try {
      blob = base64Canonico(rest.slice(sp + 1));
    } catch (e) {
      throw new Error(`firma de ${name}: ${e instanceof Error ? e.message : String(e)}`);
    }
    if (blob.length < 5) throw new Error(`firma de ${name}: menos de 5 bytes`);
    if (sigs.length === MAX_SIGS) throw new Error(`más de ${MAX_SIGS} líneas de firma`);
    sigs.push({ name, keyId: uint32BE(blob, 0), signature: blob.slice(4), line });
  }

  return { text, textBytes: utf8(text), sigs };
}

/**
 * keyId calcula el identificador de clave de signed-note:
 * los 4 primeros bytes, big-endian, de SHA-256(name || "\n" || alg || pubkey).
 */
export async function keyId(
  sha256: (b: Uint8Array) => Promise<Uint8Array>,
  name: string,
  alg: number,
  publicKey: Uint8Array,
): Promise<number> {
  const prefix = utf8(name + "\n");
  const buf = new Uint8Array(prefix.length + 1 + publicKey.length);
  buf.set(prefix, 0);
  buf[prefix.length] = alg;
  buf.set(publicKey, prefix.length + 1);
  const h = await sha256(buf);
  return uint32BE(h, 0);
}

/**
 * uint32BE lee un entero de 32 bits big-endian.
 *
 * Con aritmética y no con operadores de bits. Los de JavaScript trabajan sobre
 * enteros de 32 bits CON SIGNO, así que `b[0] << 24` con b[0] ≥ 128 produce un
 * número negativo que hay que corregir después con `>>> 0`. Funciona, pero es
 * un sitio donde equivocarse es fácil y el error no se nota. Aquí no hay ningún
 * operador de bits en todo el paquete, y así es comprobable de un vistazo.
 */
function uint32BE(b: Uint8Array, at: number): number {
  return b[at]! * 2 ** 24 + b[at + 1]! * 2 ** 16 + b[at + 2]! * 2 ** 8 + b[at + 3]!;
}

/** ALG_ED25519 es el byte de tipo de una firma Ed25519 de nota. */
export const ALG_ED25519 = 0x01;

/** ALG_COSIGNATURE_V1 es el de una tlog-cosignature@v1 con timestamp. */
export const ALG_COSIGNATURE_V1 = 0x04;
