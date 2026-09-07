// Notas firmadas de c2sp.org/signed-note.
//
// Una nota es un texto que termina en salto de línea, una línea en blanco, y una
// o más líneas de firma con la forma:
//
//     — <nombre> base64(key ID de 4 bytes || firma)
//
// El texto se separa de las firmas por la ÚLTIMA línea en blanco, porque el
// texto puede contener líneas vacías.

import { fromBase64, utf8 } from "./bytes.js";

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

/**
 * parseNote separa una nota firmada.
 *
 * Se corta por la ÚLTIMA línea en blanco y no por la primera: el cuerpo puede
 * llevar líneas vacías, y cortar por la primera partiría la nota en el sitio
 * equivocado ante un texto que las use.
 */
export function parseNote(msg: string): Note {
  const at = msg.lastIndexOf("\n\n");
  if (at < 0) throw new Error("la nota no separa cuerpo y firmas");

  const text = msg.slice(0, at + 1);
  const sigBlock = msg.slice(at + 2);

  const sigs: Sig[] = [];
  for (const line of sigBlock.split("\n")) {
    if (!line.startsWith(SIG_PREFIX)) continue;
    const sp = line.lastIndexOf(" ");
    if (sp < 0) continue;
    const name = line.slice(SIG_PREFIX.length, sp);
    let blob: Uint8Array;
    try {
      blob = fromBase64(line.slice(sp + 1));
    } catch {
      continue;
    }
    if (blob.length < 5) continue;
    const keyId =
      ((blob[0]! << 24) | (blob[1]! << 16) | (blob[2]! << 8) | blob[3]!) >>> 0;
    sigs.push({ name, keyId, signature: blob.slice(4), line });
  }
  if (sigs.length === 0) throw new Error("la nota no trae ninguna línea de firma");

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
  return ((h[0]! << 24) | (h[1]! << 16) | (h[2]! << 8) | h[3]!) >>> 0;
}

/** ALG_ED25519 es el byte de tipo de una firma Ed25519 de nota. */
export const ALG_ED25519 = 0x01;

/** ALG_COSIGNATURE_V1 es el de una tlog-cosignature@v1 con timestamp. */
export const ALG_COSIGNATURE_V1 = 0x04;
