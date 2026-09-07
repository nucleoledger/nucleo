// Criptografía, toda de WebCrypto. No se implementa ni una primitiva a mano:
// una implementación propia de Ed25519 en TypeScript sería más código, más
// lento y con más superficie de error que la que ya trae la plataforma.

/** subtle devuelve SubtleCrypto en Node y en el navegador. */
function subtle(): SubtleCrypto {
  const c = globalThis.crypto;
  if (!c?.subtle) {
    throw new Error(
      "este entorno no expone WebCrypto (SubtleCrypto). Hace falta Node >= 18.4 " +
        "o un navegador moderno, y una página servida por https o desde localhost.",
    );
  }
  return c.subtle;
}

/** sha256 devuelve el digest de los bytes dados. */
export async function sha256(data: Uint8Array): Promise<Uint8Array> {
  const buf = await subtle().digest("SHA-256", data as BufferSource);
  return new Uint8Array(buf);
}

/**
 * verifyEd25519 comprueba una firma con una clave pública de 32 bytes.
 *
 * Devuelve false ante cualquier problema —clave mal formada, firma de tamaño
 * incorrecto, algoritmo no soportado— en vez de lanzar. Un verificador que
 * lanza excepciones ante una firma inválida obliga a quien lo usa a envolver
 * cada llamada en un try, y basta un olvido para que un recibo malo parezca
 * bueno.
 */
export async function verifyEd25519(
  publicKey: Uint8Array,
  signature: Uint8Array,
  message: Uint8Array,
): Promise<boolean> {
  if (publicKey.length !== 32 || signature.length !== 64) return false;
  try {
    const key = await subtle().importKey(
      "raw",
      publicKey as BufferSource,
      { name: "Ed25519" },
      false,
      ["verify"],
    );
    return await subtle().verify(
      { name: "Ed25519" },
      key,
      signature as BufferSource,
      message as BufferSource,
    );
  } catch {
    return false;
  }
}

/** ed25519Available dice si el entorno soporta Ed25519 en WebCrypto. */
export async function ed25519Available(): Promise<boolean> {
  try {
    await subtle().importKey("raw", new Uint8Array(32) as BufferSource, { name: "Ed25519" }, false, [
      "verify",
    ]);
    return true;
  } catch {
    return false;
  }
}
