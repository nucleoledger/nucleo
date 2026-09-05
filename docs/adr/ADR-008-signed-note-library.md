# ADR-008-signed-note-library

**Estado:** aceptada · **Fecha:** 2026-09-04 · **Fuentes:** ADR-001, docs/PROTOCOL.md §3, spike sobre golang.org/x/mod v0.40.0

## Contexto

C2SP `tlog-checkpoint` es una **nota firmada** (signed note): cuerpo de texto, línea
en blanco, y una o más líneas de firma. PROTOCOL.md §3 exige firma Ed25519 de tipo
`0x01` y anticipa cosignatures `tlog-cosignature@v1`. Hay dos caminos: usar
`golang.org/x/mod/sumdb/note` (la implementación de referencia del formato, la misma
que usa el checksum database de Go) o escribir el formato a mano.

## Decisión

**Usar `golang.org/x/mod/sumdb/note`.** Se añade `golang.org/x/mod` como dependencia
del módulo. Ninguna otra dependencia entra en esta fase: `filippo.io/torchwood` y
`transparency-dev` quedan solo evaluadas en papel.

## Justificación (los tres criterios acordados)

**1. Exactitud del wire format.** Verificado empíricamente contra el código de
v0.40.0, no de memoria:

- El cuerpo se firma tal cual, con su salto de línea final; `Sign` rechaza un texto
  que no termine en `\n`.
- Cada línea de firma es `— <name> <base64(keyHash‖sig)>\n`, donde `— ` es U+2014
  seguido de espacio (bytes `e2 80 94 20`), `keyHash` son 4 bytes big-endian y `sig`
  son los 64 bytes Ed25519.
- `Open` parte el mensaje por el **último** `\n\n`, así que un cuerpo con líneas en
  blanco sobrevive el round-trip intacto (comprobado).
- Ed25519 es determinista, luego los bytes de una nota firmada son reproducibles: los
  golden tests del Bloque 2 son estables.

Escribir esto a mano es reimplementar un formato con varias trampas (el em-dash, el
orden de firmas, el split por el último `\n\n`) sin ganar nada.

**2. Tamaño de dependencia.** Decisivo y mejor de lo esperado: `go list -deps
golang.org/x/mod/sumdb/note` devuelve **un único paquete** no estándar — el propio
`sumdb/note`. Importarlo no arrastra el resto de `x/mod`. El módulo ocupa 984 KB en
caché, del que solo se compila ese paquete. Es una dependencia de superficie mínima,
mantenida por el equipo de Go.

**3. Control del key ID Ed25519 (tipo 0x01).** El punto que decidía la evaluación, y
sale a favor:

- `keyHash = BigEndian.Uint32(SHA-256(name ‖ "\n" ‖ 0x01 ‖ pubkey))`, exactamente el
  key ID de C2SP. La constante `algEd25519 = 1` es el tipo `0x01` que exige
  PROTOCOL.md §3.
- `NewSigner` acepta una clave privada codificada construida a mano desde una
  **semilla Ed25519 fija**, así que la PoC puede usar llaves deterministas de test sin
  depender de `GenerateKey` ni de un lector aleatorio simulado. Comprobado.
- `NewEd25519VerifierKey(name, pub)` produce la clave de verificación desde una
  pública cruda, de modo que las llaves pueden nacer en `internal/keys` y no en la
  biblioteca.
- `Signer` es una **interfaz**. Esto es lo que hace viable el Bloque 3 sin bifurcar
  nada: `tlog-cosignature@v1` no firma el cuerpo de la nota sino un mensaje envuelto
  (`cosignature/v1\n`, `time <unix>\n`, cuerpo) y devuelve 72 bytes
  (`u64` big-endian ‖ firma de 64), y eso se implementa como un `Signer` propio que
  la biblioteca acepta sin más.
- `Open` con una llave desconocida no rompe: mientras al menos una firma verifique,
  las demás caen en `UnverifiedSigs` y se ignoran. Es justo la regla de notas firmadas
  que el Bloque 4.2 necesita. Si **ninguna** verifica, devuelve
  `note has no verifiable signatures`; la política del recibo debe exigir por tanto
  que la llave del log sea siempre conocida.

## Consecuencias

- `go.mod` gana `golang.org/x/mod v0.40.0`. Primera dependencia externa del proyecto.
- La PoC no implementa el formato de nota; sí implementa encima: el cuerpo concreto de
  `tlog-checkpoint`, el `Signer` de cosignature v1 y el recibo `tlog-proof`.
- Si algún día conviene eliminar la dependencia, la superficie a reimplementar es un
  solo paquete y está fijada por los golden tests del Bloque 2.
- Los vectores de `testdata/vectors/` siguen siendo la verdad: la biblioteca se valida
  contra ellos, no al revés.
