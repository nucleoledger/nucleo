# ADR-013-auditoria-pre-publica

**Estado:** aceptada · **Fecha:** 2026-09-07 · **Fuentes:** auditoría externa de GPT-5.5 sobre el árbol completo antes de publicar

Este ADR registra la última revisión antes de hacer público el repositorio, y de
paso deja escrito **quién ha auditado qué** a lo largo del proyecto. Es el
documento que alguien de fuera va a leer para decidir cuánto se fía.

## Por qué existe este documento

Un producto de seguridad no se juzga solo por su código, sino por el proceso que
lo produjo. Ese proceso aquí ha sido inusual —modelos auditándose entre sí— y
tiene virtudes y límites que conviene enunciar en vez de dejar que cada cual los
suponga.

**La virtud:** cada ronda la hizo un modelo distinto del que escribió el código,
con las especificaciones primarias delante en lugar de las afirmaciones de la
implementación. Eso encontró cosas reales, incluidas varias que un lector
distraído habría dado por buenas.

**El límite, dicho sin rodeos:** no es una auditoría profesional independiente.
Nadie ha ejecutado esto en producción, nadie le ha puesto un fuzzer serio
durante días, y ninguna de las revisiones tuvo el incentivo adversarial de quien
cobra por romperlo.

## Las tres rondas

| ronda | qué se auditó | quién escribió | quién auditó | hallazgos |
|---|---|---|---|---|
| **1 — Merkle y consistencia** | `ConsistencyProof` / `VerifyConsistency` contra RFC 9162 §2.1.4 | Claude (Opus) | Claude (Opus), sesión adversarial con el texto de la RFC | 6 fixes (A–F): vectores oficiales ausentes, validación de tamaño de raíz, error tipado propio, documentación del caso `fn == 0` |
| **2 — Sprint 2 (store y vault)** | SQLite append-only, KEK/DEK, SLIP-0039, AAD | Claude (Opus) | **GPT-5.5** | 1 ALTO (rollback local indetectable), 1 MEDIO (AAD ambiguo), 1 BAJO (contrato de `RestoreKEK`) |
| **3 — Testigo HTTP** | `c2sp.org/tlog-witness`: cliente, servidor, sincronización | Claude (Opus) | **GPT-5.5** | 2 ALTOS (cliente sin verificar cosignatures; replay de checkpoint antiguo), 2 MEDIOS (422/409 invertido; tiempo demostrable por forma), 1 BAJO |
| **4 — pre-pública** | árbol completo antes de publicar | Claude (Opus) | **GPT-5.5** | 1 ALTO, 2 MEDIOS, 3 BAJOS — este documento |

Además, el SPEC-CHECK del key ID de ML-DSA-44 y la corrección del byte `0x04` de
las cosignatures los resolvió el desarrollador humano contra las
especificaciones primarias de C2SP, no un modelo.

## Los seis hallazgos de esta ronda

### HIGH — los ganchos de prueba viajaban en el binario

`NUCLEO_TEST_SEED`, `NUCLEO_TEST_CLOCK` y `NUCLEO_TEST_PASSPHRASE` estaban
compilados en el ejecutable y se apagaban con una condición en tiempo de
ejecución. Definir la primera en un despliegue real habría hecho **predecible el
material aleatorio con el que se generan las claves de un vault**.

**Cerrado** moviéndolos tras `//go:build testhooks`. El binario publicado no
contiene ese código: goreleaser compila sin el tag y hay un test que lo
comprueba buscando una cadena exclusiva de `hooks_on.go` dentro del binario
recién construido.

Sin el tag, encontrar una de esas variables **aborta** con código 1. Es fallo
cerrado a propósito: quien define `NUCLEO_TEST_SEED` espera claves
deterministas, y un aviso por stderr que se pierde en un log lo dejaría con una
expectativa falsa sobre sus propias claves.

**Matiz sobre la verificación.** No se puede exigir a la vez que el binario
*rechace* una variable y que no contenga su *nombre*: para rechazarla hay que
conocerla. Las constantes con los nombres viven fuera del build tag. Lo ausente
—y lo que importa— es el código que las obedece.

### MEDIUM — el perfil Ecuador no cotejaba la clave contra el XML

La clave de acceso del SRI codifica ocho campos que el XML repite en sus propios
elementos. Solo se comprobaba el RUC, así que un comprobante podía declarar un
establecimiento, un secuencial o una fecha distintos de los que lleva su propia
clave y sellarse igual.

No es cosmético: el ledger indexa por la clave y una persona lee los elementos.
Un registro incoherente haría que los dos entendieran cosas distintas del mismo
comprobante, para siempre.

**Cerrado** cotejando los ocho, con rechazo que nombra el campo. Un elemento
ausente también rechaza: borrarlo sería una forma de saltarse el cotejo.

**El cotejo encontró su primer fallo en nuestros propios datos de prueba.** La
clave que usaban los tests, la CLI y el tutorial estaba inventada y no cuadraba
con el XML que la acompañaba. Llevaba dos sprints ahí y ningún test lo notaba,
porque ninguno miraba.

### MEDIUM — aritmética de 32 bits en el verificador de TypeScript

Los operadores de bits de JavaScript convierten sus operandos a enteros de **32
bits con signo**, y `number` es un double, exacto solo hasta 2⁵³. El bucle de la
prueba de inclusión usaba `&`, `>>` y `Number`: un árbol de más de dos mil
millones de hojas habría dado otro índice, en silencio y sin excepción.

**Cerrado** pasando índice, tamaño y bucle a BigInt de punta a punta. No queda un
solo operador de bits en el paquete, y un test lo comprueba con un grep sobre el
código.

**Un segundo truncamiento que no estaba en el hallazgo:** el índice del header se
tomaba de `JSON.parse`, cuyos números son doubles. Por encima de 2⁵³ se redondeaba
**al parsear**, y la comparación contra el índice de la prueba comparaba dos
valores ya corrompidos —que además coincidirían, dando por bueno un recibo que no
lo es—. Ahora se lee del texto canónico como BigInt.

### LOW — `verifyReceipt` podía lanzar

La función promete no lanzar nunca y la **política** no estaba cubierta: una
clave con un número impar de dígitos hexadecimales hacía que `fromHex` lanzara.
Un `try` olvidado convierte un recibo malo en una excepción no capturada: un
botón que no hace nada en el navegador, un 500 en vez de «recibo inválido» en un
servidor — y un 500 se investiga como una caída, no como un documento falsificado.

**Cerrado** validando la política explícitamente —hexadecimal *y* tamaño de 32
bytes— y con un `catch` de último recurso alrededor de toda la función.

### LOW — lecturas sin límite

Ningún fichero de entrada lo elige el programa. **Cerrado** con topes: 64 MiB
para el documento (`--max-payload` para subirlo), 1 MiB para passphrases,
tarjetas y claves, 10 MB para el archivo arrastrado al verificador web. La
comprobación es doble: `Stat` antes de leer, que da el tamaño real en el mensaje,
y un lector acotado, que cubre el caso en que `Stat` mienta.

### LOW — la clave del testigo se guardaba como un fichero cualquiera

Se leía y, si no estaba, se escribía. Entre esas dos operaciones cabe otro
proceso, y el segundo en escribir dejaría al testigo con una clave distinta de la
que el primero ya usó para cosignar.

**Cerrado** con `O_EXCL` y `0600`, sin leer-antes-de-escribir, y rechazando un
fichero existente que otros usuarios puedan leer. **En Windows la comprobación de
permisos no se hace**, a propósito: el control de acceso real vive en la ACL, que
`FileMode` no refleja, y una comprobación que puede decir «está bien» cuando no
lo está da una confianza que no se ha ganado. `docs/RELEASING.md` explica cómo
restringir la ACL a mano.

## Frentes verificados y limpios

Se revisaron explícitamente y **no** produjeron hallazgos:

- **XSS en el verificador web.** Todo lo que entra en el DOM pasa por `escapa()`,
  incluidas las razones de rechazo y el nombre del fichero arrastrado. La página
  no usa `innerHTML` con datos sin escapar ni `eval` en ninguna forma.
- **El «✔ falso».** Se buscó un camino por el que la página pudiera mostrar
  «Recibo válido» sin que la verificación hubiera pasado. No existe: el veredicto
  sale de `result.valid`, que solo es `true` si `reasons` está vacío, y ese
  cálculo vive en el bundle que los tests ejercitan con los tres vectores golden.
- **Secretos en el repositorio.** Barrido de rutas personales, correos, nombres
  de máquina, `.db`, `.key` y tarballs en el índice: nada. Ningún `session-*.md`
  trackeado.

## Lo que sigue sin auditar

- **No hay auditoría de seguridad profesional independiente.**
- **Nadie ha usado esto en producción.**
- No se ha hecho fuzzing prolongado más allá del de JCS.
- No se ha revisado el comportamiento bajo concurrencia real más allá de
  `-race` y de la transacción atómica del testigo.
- La resistencia a un adversario con acceso físico al disco está **documentada
  como límite**, no resuelta: es lo que los testigos existen para mitigar.

Ver [`SECURITY.md`](../../SECURITY.md) para el alcance de lo que se considera
vulnerabilidad y cómo reportarla.
