# ADR-034-verificar-mldsa44-del-log

**Estado:** ACEPTADA el 2026-10-18 por el dev (Sprint 27), sin código; propuesta el 2026-10-17 (Sprint 26); las preguntas abiertas, respondidas en «Decisiones del dev (2026-10-18)» · **Fecha:** 2026-10-17 · **Fuentes:** `docs/GARANTIAS.md` L14 y L23 (Sprint 25), ADR-007 y su addendum (la extensión `0xff` y el key ID), ADR-024 (el material ML-DSA prestado de los vectores), ADR-017 (la política, raíz de confianza), ADR-018 (su formato de cable), ADR-021 (el SDK de PHP), ADR-029 §F y ADR-030 §C (lo que se hace hoy con una clave comprometida), PROTOCOL 0.7-draft §3, §3.2, §3.3 y §6, `internal/checkpoint/mldsa.go`, `internal/proof/proof.go#esFirmaMLDSA`, `internal/identity/identity.go`, `sdk/ts/src/receipt.ts`, `sdk/php/src/Verifier.php`

## El problema

Todo checkpoint que firma el log lleva dos firmas: Ed25519 (`0x01`) y ML-DSA-44 (extensión
`0xff`, ADR-007). La segunda **no la comprueba nadie** (L23). Go, TypeScript, PHP y la página
reconocen la línea por dos cosas —va a nombre del log y mide lo que mide una firma ML-DSA-44— y
la cuentan en `logAdditionalSignatures`, sin verificarla. No pueden hacer otra cosa: la
política no fija la clave pública ML-DSA del log, y un key ID de 4 bytes no deja recuperar la
clave. Sin clave, no hay contra qué verificar.

Así que hoy una firma ML-DSA alterada, o de otra clave, da un recibo exactamente igual de
válido que una buena. Es el «**sin test**» de L23, y no falta el test: falta el diseño que haría
que fallara.

La política es la única raíz de confianza (ADR-017): todo lo que un verificador trae de fuera
va en ella. La clave ML-DSA del log es eso.

## Decisión

### A. En la política: `logMLDSAKey`

Miembro nuevo y **opcional** (PROTOCOL 0.8-draft §3.2):

| miembro | tipo | regla |
|---|---|---|
| `logMLDSAKey` | cadena | OPCIONAL; exactamente **2624** caracteres `[0-9a-f]`: los 1312 bytes de la clave pública ML-DSA-44 del log, codificada como dice FIPS 204 (`pkEncode`) y como la devuelve `crypto/mldsa` (`PublicKey.Bytes`) |

**Hexadecimal en minúsculas, como las otras claves.** Se pesaron tres codificaciones:

- **hex (elegida):** 2624 caracteres, la misma regla que `logKey` y una sola representación
  (ADR-018). La política no se teclea —la imprime `sync` (ADR-017 §c)— y cabe de sobra en los
  64 KiB.
- **base64:** un tercio menos, pero una segunda codificación dentro de la política y una regla
  más —base64 canónico— que los tres parsers tendrían que aplicar igual. No compensa 870
  caracteres.
- **solo una huella** (SHA-256 de la clave, 64 hex). Más corta y legible, pero el verificador
  necesita la clave entera para verificar, y el recibo no la trae. Meterla en el recibo
  cambiaría el formato del recibo y le sumaría 1312 bytes a cada uno. Descartado.

No hace falta regla de separación: la clave del log en ML-DSA cumple el mismo papel que
`logKey`, no es una autoridad aparte, y por longitud no puede coincidir con ninguna clave
Ed25519 de la política. Toda secuencia de 1312 bytes se decodifica como clave pública
ML-DSA-44, así que no hay un «bien formada» que comprobar además de la longitud.

**Al abrir el ledger** con una política que la trae, `logMLDSAKey` tiene que ser la clave que
deriva `LogPQSeed`, igual que `logKey` tiene que casar con la del ledger (ADR-017 §a). La
semilla vive cifrada en `vault_meta` (`internal/identity`), así que la comparación se hace en
las órdenes que abren la identidad —`seal`, `sync`, `receipt`, `erase`—; donde no se abre, la
CLI no dice que la comprobó. Y `sync`, que es quien imprime la política (ADR-017 §c), la
imprime con `logMLDSAKey` (pregunta abierta 9).

### B. La regla de verificación (PROTOCOL 0.8-draft §3.3)

Con una política que trae `logMLDSAKey` `P`:

1. El verificador calcula el key ID de `P` con la regla fijada en ADR-007:
   `SHA-256(origin ‖ "\n" ‖ 0xff ‖ "nucleoledger.com/sig/ml-dsa-44@v1" ‖ "\n" ‖ P)[:4]`.
2. Las líneas de firma a nombre del `origin` y con ese key ID son líneas de **una clave de la
   política**, y la regla de §3.3 ya dice qué pasa con ellas: **todas tienen que verificar**;
   si una no verifica, la nota es inválida, aunque haya otra de la misma clave que sí.
   Verificar es `ML-DSA.Verify(P, M, σ)` de FIPS 204, la variante pura, con **contexto
   vacío** —lo que firma `checkpoint.MLDSASigner` (`mldsa.Options{}`)—, donde `M` es el texto
   de la nota, el mismo que firma la Ed25519, y `σ` los 2420 bytes que siguen al key ID.
3. **Tiene que haber al menos una.** Sin ella, el recibo es inválido: *«la política fija la
   clave ML-DSA del log y el checkpoint no trae su firma»*.
4. La firma Ed25519 del log sigue siendo **obligatoria**. ML-DSA se suma; no sustituye.
5. Una línea a nombre del log con forma de ML-DSA pero **otro** key ID es de una clave que la
   política no conoce, y se ignora (c2sp.org/signed-note), como hoy.

Sin `logMLDSAKey`, nada cambia: la línea se reconoce como hoy y no decide nada.

### C. Semántica: si la política fija la clave, la firma es obligatoria

Recomendación: **una política con `logMLDSAKey` exige la firma, y válida.** Falta o es
inválida → el recibo es inválido. La alternativa —«si está, tiene que verificar; si falta,
da igual»— se descarta por tres razones:

- **La degradación.** La única persona contra la que protege esta firma es la que puede
  falsificar Ed25519, es decir, la de un computador cuántico. A esa persona le basta con
  **quitar la línea**: firma con Ed25519 lo que quiera y el recibo pasa. Una firma opcional
  contra el adversario para el que existe no protege de nada; fijar la clave sin exigirla
  sería la promesa vacía de la enmienda de ADR-030, escrita en la política.
- **La compatibilidad no lo impide.** Los recibos de hoy ya llevan la línea: `checkpoint.Log`
  la añade a todo checkpoint desde el addendum de ADR-007 (2026-09-06, antes de
  v0.1.0-alpha), y lo que se firmó bajo 0.1-draft no verifica bajo 0.2-draft de todos modos
  (PROTOCOL, nota de 0.2-draft). El ensayo de actualización lo comprueba con un recibo de
  v0.4.0-alpha (plan, abajo).
- **Es opcional donde tiene que serlo: en la política.** Quien tenga un recibo sin línea
  —un log que no la firmara, si existiera— lo verifica con una política sin `logMLDSAKey`, y
  obtiene exactamente lo de hoy. No se pierde nada que hoy se tenga.

### D. Qué hace cada verificador

El resultado de los tres gana un campo de **tres estados**, `logMLDSA` (Go:
`proof.Result.LogMLDSA`; TS y PHP: `logMLDSA`):

| valor | significa |
|---|---|
| `"verified"` | la política fija la clave y toda línea de esa clave verifica |
| `"present-unverified"` | hay una línea a nombre del log con forma de ML-DSA-44 y **nadie la verificó**: o la política no fija la clave, o este verificador no implementa ML-DSA-44 |
| `"absent"` | no hay ninguna línea así (sin `logMLDSAKey`; con ella, el recibo ya es inválido) |

El texto de la salida dice el motivo de `"present-unverified"`, que no es el mismo: *«firma
ML-DSA-44 del log: presente, NO verificada (la política no fija su clave)»* o *«… (este
verificador no implementa ML-DSA-44)»*. Lo que **no** cambia es el recibo: el texto legible
que firma el emisor no gana ninguna línea. Esto es salida del verificador, no formato.

`logAdditionalSignatures` se queda como está, porque la 0.4 lo publicó; cuenta líneas, y
`logMLDSA` dice qué se sabe de ellas.

**Go**: con `crypto/mldsa` de la stdlib, de verdad. `internal/checkpoint.NewMLDSAVerifier`
existe y hoy solo lo llaman tests; `internal/proof` lo usa con la clave de la política. Con
`logMLDSAKey`, el resultado de Go es `"verified"` o el recibo es inválido. Lo mismo hace la
autoverificación de `nucleo receipt`, que es la única verificación de recibos en Go que hoy
llega a un usuario (pregunta abierta 8).

**TypeScript y PHP, sin dependencias** —ni WebCrypto ni `ext-sodium` traen ML-DSA—, tres
opciones:

- **A. Verificar de verdad, con una implementación propia.** ML-DSA-44 *Verify*: `pkDecode` y
  `sigDecode`, `ExpandA`, la NTT módulo q = 8380417, `SampleInBall`, `UseHint`, `w1Encode`, y
  SHAKE128 y SHAKE256 —que no están ni en WebCrypto ni en `hash` de PHP, así que también
  Keccak—. Del orden de seiscientas a novecientas líneas por lenguaje, sin medir. Verificar no
  maneja secretos, así que no exige tiempo constante, y eso le quita el riesgo mayor. **Coste**:
  dos implementaciones criptográficas nuevas que mantener y revisar —lo que ADR-024 llamó «un
  oráculo con un bug de Dilithium»—, con su rendimiento en PHP por medir. **A cambio**: los
  tres verificadores dan el mismo veredicto, el diferencial queda entero y la página verifica
  ML-DSA en el navegador.
- **B. Aceptar la clave y decir que no la verificaron (recomendada para la 0.5).** Parsean
  `logMLDSAKey`, calculan su key ID, exigen la línea (sin ella, inválido, como Go) y que mida
  2420 bytes, y no la verifican: `"present-unverified"`, con el motivo en el texto. **Coste**:
  unas decenas de líneas por lenguaje, y **una divergencia con Go, declarada**: una línea con
  el key ID correcto y la firma mala es inválida en Go y válida, con `"present-unverified"`, en
  TS y PHP. El diferencial de notas re-firmadas la cataloga como esperada y comprueba lo único
  que importa: que siempre que TS o PHP aceptan lo que Go rechaza, dicen
  `"present-unverified"`. Lo que se pierde en TS y PHP es solo la protección post-cuántica, y
  lo dicen. Una variante, **B'**, usaría el ML-DSA de `node:crypto` donde lo haya (Node
  recientes con OpenSSL 3.5; la versión mínima está por confirmar) y B en el navegador: el
  veredicto del SDK pasaría a depender del runtime, y cada vector tendría que correr en los
  dos. No se propone para la 0.5.
- **C. Solo Go.** TS y PHP rechazan, con un error que lo dice, verificar bajo una política con
  `logMLDSAKey`. **Coste**: casi ninguno de código, y rompe ADR-017 §b —un solo fichero de
  política para la contraparte y para la página—: la contraparte necesitaría dos políticas, y
  la página no podría usar la que imprime `sync`. Y como Go no verifica hoy recibos ajenos
  desde la CLI, C deja a la contraparte sin ningún sitio donde verificar nada con esa política.

Con B, ningún verificador puede dar a entender que comprobó lo que no comprobó: `valid` dice
lo que dice hoy, y `logMLDSA` dice si la ML-DSA se verificó. A puede venir después sin tocar el
formato: el día que TS o PHP verifiquen, su `"present-unverified"` pasa a `"verified"` o a
inválido, y la divergencia declarada desaparece del diferencial.

### E. La rotación de la identidad del log

Hoy **no hay rotación**, en ninguna forma (PROTOCOL §6, enmienda del 2026-10-10). La semilla
ML-DSA es parte de la identidad (`identity.Identity.LogPQSeed`), se genera en `init` con las
otras dos y vive lo que vive el log. Una clave comprometida —la Ed25519 o la ML-DSA— significa
un log nuevo y retirar el viejo en sus testigos (ADR-029 §F, ADR-030 §C), y una política nueva
con las dos claves del log nuevo. Este ADR no cambia eso.

Cuando llegue la rotación de identidad (su propio ADR, PROTOCOL §6), tendrá que cumplir esto:

- **El bloque de rotación nombra las dos claves nuevas y lo firman las dos salientes.** Si
  bastara la Ed25519 saliente, la rotación sería la puerta trasera: el adversario cuántico
  falsificaría una rotación a su propia clave ML-DSA, y desde ahí todo.
- **Sin rotar solo una.** Un log cuya ML-DSA rota y su Ed25519 no —o al revés— es una
  identidad con dos historias; la rotación es de la identidad entera.
- **La migración al byte que C2SP asigne algún día** (ADR-007, «Rotación prevista») cambia el
  key ID, no la clave. Como la política fija la **clave** y no el key ID, esa migración es un
  cambio en cómo se calcula el key ID —protocolo, con su ADR—, no un cambio de política.

Añadir `logMLDSAKey` a la política de un log que ya existe no necesita nada: la semilla está
en `identity/v1` desde que el log se creó.

### F. Los vectores

Las firmas ML-DSA-44 de los vectores se calculan **fuera del código**, con una implementación
independiente de `crypto/mldsa`. En esta máquina no hay ninguna: OpenSSL es 3.0.2 y
`cryptography` de Python es 3.4.8, sin ML-DSA ninguno de los dos. ADR-024 descartó escribir
ML-DSA en Python e instalar una biblioteca sin aprobación. La propuesta (pregunta abierta 7):

- **OpenSSL ≥ 3.5**, que implementa ML-DSA (FIPS 204) de forma nativa, como **herramienta de
  desarrollo** para generar vectores —como `sha256sum` o `cosign`—, no como dependencia del
  producto, instalada con su checksum como las herramientas del ritual. Genera la clave desde
  una semilla, firma en modo determinista y verifica; las opciones exactas se fijan contra la
  versión que se instale.
- **Los vectores sigVer del ACVP del NIST para ML-DSA-44**, la fuente oficial, como segunda
  referencia para el núcleo del verificador —un subconjunto, con su procedencia y su
  checksum—.

Y, sobre eso:

- **`testdata/vectors/mldsa/`**: `(clave pública, mensaje, firma, veredicto)` generados con
  OpenSSL desde semillas fijas. Negativos: un bit cambiado en la firma —en `z`, en las pistas—;
  firma de otra clave; mensaje alterado en un byte; firma con **contexto no vacío**, que tiene
  que fallar con el contexto vacío (la separación de dominios de FIPS 204); longitud 2419 y
  2421.
- **La comprobación cruzada byte a byte**: con la misma semilla y el mismo mensaje, la firma
  determinista de OpenSSL y la de `MLDSASigner.Sign` (`SignDeterministic`) tienen que ser la
  misma. No es un golden calculado por el código: es una implementación contra otra.
- **Los recibos**: `generar.py` deja de prestar `material/mldsa.json` y le pide la firma a
  OpenSSL sobre el cuerpo de nota que él produce. ADR-024 se revisa como él mismo previó («si
  algún día entra una, este ADR se revisa y el material desaparece»). Recibos nuevos, con la
  política fijando la clave: `valido-mldsa-fijada-verificada`; `invalido-mldsa-fijada-ausente`
  (en los tres); `invalido-mldsa-fijada-alterada` (inválido en Go; con la opción B,
  `"present-unverified"` en TS y PHP, así que el vector declara el veredicto de cada uno);
  `invalido-mldsa-fijada-dos-lineas-una-mala`; `invalido-mldsa-solo-de-otra-clave` (la única
  línea ML-DSA es de una clave que la política no fija: equivale a ausente). El key ID lo sigue
  calculando `hashlib`, como fijó ADR-007.
- **`testdata/vectors/policy/`**: `logMLDSAKey` de 2623 y 2625 caracteres, en mayúsculas, no
  hexadecimal, `null`, número, con otra grafía del nombre, repetido.

## Lo que NO resuelve

- **Las cosignatures de los testigos siguen siendo Ed25519** (L14; ADR-011 desvía el SHOULD
  de `tlog-witness`). El **tiempo demostrable** sale de ellas (ADR-002), así que contra un
  adversario cuántico la fecha no tiene protección post-cuántica, ni el quórum.
- **La firma de cada bloque y la del emisor del recibo siguen siendo Ed25519.** Con la ML-DSA
  verificada, lo que un adversario cuántico ya no puede falsificar es **que el log firmó esa
  raíz**; y como la hoja fija el header bajo la raíz con SHA-256, que el registro está en el
  log del que la contraparte tiene la clave. Lo que sí puede falsificar: quién firmó el bloque
  (`signerKey`), cuándo (los testigos) y a quién se emitió el recibo (ADR-015).
- **Esto no convierte nada en «post-cuántico de punta a punta»**, y la documentación no puede
  decirlo. Ni con A, ni con los tres verificadores.
- **Con la opción B, TypeScript, PHP y la página no comprueban la ML-DSA.** Lo dicen en cada
  resultado; no la comprueban.
- **La política tiene que llegar por un medio autenticado** (ADR-017): quien la cambie puede
  poner su propia `logMLDSAKey`, como puede poner su propia `logKey`.
- **La clave vive en el servidor**, como la Ed25519 del log: quien controle el servidor firma
  checkpoints con las dos. Contra eso están los testigos y los recibos, no esta firma.
- **`crypto/mldsa` no está en el módulo FIPS 140-3 v1.0.0** (ADR-007): compilado con
  `GOFIPS140`, verificar falla igual que firmar.

## Alternativas descartadas

- **Seguir sin verificar y documentarlo.** Es L23. Una firma que nadie puede comprobar no es
  una garantía, y el CONCEPTO la presentaba como una.
- **Fijar el key ID en vez de la clave.** No deja verificar.
- **Meter la clave pública en el recibo.** Cambia el formato del recibo, suma 1312 bytes a
  cada uno, y una clave que llega con el artefacto no es una raíz de confianza: es la
  afirmación del recibo sobre sí mismo que ADR-017 quitó del firmante.
- **Firma opcional cuando la política fija la clave.** §C, la degradación.
- **Dejar de emitir la ML-DSA hasta poder verificarla en todas partes.** Los recibos que se
  emitan entretanto no se podrían verificar nunca con ella; emitida hoy, un verificador de
  mañana la comprueba sobre recibos de hoy.

## Consecuencias

- PROTOCOL 0.8-draft: §3.2 gana `logMLDSAKey`; §3.3, la regla de §B; §3, la línea del log en
  ML-DSA pasa de «SHOULD be added» a verificable con política.
- `internal/proof`: la verificación con `crypto/mldsa`, el campo `LogMLDSA`.
  `internal/policy` y sus gemelos leen el miembro.
- `sync` imprime `logMLDSAKey`; las órdenes que abren la identidad la cotejan.
- TS, PHP y la página: el campo de tres estados y su texto (con B).
- GARANTIAS: L23 se cierra para Go y queda, si se elige B, para TS, PHP y la página; L14 no
  cambia; G23 gana el test que hoy falta —una ML-DSA alterada **invalida** el recibo en Go
  bajo una política que fija la clave—.
- ADR-024 se revisa: el material prestado desaparece.

## Decisiones del dev (2026-10-18)

El dev acepta el ADR y cierra las preguntas abiertas 5 a 10 (las 1 a 4 son de ADR-033 y se
responden allí). Donde una decisión precisa o cambia el texto de arriba, manda esta sección.

**5. Opción B.** Go verifica la ML-DSA-44 con `crypto/mldsa`; TypeScript, PHP y la página
aceptan `logMLDSAKey`, calculan su key ID, exigen la línea de esa clave y que mida 2420
bytes, **no** la verifican y dan `logMLDSA: "present-unverified"` con el motivo *«este
verificador no implementa ML-DSA-44»* (§D). La divergencia con Go —una línea con el key ID
correcto y la firma mala es inválida en Go y válida, con `"present-unverified"`, en TS y
PHP— **se declara en el diferencial**: el catálogo de notas re-firmadas la lista como
esperada y comprueba que, cada vez que TS o PHP aceptan lo que Go rechaza, dicen
`"present-unverified"` y el único motivo de Go es la ML-DSA. Cualquier otra divergencia
sigue siendo un fallo. README y GARANTIAS lo dirán con estas palabras: **la comprobación
post-cuántica solo la hace el verificador de Go** (`nucleo verify-receipt` y la
autoverificación de `nucleo receipt`); L23 se cierra para Go y queda abierto, escrito, para
TS, PHP y la página. B' (el ML-DSA de `node:crypto`) y A quedan para después, sin cambiar el
formato.

**6. El nombre: `logMLDSAKey`**, en hexadecimal en minúsculas, **exactamente 2624
caracteres** (los 1312 bytes de `pkEncode`), como §A.

**7. OpenSSL ≥ 3.5, aprobado como herramienta de desarrollo**, solo para generar vectores:
no es dependencia del producto ni del binario. Se instala con una **versión fijada y su
sha256**, como las herramientas del ritual (cosign, shellcheck, goreleaser), y la versión y
la huella se anotan donde se anotan las de esas. Con ella, **los vectores sigVer del ACVP
del NIST para ML-DSA-44**, un subconjunto con su procedencia y su checksum, como segunda
referencia. ADR-024 se revisa en el sprint de los vectores y `material/mldsa.json`
desaparece. Lo que necesite el CI para el `generar.py --check` de esas firmas es
configuración de `.github/`, y la decide el dev en ese sprint.

**8. Entra en la 0.5 `nucleo verify-receipt`**, para que L23 se cierre también para
terceros y no solo para el emisor:

```
nucleo verify-receipt --receipt FICHERO --policy-file POLITICA [--json]
```

- Verifica un recibo **ajeno**, offline: no abre ningún ledger, no pide passphrase, no usa la
  red. Es `internal/receipt` (`Parse` + `Verify`) con la política del fichero, el mismo
  código que autoverifica `receipt`.
- Sale con 0 si el recibo vale, con 2 si no (`exitVerify`), con 1 si el uso está mal (sin
  `--policy-file`, fichero ilegible, política inválida).
- Dice lo que dicen los SDK —validez, motivos, tiempo declarado y demostrable, índice,
  testigos— y `logMLDSA`; con `--json`, un objeto documentado en `docs/CLI-JSON.md` con los
  nombres del resultado de los SDK.
- Con una política que fija `logMLDSAKey`, su resultado es `"verified"` o el recibo es
  inválido: es el sitio donde una contraparte comprueba la firma post-cuántica.
- Se añade al plan conjunto (implementación, ensayo) y a la lista de órdenes del README.

**9. `sync` imprime siempre `logMLDSAKey`** en la política, desde la 0.5. La saca de
`LogPQSeed`, así que es de las órdenes que abren la identidad (§A).

**10. La 0.5 sale con los dos ADR implementados.** Ni el SDK ni el binario 0.5 se publican
con un miembro aceptado en la gramática que nadie use.

## Plan conjunto con ADR-033 y ADR-034 (el mismo texto en los dos)

Los dos ADR tocan lo mismo —la gramática de la política, PROTOCOL §3.2— y se proponen a la vez
para que **la política suba una sola vez**. Una contraparte que actualiza su verificador lo
hace una vez para los dos miembros, no dos veces en dos meses.

### Una sola subida

- **PROTOCOL 0.8-draft**, con los dos miembros nuevos y opcionales de la política:
  `retiredErasureKeys` (ADR-033) y `logMLDSAKey` (ADR-034). §3.2 gana sus filas y sus reglas;
  §3.3, la regla de la línea ML-DSA cuando la política fija la clave; §5.1, las claves
  retiradas en «When an event is authorized» y en la receta del tercero. Ningún artefacto
  cambia de bytes: ni el bloque, ni la hoja, ni el checkpoint, ni el recibo.
- **Una sola versión del SDK, `0.5.0-alpha.0`**: `@nucleoledger/verify` y el SDK de PHP, los
  dos con los dos miembros. No hay una 0.5 con uno solo.

### La compatibilidad

| política | SDK 0.4 / binario v0.4.0-alpha | SDK 0.5 / binario v0.5 |
|---|---|---|
| sin los miembros nuevos (toda política de hoy) | vale, como hoy | vale, y significa lo mismo |
| con `retiredErasureKeys` o `logMLDSAKey` | **se rechaza**: miembro desconocido (§3.2) | vale |

Es exactamente lo que pasó con `erasureKey` en la 0.4 (PROTOCOL 0.7-draft): un verificador
viejo rechaza un miembro que no sabría usar, y eso es lo correcto. Rechazar es lo seguro: un
verificador 0.4 que aceptara `logMLDSAKey` sin saber qué es daría a entender que la comprobó.

Los recibos no cambian, así que todo recibo emitido por v0.4.0-alpha verifica bajo 0.8-draft
con una política vieja; con una política que fija `logMLDSAKey`, verifica si su checkpoint
trae la línea ML-DSA de esa clave, que es lo que firma `checkpoint.Log` en todo checkpoint
desde el addendum de ADR-007 (lo comprueba el ensayo, abajo).

### El orden de implementación

1. El dev acepta, enmienda o rechaza ADR-033 y ADR-034, y cierra las preguntas de abajo.
2. PROTOCOL 0.8-draft, con la nota de cabecera de cada subida (qué acepta de más, qué no
   cambia), por instrucción del dev.
3. **Los vectores, antes que el código** (regla criptográfica): `testdata/vectors/policy/`
   desde `generar.py`, escrito a mano a partir de las tablas; `testdata/vectors/erasure/`, la
   segunda clave y el escenario de rotación, con la biblioteca `cryptography` de Python;
   `testdata/vectors/mldsa/` y los recibos ML-DSA, con la implementación independiente que
   apruebe el dev (ADR-034, «Los vectores»). Cambiar `testdata/vectors/` exige este ADR.
4. **Go**: `internal/policy` (los dos miembros; `internal/estricto` no cambia, porque ninguno
   trae un tipo JSON nuevo), `internal/erasure` y `internal/reconcile` (las claves retiradas),
   `internal/proof` (la ML-DSA con `crypto/mldsa` y el campo de tres estados) y la CLI
   (`sync` imprime `logMLDSAKey` en la política y el fragmento de `retiredErasureKeys`; la
   apertura la coteja; `erasure-key authorize` rechaza una clave retirada; `reconcile
   --json` dice qué clave autorizó cada supresión y lista las regularizadas; y la orden
   nueva `nucleo verify-receipt`, que verifica un recibo ajeno con una política —ADR-034,
   decisión 8—).
5. **TypeScript y PHP**: el parser contra los mismos vectores, el campo de tres estados en el
   resultado y su texto; la página de `web/verify/` con él.
6. **El diferencial**: el catálogo de políticas muta los dos miembros nuevos; el de notas
   re-firmadas muta la línea ML-DSA, con la divergencia declarada si se elige la opción B de
   ADR-034.
7. **La documentación**: GARANTIAS (L14, L21, L23 y las garantías nuevas, con su test),
   `docs/OPERACION.md` §3 (cómo se rota la clave de supresión), `docs/CLI-JSON.md`, README.
8. `./scripts/compuerta.sh` en verde, un commit por paso.

### El orden de publicación

Como manda RELEASING: **primero el SDK** —tag `vsdk-0.5.0-alpha.0`, npm—, **después el
binario** `v0.5.0-alpha`. La razón es la de siempre y aquí pesa más: el `sync` del binario
nuevo imprime políticas con `logMLDSAKey`, y la contraparte que la reciba tiene que poder
leerla el día que el binario se publica, no después.

### El ensayo de actualización desde v0.4.0-alpha

`./scripts/ensayo-actualizacion.sh v0.4.0-alpha` con `NUCLEO_ENSAYO_SDK=0.4.0-alpha.0`, que
gana estos pasos:

1. Con el binario **publicado** de v0.4.0-alpha: ledger, testigo, una política con
   `erasureKey` A, un recibo, y una supresión autorizada con A. Todo esto ya lo hace hoy.
2. Con el HEAD, la misma política vieja: abre, sella, sincroniza y reconcilia igual.
3. Con el HEAD, la política nueva: `erasureKey` B, `retiredErasureKeys` `{A: índice del
   evento del paso 1}` y `logMLDSAKey` copiada de lo que imprime `sync`. La supresión del
   paso 1 **sigue contando** (es el cambio de L21); una supresión nueva con B cuenta;
   `erasure-key authorize` con las tarjetas de A y la política nueva se rechaza.
4. El recibo emitido por v0.4.0-alpha, con la política nueva: el verificador de Go
   —`nucleo verify-receipt` del HEAD— dice «ML-DSA verificada»; el SDK 0.5 del HEAD y el de npm lo aceptan y dicen lo que su opción
   de ADR-034 obliga a decir; el SDK 0.4 de npm **rechaza** la política nueva (miembro
   desconocido) y sigue aceptando la vieja.
5. `scripts/tercero-supresion.sh` con la clave retirada: el tercero elige la clave por el
   índice del evento y la comprueba con `openssl`.

Que una clave retirada no autorice nada después de su corte no entra en el ensayo: para
probarlo hay que sellar un evento sin pasar por `erase`, y eso es un test de Go
(ADR-033, «Los tests y los vectores»).

### Preguntas abiertas para el dev (respondidas el 2026-10-18)

Cada pregunta lleva debajo la respuesta del dev; el detalle está en la sección «Decisiones
del dev (2026-10-18)» del ADR al que pertenece.

1. **ADR-033, la forma.** ¿`retiredErasureKeys` como objeto `{clave: corte}` —recomendado: no
   añade arrays al lector estricto y una clave repetida ya es un error de la gramática— o
   como el array `[{key, until}]` de la idea de partida?
   **Respuesta:** objeto clave → corte.
2. **ADR-033, sin clave actual.** ¿Vale una política con `retiredErasureKeys` y sin
   `erasureKey` —«ya no suprimo, pero lo suprimido sigue contando»—? Se recomienda que sí.
   **Respuesta:** sí, vale.
3. **ADR-033, la herramienta.** ¿Un `nucleo erasure-key rotate --policy-file` que escriba la
   política nueva con el corte calculado desde el último checkpoint atestiguado, o se edita
   a mano con la receta de OPERACION? Se recomienda editarla a mano en la 0.5 y la orden
   cuando alguien rote de verdad.
   **Respuesta:** a mano en la 0.5, sin `rotate`; pero `nucleo sync --policy-file` imprime el
   fragmento exacto de `retiredErasureKeys`, con el corte calculado dentro de lo que ese
   `sync` acaba de atestiguar (ADR-033, decisión 3).
4. **ADR-033, volver a autorizar.** Si se pone el corte por debajo de un evento sospechoso,
   las supresiones legítimas de después dejan de contar. ¿Se permite sellar un segundo
   evento, autorizado con la clave nueva, para un bloque ya suprimido? El protocolo ya lo
   admite (§5.1 no prohíbe dos eventos para el mismo contenido); `erase` hoy no lo hace.
   **Respuesta:** sí. El original no desaparece: `reconcile` lo informa como «no autorizada,
   regularizada en el evento N» y sale con 0, con un aviso permanente en el texto y en el
   JSON (`regularized`). Corrección: `erase` ya sella ese segundo evento; lo nuevo es cómo lo
   cuenta `reconcile` (ADR-033, decisión 4, con la regla exacta y su test).
5. **ADR-034, TypeScript y PHP.** Opción A (verificar de verdad, implementación propia),
   B (aceptar la clave y decir «presente sin verificar»; recomendada para la 0.5) o C (solo
   Go).
   **Respuesta:** B. TS y PHP dan `"present-unverified"`; la divergencia con Go se declara
   en el diferencial; README y GARANTIAS dicen que la comprobación post-cuántica solo la
   hace el verificador de Go (ADR-034, decisión 5).
6. **ADR-034, el nombre y la codificación.** `logMLDSAKey` en hexadecimal en minúsculas, 2624
   caracteres, como el resto de las claves de la política. ¿O otro nombre?
   **Respuesta:** `logMLDSAKey`, hexadecimal en minúsculas, 2624 caracteres.
7. **ADR-034, la implementación independiente para los vectores.** ¿Se aprueba OpenSSL ≥ 3.5
   como herramienta de desarrollo —no como dependencia del producto—, instalada con su
   checksum como las del ritual, junto con los vectores sigVer del ACVP del NIST? Con eso
   ADR-024 se revisa y `material/mldsa.json` desaparece.
   **Respuesta:** aprobado, versión fijada con su checksum, solo para generar vectores, junto
   con los sigVer del ACVP (ADR-034, decisión 7).
8. **ADR-034, quién verifica fuera.** La única verificación de recibos en Go es la que la CLI
   hace de los suyos (TODO, «Verificar recibos ajenos desde la CLI»). Con la opción B, una
   contraparte no tiene dónde comprobar la ML-DSA. ¿Entra en la 0.5 una orden para verificar
   un recibo ajeno, o la 0.5 cierra L23 solo para el emisor?
   **Respuesta:** entra `nucleo verify-receipt` (ADR-034, decisión 8).
9. **ADR-034, el `sync`.** ¿La política que imprime `sync` lleva `logMLDSAKey` siempre? Se
   recomienda que sí desde v0.5: es la política completa del log, y una contraparte con el
   SDK 0.4 tiene que actualizar de todos modos para leer una política 0.8-draft.
   **Respuesta:** sí, siempre.
10. **Los dos.** ¿Se publica la 0.5 cuando estén los dos ADR implementados, o vale publicar el
    SDK 0.5 con los dos miembros aceptados en la gramática aunque la CLI implemente uno
    después? Se recomienda lo primero: una gramática que acepta un miembro que nadie usa es
    la promesa vacía que la enmienda de ADR-030 quitó.
    **Respuesta:** la 0.5 se publica solo con los dos ADR implementados.
