<!--
Este preámbulo lo añade el repositorio; el informe empieza donde lo dice y no se ha
tocado una coma. Si alguna vez hay que separar las dos cosas, el corte es la línea
"FIN DEL PREÁMBULO".
-->

# Nota de procedencia

**Versionado el 2026-10-11 desde la copia que el dev dejó en
`C:\Users\C-SERMIL\Documents\nucleo-revisiones\`**, sacada del clon limpio donde lo escribió
el modelo, `/tmp/opencode/nucleo-rev`. El texto de abajo es esa copia **sin modificar**:
SHA-256 `72d3dc7ef8be7c41001db5b8999639dbc16f858a852fe31ca09806852b7cf1a9`, el mismo que da
`sed '1,/^FIN DEL PREÁMBULO$/d' | tail -n +4` sobre este fichero.

| | |
|---|---|
| **Modelo** | `gpt-5.5` (OpenAI), vía OpenCode 1.18.32 |
| **Encargo** | revisar todo lo cambiado desde `v0.3.1-alpha`, con foco en ADR-032, sobre un clon limpio |
| **Fecha del informe** | 2026-10-11 |
| **Commit revisado** | `c52d906` (`c52d9068edf12b93b113001cac16e312c3284183`) |
| **Método** | ejecutó `go test ./...` y `-race`, `scripts/lint.sh`, la suite de TypeScript y la compuerta con `bash` (sin el bit de ejecución, H7); **no** la suite de PHP ni el diferencial —no había PHP—, y el propio informe lo dice |
| **Longitud** | 26.228 caracteres, 419 líneas |

FIN DEL PREÁMBULO

---

# Revisión externa técnica - v0.4.0-alpha / ADR-032

Proyecto: `github.com/nucleoledger/nucleo`.

Commit revisado: `c52d9068edf12b93b113001cac16e312c3284183`.

Clon: `/tmp/opencode/nucleo-rev`.

Fecha: 2026-10-11.

Alcance: todo lo cambiado desde `v0.3.1-alpha`, con foco en ADR-032, supresión, reconciliación, testigo de varios logs, `argShell`, regresión de `receipt --out`, SDKs y `scripts/ensayo-actualizacion.sh`. No modifiqué el repositorio salvo este informe.

## Metadatos pedidos

```text
$ git rev-parse HEAD
c52d9068edf12b93b113001cac16e312c3284183
```

```text
$ go version
go version go1.27.2 linux/amd64
```

```text
$ git log --oneline v0.3.1-alpha..HEAD
c52d906 build: scripts/ensayo-actualizacion.sh, el ensayo desde un release publicado
8dc84c8 test(hooks): sin go en el PATH se salta, salvo en el CI
82f3973 docs: la supresión en dos equipos, revisada contra el código
b5935e4 docs(release): el ensayo desde v0.3.1-alpha, repetido con el código final
eb5a5db chore(sdk): @nucleoledger/verify 0.4.0-alpha.0, la política con erasureKey
b0133a4 fix(cli): las órdenes impresas se entrecomillan según la plataforma
7e0a928 docs: ADR-032 aceptado por el dev
e637ff7 fix(lint): errorlint y staticcheck en la autorización de supresión
b7f051b docs(tools): por qué se descarta el aviso de KaTeX del validador Mermaid
4ac7811 docs(release): v0.4.0-alpha cuenta las dos rondas de la supresión
f8341f0 docs(garantias): la autoridad de supresión, G40-G46 y L20-L21
d21bc93 feat(erase): una supresión solo cuenta con la autorización de la clave de supresión
447c9c4 feat(policy): erasureKey, la clave de supresión, en los tres parsers
c4d56aa docs: ADR-032, la autoridad de supresión; PROTOCOL 0.7-draft
0e2e09c release: prepara v0.4.0-alpha (CHANGELOG, notas, actualización ensayada)
d855f53 docs: PROTOCOL 0.6-draft registra nucleo.erasure.v1; CONCEPTO sin Taskfile
c3922e1 fix(erase): suprimir exige dos tarjetas, y cada supresión abre una alarma
7737a01 docs: cierre del triaje del 2026-10-10 y CHANGELOG del Sprint 17
f2a072e build: scripts/compuerta.sh, la compuerta completa con una orden
669b846 ci: el job mermaid falla si un bloque de ARQUITECTURA no es Mermaid válido
811c63f docs: enmiendas a la vista de PROTOCOL §3/§6/§9 y ADR-005; keys en PLAN
dc15885 feat(erase): la supresión tiene comando, evento sellado y ADR-031
906421f docs: triaje de la revisión 2026-10-10 en ARQUITECTURA y GARANTIAS
5c7f821 fix(receipt): con --out, nunca queda en disco un recibo que no verificó
d4740d9 docs: la revisión del mapa (2026-10-10), versionada tal cual
2c592f0 test: el mapa no puede citar lo que no existe (mapa_test.go)
b1ff329 docs: GARANTIAS.md - cada afirmación con su ADR y su test, y los límites
84f3fdb docs: ARQUITECTURA.md, el mapa del sistema escrito desde el código
fa33b74 feat(witness): la clave de un log retirado comprueba su memoria (enmienda de ADR-030)
6895443 docs: Sprint 15 en TODO, PLAN, README y CHANGELOG
d0d11c8 test: la salida del testigo en el test se lee y se escribe con un mutex
75c62ce docs(concepto): enmienda a la vista - no hay nucleod, y el VRF no va en el ledger
f40329a feat(deploy): el kit del operador del testigo, validado en el CI
156d8e3 feat: el testigo mutuo, ensayado con dos procesos en local y en el CI
d794de4 feat(witness serve): --config, un proceso para varios logs (ADR-030)
2b4c04a feat(witness): la configuración de un testigo de varios logs (ADR-030 §A)
8984190 feat(witness): logs retirados y memoria aislada por log (ADR-030 §C y §D)
534a7ea refactor: el lector JSON estricto de la política pasa a internal/estricto
8af9298 docs(adr): ADR-030 - un testigo para varios logs, con altas, bajas y retirada
0cc638d docs(releasing): fijar el Go mantiene el binario reproducible, comprobado
ffe947d build: el Go fijado en go.mod (toolchain go1.27.2), en local y en todos los workflows
22bfae6 docs: v0.3.1-alpha publicada como pre-release
a89e855 docs(release): notas de v0.3.1-alpha completas - verificación y sha256
3c7e2be docs(releasing): v0.3.1-alpha se recompila byte a byte desde su tag
```

```text
$ git diff --stat v0.3.1-alpha..HEAD
133 files changed, 11846 insertions(+), 514 deletions(-)
```

## Lectura realizada

Leí `CLAUDE.md`, `docs/CONCEPTO-v1.2-es.md`, `docs/PROTOCOL.md` 0.7-draft, ADR-029 a ADR-032, `docs/ARQUITECTURA.md`, `docs/GARANTIAS.md`, `docs/CLI-JSON.md`, `CHANGELOG.md`, `docs/releases/v0.4.0-alpha.md` y las revisiones `docs/revision-externa-modelo-20261003.md` y `docs/revision-externa-modelo-20261010.md`.

No repito como hallazgos vigentes los defectos cerrados de 2026-10-03 ni el hallazgo alto de `receipt --out` de 2026-10-10: este commit lo corrige con `cmd/nucleo/seal.go#entregaRecibo` y `cmd/nucleo/entrega_test.go`.

## Ejecución

```text
$ go test ./...
ok   github.com/nucleoledger/nucleo/cmd/nucleo 2.643s
ok   github.com/nucleoledger/nucleo/internal/store 7.977s
ok   github.com/nucleoledger/nucleo/internal/vault 5.326s
ok   github.com/nucleoledger/nucleo/internal/witness 1.079s
ok   github.com/nucleoledger/nucleo/profiles/ecuador 0.009s
```

```text
$ go test -race ./...
ok   github.com/nucleoledger/nucleo/cmd/nucleo 5.222s
ok   github.com/nucleoledger/nucleo/internal/receipt 33.009s
ok   github.com/nucleoledger/nucleo/internal/store 19.300s
ok   github.com/nucleoledger/nucleo/internal/vault 24.001s
ok   github.com/nucleoledger/nucleo/profiles/ecuador 1.079s
```

```text
$ ./scripts/lint.sh
lint.sh: golangci-lint v2.14.0 con go1.27.2 - lo que fija el job lint de ci.yml
== golangci-lint run ./...
0 issues.
== golangci-lint run --build-tags testhooks ./...
0 issues.
lint.sh: ✔ las dos pasadas, sin issues
```

```text
$ cd sdk/ts && npm ci && npm test
Test Files  8 passed (8)
Tests       209 passed (209)
found 0 vulnerabilities
```

```text
$ php sdk/php/test/run.php
/bin/bash: line 1: php: command not found
```

PHP no está instalado en este entorno. No pude ejecutar la suite PHP ni el diferencial de tres verificadores localmente; sí revisé el código PHP y la compuerta confirmó que falla cerrado si falta PHP.

```text
$ ./scripts/compuerta.sh
/bin/bash: line 1: ./scripts/compuerta.sh: Permission denied
```

El fichero no tiene permiso ejecutable en este clon/FS. Lo ejecuté con `bash` para comprobar su contenido:

```text
$ bash scripts/compuerta.sh
━━ gofmt
   ✔ 0 s
━━ go vet
   ✔ 1 s
━━ go vet -tags testhooks
   ✔ 1 s
━━ lint (scripts/lint.sh)
   ✔ 5 s
━━ go test -race
   ✔ 34 s
━━ go test -race -tags testhooks
   ✔ 183 s
━━ SDK de TypeScript
   ✔ 3 s
━━ vectores de recibo (generar.py --check)
   ✔ 0 s
━━ PHP con ext-sodium
   ✘ FALLÓ (0 s). Las últimas líneas:
   │ no hay PHP: ni $NUCLEO_PHP ni `php` en el PATH.
━━ suite de PHP, con el binario
   ✘ FALLÓ (0 s). Las últimas líneas:
   │ no hay PHP: ni $NUCLEO_PHP ni `php` en el PATH.
━━ diferencial de los TRES verificadores
   ✘ FALLÓ (0 s). Las últimas líneas:
   │ no hay PHP: ni $NUCLEO_PHP ni `php` en el PATH.
━━ criterio de éxito (demo-criterio-exito.sh)
   ✔ 3 s
━━ testigo mutuo (ensayo-testigo-mutuo.sh)
   ✔ 4 s
━━ kit del testigo (valida-kit-testigo.sh)
   ✔ 1 s
━━ ejemplo erp-node
   ✔ 11 s
━━ Mermaid de ARQUITECTURA
   ✔ 11 s
━━ sin testigos huérfanos
   ✔ 1 s

✘ COMPUERTA EN ROJO (258 s): 3 pasos fallaron
   · PHP con ext-sodium
   · suite de PHP, con el binario
   · diferencial de los TRES verificadores
```

Pruebas puntuales ejecutadas:

```text
$ go test -tags testhooks ./cmd/nucleo -run 'Test(EraseDiceQueOrdenPedirYEsaOrdenFunciona|LaSupresionDejaLaCadenaYLosRecibos|LaClaveDelServidorNoSuprime|CadaSupresionAbreUnaAlarma|ErasureKeyInitNoAbreNingunLedger|AuthorizeRechazaLasTarjetasDelVault|UnTerceroCompruebaLaAutorizacionConLosRecibos|UnReciboQueNoVerificaNoSeEscribe|UnReciboQueVerificaSeEscribeEntero|ArgShellSobreviveALaShellDeCadaPlataforma|PolicyFileEsFormatoDeCable|ErasureKeyNoPuedeSerLaDelFirmante)' -v
--- PASS: TestLaClaveDelServidorNoSuprime (1.05s)
--- PASS: TestCadaSupresionAbreUnaAlarma (0.82s)
--- PASS: TestUnTerceroCompruebaLaAutorizacionConLosRecibos (0.98s)
--- PASS: TestEraseDiceQueOrdenPedirYEsaOrdenFunciona (0.53s)
--- PASS: TestAuthorizeRechazaLasTarjetasDelVault (0.69s)
--- PASS: TestErasureKeyInitNoAbreNingunLedger (0.11s)
--- PASS: TestArgShellSobreviveALaShellDeCadaPlataforma (0.00s)
--- PASS: TestUnReciboQueNoVerificaNoSeEscribe (0.00s)
--- PASS: TestUnReciboQueVerificaSeEscribeEntero (0.00s)
--- PASS: TestLaSupresionDejaLaCadenaYLosRecibos (1.17s)
--- PASS: TestPolicyFileEsFormatoDeCable (0.55s)
--- PASS: TestErasureKeyNoPuedeSerLaDelFirmante (0.50s)
PASS
```

```text
$ go test ./internal/erasure ./internal/reconcile ./internal/witness -run 'Test(LaAutorizacionCoincideConElVector|CasosDeLaAutorizacion|SinClaveNadaEstaAutorizado|UnRegistroSuprimidoNoEsUnFaltante|SinEventoUnRegistroBorradoEsUnFaltante|SupresionSinAutorizacionNoCuenta|AutorizacionAjenaNoCuenta|VariosLogsNoSePisanLaMemoria|LogRetiradoNoSeCosignaYConservaSuMemoria|RetirarConOtraClaveSeRechaza)' -v
--- PASS: TestLaAutorizacionCoincideConElVector (0.00s)
--- PASS: TestCasosDeLaAutorizacion (0.00s)
--- PASS: TestSinClaveNadaEstaAutorizado (0.00s)
--- PASS: TestSupresionSinAutorizacionNoCuenta (0.22s)
--- PASS: TestUnRegistroSuprimidoNoEsUnFaltante (0.11s)
--- PASS: TestAutorizacionAjenaNoCuenta (0.43s)
--- PASS: TestSinEventoUnRegistroBorradoEsUnFaltante (0.07s)
--- PASS: TestVariosLogsNoSePisanLaMemoria (0.08s)
--- PASS: TestLogRetiradoNoSeCosignaYConservaSuMemoria (0.07s)
--- PASS: TestRetirarConOtraClaveSeRechaza (0.04s)
PASS
```

Empaquetado TS:

```text
$ cd sdk/ts && npm pack --dry-run
npm notice name: @nucleoledger/verify
npm notice version: 0.4.0-alpha.0
npm notice Tarball Contents
npm notice 34.3kB LICENSE
npm notice 11.2kB README.md
npm notice 1.4kB dist/bytes.d.ts
...
npm notice 22.7kB dist/receipt.js
npm notice 1.6kB package.json
npm notice total files: 25
```

No aparecen `src/`, tests, lockfile, configuración ni vectores en el paquete.

Flujo CLI ejecutado para la pregunta abierta de política de otro `origin`:

```text
$ nucleo --json reconcile --source live.jsonl --policy-file policy-wrong-origin.json
EXIT: 2
STDOUT:
{
  "error": "store: verificación de integridad fallida: log: store: el origin de la política no es el del ledger: el ledger es \"nucleoledger.com/pruebas\" y la política es de \"otro.example/log\"",
  "error_class": "integrity",
  "exit_code": 2,
  "ok": false
}
```

El flujo usa un binario compilado con `-tags testhooks` solo para fijar semilla/passphrase/reloj; el código de salida real del binario es `2`.

## Hallazgos

### H1 - MEDIA - CONFIRMADO - `reconcile --json` puede emitir dos objetos JSON si falla `VerifyFull`

Fichero: `cmd/nucleo/reconcile.go:70-108`.

Evidencia: `cmdReconcile` imprime siempre el informe JSON en `cmd/nucleo/reconcile.go:70-87`. Después, si `rep.FullVerify != nil && !rep.FullVerify.OK`, devuelve `verifyErr` en `cmd/nucleo/reconcile.go:106-108`. Como ese error no lleva `reported: true`, `main.run` imprimirá además el objeto JSON de error. Esto contradice `docs/CLI-JSON.md:3-4`, que promete exactamente un objeto JSON en stdout, y `docs/CLI-JSON.md:371-374`, que ya modela `full_verify` dentro del informe.

Cómo reproducirlo: crear un ledger que abra por atestación pero falle en `VerifyFull` y ejecutar `nucleo --json reconcile --source live.jsonl --policy-file politica.json`. El escenario está modelado en `internal/store/attested_test.go#TestVerifyFullCazaUnaFirmaInvalidaYaATESTIGUADA`, pero falta un test CLI de `reconcile --json`.

Arreglo propuesto: en `cmd/nucleo/reconcile.go:106-108`, devolver `&exitError{code: exitVerify, err: ..., reported: true}` igual que en el caso de hallazgos. Test: un test CLI JSON que corrompa una firma cubierta por el atajo atestiguado, ejecute `reconcile --json`, compruebe salida única, `ok:false`, `full_verify.ok:false`, `findings:[]` y ausencia de `error/exit_code/error_class` de segundo objeto.

### H2 - MEDIA - CONFIRMADO - `argShell` no es pegable tal cual en PowerShell para `$` y backtick

Fichero: `cmd/nucleo/comillas.go:40-73`.

Evidencia: `argWindows` aplica reglas de `CommandLineToArgvW`: comillas dobles, backslashes duplicados antes de comillas, y `\"` para comillas internas. Eso reconstruye argv en un proceso Windows, pero no neutraliza expansión de PowerShell dentro de comillas dobles.

Ejemplos que cambian de valor en PowerShell:

```text
entrada:  C:\$HOME\p.json
impreso:  "C:\$HOME\p.json"
efecto:   $HOME se expande

entrada:  C:\foo`nbar\p.json
impreso:  "C:\foo`nbar\p.json"
efecto:   `n se convierte en salto de línea
```

`cmd/nucleo/comillas_test.go#TestArgShellSobreviveALaShellDeCadaPlataforma` no cubre PowerShell real; usa un parser sintético de argv Windows.

Cómo reproducirlo: pegar una orden que contenga una ruta con `$HOME` o `` `n `` en PowerShell. El argumento recibido por el proceso no será el literal impreso.

Arreglo propuesto: distinguir shell de Windows o imprimir forma compatible con PowerShell cuando esa sea la consola documentada. Para PowerShell, usar comillas simples y duplicar `'`, o `--%` si se controla la posición. Test: prueba de quoting PowerShell con `$`, backtick y comillas simples; si no se puede invocar PowerShell en CI Linux, incluir parser/fixture explícito y una prueba real en Windows.

### H3 - MEDIA - CONFIRMADO - `argShell` no es pegable tal cual en `cmd.exe` para `%VAR%`

Fichero: `cmd/nucleo/comillas.go:40-73`.

Evidencia: `argWindows` entrecomilla `%`, pero `cmd.exe` expande `%VAR%` incluso dentro de comillas dobles.

Ejemplo:

```text
entrada:  C:\%USERNAME%\p.json
impreso:  "C:\%USERNAME%\p.json"
efecto:   cmd.exe expande %USERNAME%
```

Con delayed expansion habilitado, también falla `!VAR!`:

```text
entrada:  C:\!USERNAME!\p.json
impreso:  "C:\!USERNAME!\p.json"
efecto:   cmd /v:on expande !USERNAME!
```

Los tests incluyen caracteres `%` y `!` como caracteres sueltos, pero no modelan expansión de `cmd.exe`.

Cómo reproducirlo: pegar en `cmd.exe` una orden con una ruta que contenga `%USERNAME%`.

Arreglo propuesto: para recetas destinadas a `cmd.exe`, escapar `%` como `%%` en contexto batch y documentar/emitir una forma para consola interactiva que evite expansión, o no prometer compatibilidad con `cmd.exe` para esos caracteres. Test: caso explícito `%USERNAME%` y, si se decide soportarlo, ejecución real en Windows.

### H4 - MEDIA - CONFIRMADO - `scripts/ensayo-actualizacion.sh` ejecuta el binario descargado aunque no haya verificado firma si falta `cosign`

Fichero: `scripts/ensayo-actualizacion.sh:111-132`.

Evidencia: el script valida el hash del tarball contra `checksums.txt` en `scripts/ensayo-actualizacion.sh:100-109`. Si `cosign` existe, verifica la firma de `checksums.txt` en `scripts/ensayo-actualizacion.sh:111-128`. Si `cosign` no existe, solo avisa en `scripts/ensayo-actualizacion.sh:129-130` y continúa a `tar -xzf` y a ejecutar el binario descargado. La cabecera dice que sale con 2 si “el binario descargado no es el que se firmó” y que en ese caso no se ejecuta nada, pero sin `cosign` no puede comprobar que `checksums.txt` sea el firmado.

Cómo reproducirlo: ejecutar el script en un entorno sin `cosign`. El flujo seguirá tras imprimir “cosign no está”.

Arreglo propuesto: hacer `cosign` obligatorio por defecto para este ensayo, o exigir una variable explícita tipo `NUCLEO_ENSAYO_SIN_COSIGN=1` que cambie el texto y el riesgo. Test: prueba shell o análisis estático que confirme que sin `cosign` se sale antes de extraer/ejecutar.

### H5 - BAJA - CONFIRMADO - Los vectores de erasure solo se consumen en Go, no en TS/PHP

Ficheros: `internal/erasure/autorizacion_test.go`, `testdata/vectors/erasure/`, `sdk/ts/`, `sdk/php/`.

Evidencia: Go usa `testdata/vectors/erasure/autorizacion.json` y `testdata/vectors/erasure/casos.json` en `internal/erasure/autorizacion_test.go#TestLaAutorizacionCoincideConElVector` y `#TestCasosDeLaAutorizacion`. No hay implementación TS/PHP de comprobación de autorización de supresión ni pruebas TS/PHP que lean `testdata/vectors/erasure`. ADR-032 lo acota: los SDK no añaden esa comprobación hasta que un integrador la pida. Por tanto no es bug contra el producto actual, pero sí contra la pregunta “que los vectores de erasure se usen de verdad en las TRES implementaciones”.

Cómo reproducirlo: buscar `vectors/erasure` en `sdk/ts` y `sdk/php`; no hay consumidores.

Arreglo propuesto: si se quiere reclamar cobertura de tres implementaciones para la autorización, añadir una función de verificación de erasure en TS/PHP y tests contra `testdata/vectors/erasure`. Si no, `GARANTIAS.md` debe mantenerlo como Go/CLI solamente.

### H6 - BAJA - CONFIRMADO - Comentario obsoleto sobre `payload_cid` de eventos de supresión

Fichero: `internal/erasure/erasure.go:10-14`.

Evidencia: el comentario de paquete todavía describe el evento de supresión como sellado con `payload_cid "none://"`, que era ADR-031/0.6-draft. El código de ADR-032 usa `payload_cid` con `nucleo-erasure-auth@v1:<through>:<firma>` y cumple PROTOCOL 0.7-draft.

Cómo reproducirlo: leer `internal/erasure/erasure.go` y compararlo con `internal/erasure/autorizacion.go:26-87` y `docs/PROTOCOL.md:388-392`.

Arreglo propuesto: actualizar el comentario. Test no necesario; `mapa_test.go` no valida comentarios.

### H7 - INFO - CONFIRMADO - `compuerta.sh` no es ejecutable en el clon, aunque funciona con `bash`

Fichero: `scripts/compuerta.sh`.

Evidencia: `./scripts/compuerta.sh` devolvió `Permission denied`; `bash scripts/compuerta.sh` ejecutó la compuerta y solo falló por PHP ausente. Puede ser efecto del modo de fichero publicado o del FS del clon, pero contradice las instrucciones que lo invocan como `./scripts/compuerta.sh`.

Cómo reproducirlo: `./scripts/compuerta.sh` en este clon.

Arreglo propuesto: asegurar bit ejecutable en Git para `scripts/compuerta.sh`, o documentar `bash scripts/compuerta.sh` si se prefiere no depender del bit.

## Pregunta abierta resuelta: política de otro origin

Código: `cmd/nucleo/reconcile.go:38-44` abre el ledger con política antes de emitir el informe; `internal/store/integrity.go` devuelve error de integridad si `policy.origin` no coincide con el origin del ledger; `cmd/nucleo/env.go` lo mapea a `exitVerify`.

Ejecución: con un ledger de `nucleoledger.com/pruebas` y una política idéntica salvo `origin:"otro.example/log"`, `nucleo --json reconcile --source live.jsonl --policy-file policy-wrong-origin.json` devuelve código `2` y este JSON:

```json
{
  "error": "store: verificación de integridad fallida: log: store: el origin de la política no es el del ledger: el ledger es \"nucleoledger.com/pruebas\" y la política es de \"otro.example/log\"",
  "error_class": "integrity",
  "exit_code": 2,
  "ok": false
}
```

No es un informe `reconcile`: no hay `findings`, `erased`, `full_verify`, `attestation` ni `freshness`, porque el ledger no llega a abrirse. Hay test relacionado para `status` (`cmd/nucleo/policy_test.go#TestPolicyFileEsFormatoDeCable`, subtest `origin_de_otro_log`), pero no encontré un test específico para `reconcile --json` con política de otro origin.

## Tabla G38-G46 y L18-L21

| garantía/límite | test citado | ¿lo respalda? | nota |
|---|---|---|---|
| G38 | `cmd/nucleo/erase_test.go#TestLaSupresionDejaLaCadenaYLosRecibos`; `internal/store/supresion_test.go#TestLaSupresionVaConSuEventoONoVa` | Sí | Cubre borrado de blob/compromisos, evento, cadena y recibos. |
| G39 | `internal/store/supresion_test.go#TestLaSupresionNoDejaElContenidoEnElDisco` | Sí | Busca bytes en fichero principal y WAL; cubre `secure_delete` y purge normal. No fuerza WAL busy. |
| G40 | `internal/reconcile/supresion_test.go#TestUnRegistroSuprimidoNoEsUnFaltante`; `#TestSinEventoUnRegistroBorradoEsUnFaltante`; `#TestSupresionSinAutorizacionNoCuenta`; `#TestAutorizacionAjenaNoCuenta` | Sí | Cubre sin evento, autorización válida, sin clave, otra clave, otro hash, otro origin, `through == event.index`, clave tenant y copia posterior. |
| G41 | `cmd/nucleo/ataque_supresion_test.go#TestElFicheroDeLaPassphraseNoSuprime`; `#TestLaClaveDelServidorNoSuprime`; `cmd/nucleo/erase_test.go#TestSealNoAceptaTiposReservados`; demo ejemplo | Sí | Fija que passphrase/clave tenant no bastan y que `seal` rechaza `nucleo.*`. La demo no se leyó como prueba primaria, pero la compuerta la ejecutó. |
| G42 | `cmd/nucleo/ataque_supresion_test.go#TestCadaSupresionAbreUnaAlarma`; `sdk/php/test/contrato.php`; `cmd/nucleo/clijson_vectors_test.go#TestVectoresCLIJSON`; demo ejemplo | Sí en Go/contrato; PHP no ejecutado aquí | Código muestra hook `onErasure` en `sdk/php/src/Sealer.php:405-434`; la ejecución PHP queda pendiente por falta de PHP. Falta test explícito de que `alert ack` no cambia `reconcile`, aunque el código lo separa. |
| G43 | `cmd/nucleo/autorizacion_supresion_test.go#TestErasureKeyInitNoAbreNingunLedger`; `#TestAuthorizeRechazaLasTarjetasDelVault`; `cmd/nucleo/policy_test.go#TestErasureKeyNoPuedeSerLaDelFirmante`; vectores policy Go/TS/PHP | Sí, con matiz | Prueba que no crea ledger y que rechaza tarjetas del vault. Que no escriba ningún otro fichero se ve por lectura, no por snapshot exhaustivo. Vectores policy están en las tres implementaciones; erasure vectors no. |
| G44 | `internal/erasure/autorizacion_test.go#TestLaAutorizacionCoincideConElVector`; `#TestCasosDeLaAutorizacion`; `cmd/nucleo/autorizacion_supresion_test.go#TestLaAutorizacionNoCubreUnaCopiaPosterior` | Sí | Cubre texto exacto, digest, firma, parsing estricto y bordes de `through`. |
| G45 | `cmd/nucleo/autorizacion_supresion_test.go#TestUnTerceroCompruebaLaAutorizacionConLosRecibos` | Sí parcial | El test usa biblioteca estándar de Go, no `internal/erasure`, lo cual evita circularidad razonable. La receta exacta con `openssl` está documentada, pero no automatizada. |
| G46 | `cmd/nucleo/comillas_test.go#TestArgShellSobreviveALaShellDeCadaPlataforma`; `cmd/nucleo/autorizacion_supresion_test.go#TestEraseDiceQueOrdenPedirYEsaOrdenFunciona`; demo ejemplo | No completamente | POSIX y `CommandLineToArgvW` están cubiertos. No cubre expansión real de PowerShell ni `cmd.exe` con `%VAR%`; ver H2 y H3. |
| L18 | sin test | Bien acotado | Es límite legal/operativo: backups, sistema integrador y hash residual quedan fuera. Correcto como límite no testeable. |
| L19 | sin test | Bien acotado | README/release dicen alfa, sin auditoría profesional y sin producción. Es afirmación de estado, no propiedad del código. |
| L20 | `cmd/nucleo/ataque_supresion_test.go#TestLaClaveDelServidorNoSuprime`; `#TestCadaSupresionAbreUnaAlarma` | Sí para la parte programática | Fija que servidor sin autorización no consigue veredicto bueno y que alarma se abre/reabre. La separación de personas no es testeable por software. |
| L21 | `internal/reconcile/supresion_test.go#TestAutorizacionAjenaNoCuenta` | Sí parcial | Cubre que otra clave no cuenta. No hay test del límite social “la política debe llegar autenticada” ni de rotación de `erasureKey` vieja/nueva, que el documento declara como límite. |

## PROTOCOL 0.7-draft frente al código y SDKs

Correcto en Go:

- Texto firmado exacto y línea final: `internal/erasure/autorizacion.go:41-55` coincide con `docs/PROTOCOL.md:370-383`.
- Firma Ed25519 sobre `SHA-256(text)`: `internal/erasure/autorizacion.go:57-66`.
- `payload_cid` estricto: `internal/erasure/autorizacion.go:69-87`, con vectores de ceros a la izquierda, signo, overflow, mayúsculas, longitud, campos extra y espacios.
- `through < E.index`: `internal/erasure/autorizacion.go:137-139`.
- `B.index <= through`: `internal/reconcile/reconcile.go:344-354`.
- Sin política o sin `erasureKey`, ninguna cuenta: `internal/erasure/autorizacion.go:91-94`, `internal/policy/policy.go:171-178`, `cmd/nucleo/reconcile.go:48-53`.
- Evento `nucleo.erasure.v1` y payload `{"erased_payload_hash":"..."}`: cubierto por `cmd/nucleo/erase_test.go` e `internal/erasure/erasure_test.go`.

Correcto en parsers de política Go/TS/PHP:

- Go: `internal/policy/policy.go:149-169`.
- TS: `sdk/ts/src/policy.ts:309-318`.
- PHP: `sdk/php/src/Policy.php:209-224`.
- Los vectores de `testdata/vectors/policy` se consumen en Go, TS y PHP.

Matiz: `testdata/vectors/erasure` solo se consume en Go porque TS/PHP no implementan verificación de autorización de supresión.

## Comprobado y correcto

- ADR-032 cumple su frontera central en Go/CLI: la reconciliación solo da por suprimido un bloque si existe evento posterior autorizado por `erasureKey`, con `through` correcto y política externa. La passphrase y la clave tenant no bastan.
- `erase` verifica autorización antes de abrir el vault y borra blob/compromisos/evento/detalle en una transacción. Si el proceso muere antes del commit, no queda borrado parcial; si muere después del commit y antes del WAL truncate, repetir no sella otro evento y reintenta el purge.
- `erasure-key init` genera clave separada con `crypto/rand`, no abre ledger, no deriva del vault y las tarjetas de vault se rechazan en `authorize`.
- `alert ack` sigue sin firma, pero solo escribe `log/erasure-ack/v1/<hash>` en `log_state`; `reconcile` decide desde bloques firmados y política, no desde el ack. El ack puede callar la alarma, no convertir una supresión no autorizada en `erased`.
- ADR-030 está correctamente implementado: `testigo.json` usa lector estricto, log retirado devuelve 404 con cuerpo distinguible, la memoria se conserva y se publica, y al retirar con memoria se comprueba la clave recordada.
- Regresión `receipt --out` cerrada: `entregaRecibo` verifica antes de escribir, usa temporal en el mismo directorio, fsync del fichero y rename. Los tests `TestUnReciboQueNoVerificaNoSeEscribe` y `TestUnReciboQueVerificaSeEscribeEntero` pasan.
- SDK TS 0.4.0-alpha.0 empaqueta solo `dist`, `README.md`, `LICENSE` y `package.json`. La política 0.3 sin `erasureKey` sigue aceptándose; la política con `erasureKey` exige SDK 0.4, como dice el README.
- SDK PHP tiene `onErasure` implementado: lee `erasure_alert`, llama el hook solo si `state == "open"`, y si el hook lanza lo registra con `error_log` sin romper la operación.
- `scripts/ensayo-actualizacion.sh` limpia temporales y testigos con `trap`, valida hash antes de extraer, y ordena la ejecución de forma reproducible. El hallazgo es solo que la firma queda opcional si falta `cosign`.
