<!--
Este preámbulo lo añade el repositorio; el informe empieza donde lo dice y no se ha
tocado una coma. Si alguna vez hay que separar las dos cosas, el corte es la línea
"FIN DEL PREÁMBULO".
-->

# Nota de procedencia

**Versionado el 2026-10-15 desde la copia que el dev dejó en
`C:\Users\C-SERMIL\Documents\nucleo-revisiones\`**, sacada del clon limpio donde lo escribió
el modelo, `/tmp/opencode/nucleo-rev2`. El texto de abajo es esa copia **sin modificar**:
SHA-256 `ffb484b20db14aa27eb3f5ac605b2734edcb27e48e7cf18cabad5fec8978f6e2`, el mismo que da
`sed '1,/^FIN DEL PREÁMBULO$/d' | tail -n +4` sobre este fichero.

| | |
|---|---|
| **Modelo** | `GPT-5.6 Terra Fast` (OpenAI), vía OpenCode — no el `gpt-5.5` de las revisiones anteriores |
| **Encargo** | revisar solo lo cambiado desde `c52d906`, con el trabajo principal de comprobar la tabla «Cierre» de la revisión del 2026-10-11, sobre un clon limpio |
| **Fecha del informe** | 2026-10-14 |
| **Commit revisado** | `ec21632` (`ec21632270f84a75026a80a8ed8725b52827422f`) |
| **Método** | ejecutó `go test ./...` y `-race`, con y sin `testhooks`, `scripts/lint.sh`, shellcheck, `tercero-supresion.sh`, la compuerta —en rojo solo por los tres pasos de PHP: no había PHP, y el propio informe lo dice— y el ensayo de actualización con cosign y sin él |
| **Longitud** | 14.827 caracteres, 208 líneas |

## Cierre

Sprint 21 (2026-10-15). Cada hallazgo se contrastó con el código antes de aceptarlo; los tres
eran ciertos. H10, que el informe da por mejora de cobertura sin defecto, sí tenía uno: al
ejecutar sus casos en `powershell.exe` 5.1, la raíz UNC con espacio rompía el argv.

| hallazgo | estado | commit | test |
|---|---|---|---|
| **H8** — el ensayo usa `checksums.txt` antes de autenticarlo | **cerrado**: `checksums.txt` y su firma → `cosign verify-blob` con la identidad exacta → la línea exacta del tarball en ese manifiesto ya autenticado (si no lo nombra, no se baja) → solo entonces el tarball → `sha256sum -c` → `tar`. Con `NUCLEO_ENSAYO_SIN_FIRMA=1`, el mismo orden sin cosign y con el aviso. `NUCLEO_ENSAYO_SOLO_PASO1=1` corta tras el paso 1 | `ce3ab19` | `scripts/test-ensayo-orden.sh`, sin red, con shims de `curl`, `cosign`, `sha256sum` y `tar` que anotan el orden: cosign antes del tarball y de `sha256sum`; cosign que falla → 2 sin tarball ni `tar`; sin cosign → 2 sin ni un `curl` (H4, que hasta ahora no tenía test); con la variable, sigue y avisa. Contra el script anterior, falla en tres de los cuatro casos. Lo corren la compuerta y el job `scripts` del CI. Y el ensayo completo con cosign v2.5.2, en verde |
| **H9** — `tercero-supresion.sh` puede usar la red al compilar | **cerrado**: el modo completo compila con `GOPROXY=off` y `GOFLAGS=-mod=readonly`; si faltan módulos —o la toolchain de `go.mod`— sale con 1 y dice `go mod download`, que se corre aparte; `NUCLEO_BIN` evita compilar. El job `scripts` del CI baja los módulos en un paso propio, antes. Cabecera y G45 precisos | `d02c0fb` | el camino normal, el propio script en la compuerta y el CI. **Sin test automatizado** del camino sin caché: comprobado a mano con un `GOMODCACHE` vacío —sale con el mensaje; tras `go mod download` con esa caché, pasa— y con `NUCLEO_BIN` y sin `go` en el PATH |
| **H10** — los bordes de Windows de `filepath.Clean`, sin test de consola | **cerrado, con un arreglo**: la rama Windows de `rutasConTrampa` gana `C:`, `\\servidor\mi recurso\`, `.\x` y componentes que acaban en espacio y en punto. Con la raíz UNC, PowerShell 5.1 partía el argv de las seis órdenes: `Clean` conserva la `\` final de una raíz y esa `\` escapaba la comilla de cierre. `rutaWindowsParaImprimir` le añade un `.` (el mismo directorio). G46 y CHANGELOG lo dicen; **la enmienda de ADR-032 §F sigue diciendo solo `filepath.Clean`** —los ADR no los toca el agente—: queda para el dev | `9b87ca5` | `cmd/nucleo/comillas_shell_test.go#TestLasOrdenesImpresasFuncionanEnLaConsolaDeVerdad` (ejecutado aquí con el binario de tests de Windows desde WSL y `powershell.exe` 5.1: 108 órdenes; `pwsh` no está en esta máquina, en el CI lo corren los dos) y `#TestRutaWindowsParaImprimir`, con los valores escritos a mano |

FIN DEL PREÁMBULO

---

# Revisión externa técnica - cierre Sprint 20

Proyecto: `github.com/nucleoledger/nucleo`.

Commit revisado: `ec21632270f84a75026a80a8ed8725b52827422f`.

Clon: `/tmp/opencode/nucleo-rev2`.

Fecha: 2026-10-14.

Alcance: solo cambios desde `c52d906`, con trabajo principal de comprobar la tabla «Cierre» de `docs/revision-externa-modelo-20261011.md`. No modifiqué el repositorio salvo este informe y no hice push.

## Metadatos

```text
$ git rev-parse HEAD
ec21632270f84a75026a80a8ed8725b52827422f

$ go version
go version go1.27.2 linux/amd64
```

```text
$ git log --oneline c52d906..HEAD
ec21632 docs: cierre de la revisión del 2026-10-11 (H2, H3, H4, G45), y CHANGELOG
9afa871 ci: job scripts con el bit de ejecución y shellcheck fijado
02dd249 fix(scripts): lo que señala shellcheck 0.11.0 en scripts/*.sh
72cab08 build: scripts/tercero-supresion.sh, la comprobación del tercero sin red (G45)
9d7278b build(ensayo): sin cosign, el ensayo sale con 2 antes de descargar nada (H4)
4f247c1 fix(cli): en Windows, las órdenes impresas son para PowerShell (H2, H3)
a82d458 docs: cierre parcial de la revisión del 2026-10-11, y CHANGELOG
60e53d6 ci: -timeout 15m explícito en los dos pasos de test, y en la compuerta
6a462ce test(reconcile): la política de otro origin, un objeto de error de integridad
66b2af8 test(erase): reconocer una supresión no la autoriza (G42)
0e3f9b4 fix(reconcile): --json emite un solo objeto también si falla VerifyFull (H1)
4bb191f docs: la autorización de supresión la comprueba solo Go (H5, H6)
756b586 test(cli): el rechazo TLS intencionado ya no ensucia el log del CI
7b68521 test(cli): el vault de los tests, con --kdf-profile constrained
e0b2a83 docs: ADR-033 candidato, la rotación de erasureKey, anotada sin diseñar
711af7a build(compuerta): todo scripts/*.sh, con el bit de ejecución en el índice
cd392b5 docs: la revisión externa del 2026-10-11, versionada tal cual
be6a18f build: scripts/compuerta.sh con el bit de ejecución en el índice
```

```text
$ git diff --stat c52d906..HEAD
37 files changed, 1873 insertions(+), 224 deletions(-)
```

Leí entero `docs/revision-externa-modelo-20261011.md`, incluido el preámbulo y su tabla «Cierre»; además leí código, tests, `GARANTIAS.md`, ADR-032 §F, `scripts/tercero-supresion.sh`, `scripts/ensayo-actualizacion.sh` y `.github/workflows/ci.yml` relacionados con cada fila.

## Ejecución

```text
$ go test ./... -race -timeout 15m
ok   github.com/nucleoledger/nucleo/cmd/nucleo 83.566s
ok   github.com/nucleoledger/nucleo/internal/receipt 32.374s
ok   github.com/nucleoledger/nucleo/internal/store 18.047s
ok   github.com/nucleoledger/nucleo/internal/vault 22.523s
ok   github.com/nucleoledger/nucleo/internal/witness 3.191s

$ go test -tags testhooks ./... -race -timeout 15m
ok   github.com/nucleoledger/nucleo/cmd/nucleo 219.769s
ok   github.com/nucleoledger/nucleo/internal/receipt 35.151s
ok   github.com/nucleoledger/nucleo/internal/store 18.638s
ok   github.com/nucleoledger/nucleo/internal/vault 23.712s
ok   github.com/nucleoledger/nucleo/internal/witness 3.776s
```

```text
$ ./scripts/lint.sh
lint.sh: golangci-lint v2.14.0 con go1.27.2
0 issues.
0 issues.
lint.sh: ✔ las dos pasadas, sin issues

$ shellcheck scripts/*.sh
# salida vacía; código 0
```

```text
$ ./scripts/tercero-supresion.sh
   ✔ la autorización cubre el bloque (0 ≤ 0 < 2)
   ✔ el evento suprime el contenido del bloque
   ✔ la firma de la autorización verifica con openssl y la erasureKey de la política
   ✔ y con la erasureKey de otra clave, la firma no verifica: la comprobación muerde
✔ el tercero comprueba la supresión con sha256sum y openssl
```

```text
$ ./scripts/compuerta.sh
━━ bit de ejecución de scripts/*.sh                  ✔
━━ shellcheck de scripts/*.sh                        ✔
━━ gofmt                                             ✔
━━ go vet                                            ✔
━━ go vet -tags testhooks                            ✔
━━ lint                                               ✔
━━ go test -race                                     ✔
━━ go test -race -tags testhooks                     ✔
━━ SDK de TypeScript                                 ✔
━━ vectores de recibo                                ✔
━━ PHP con ext-sodium                                ✘ no hay PHP
━━ suite de PHP, con el binario                      ✘ no hay PHP
━━ diferencial de los TRES verificadores             ✘ no hay PHP
━━ criterio de éxito, testigo mutuo, kit, tercero,
   ejemplo ERP, Mermaid y testigos huérfanos         ✔

✘ COMPUERTA EN ROJO (359 s): solo fallaron los 3 pasos de PHP
```

No hay `php` en este entorno. Esa es la única causa de fallo de la compuerta; el script ahora se ejecuta directamente y verificó el bit `100755` de todos los `scripts/*.sh`.

Pruebas de cierre ejecutadas con detalle:

```text
$ go test -tags testhooks ./cmd/nucleo -run 'Test(ReconcileJSONConVerifyFullFallidoEsUnSoloObjeto|ReconcileConVerifyFullFallidoLoDiceAPersonas|ReconocerNoAutorizaUnaSupresion|ReconcileJSONConPoliticaDeOtroOrigin|LasOrdenesImpresasFuncionanEnLaConsolaDeVerdad|KDFProfileEnInit|RestoreFijaPassphraseNueva)$' -v
--- PASS: TestReconocerNoAutorizaUnaSupresion
--- PASS: TestLasOrdenesImpresasFuncionanEnLaConsolaDeVerdad/sh (78 órdenes)
--- PASS: TestReconcileJSONConVerifyFullFallidoEsUnSoloObjeto
--- PASS: TestReconcileConVerifyFullFallidoLoDiceAPersonas
--- PASS: TestReconcileJSONConPoliticaDeOtroOrigin
--- PASS: TestRestoreFijaPassphraseNueva
--- PASS: TestKDFProfileEnInit
PASS

$ go test ./internal/vault -run TestArgon2idGolden -v
--- PASS: TestArgon2idGolden
```

También ejecuté el ensayo completo de actualización con `cosign`: llega a `✔ ENSAYO EN VERDE: v0.3.1-alpha → HEAD`. La ruta sin `cosign`, usando un `PATH` controlado que conserva las herramientas requeridas pero omite `cosign`, imprimió la negativa indicada y salió con código `2` antes de la fase de descargas.

## Hallazgos

### H8 - BAJA - CONFIRMADO - El ensayo autentica `checksums.txt` después de usarlo para comprobar el tarball

Fichero: `scripts/ensayo-actualizacion.sh:117-150`.

Evidencia: el script descarga a la vez el tarball y `checksums.txt` en líneas 117-121. Luego usa el manifiesto aún no autenticado para ejecutar `sha256sum -c` en líneas 122-132. Solo después descarga bundle/firma y ejecuta `cosign verify-blob checksums.txt` en líneas 133-150. El ensayo no extrae ni ejecuta el binario antes de que `cosign` pase, por lo que no vi ejecución de código no autenticado; pero el orden pedido no se cumple y un manifiesto atacante se usa como entrada de verificación antes de autenticarlo.

Cómo reproducirlo: inspeccionar el orden de esas líneas, o instrumentar `sha256sum` y `cosign`; el primero recibe `checksums.txt` antes de `cosign verify-blob`.

Arreglo propuesto: descargar primero `checksums.txt` y su bundle/firma, verificar exactamente esa firma con `cosign`, y solo entonces descargar el tarball y contrastar su hash contra el manifiesto ya autenticado. Test: script de prueba con wrappers de `curl`, `sha256sum` y `cosign` que registre orden y falle si `sha256sum -c` ocurre antes de `cosign verify-blob`.

### H9 - BAJA - CONFIRMADO - El modo completo de `tercero-supresion.sh` no garantiza ausencia de red en un entorno sin caché Go

Fichero: `scripts/tercero-supresion.sh:90-122`.

Evidencia: el verificador aislado `comprueba` de líneas 30-75 usa solo Python, `sha256sum`, `xxd` y OpenSSL, y no invoca `nucleo`. El modo sin argumentos, sin embargo, llama a `go build` en línea 122. En una máquina limpia, Go puede descargar módulos desde `GOPROXY`/sumdb; el script no fuerza `GOPROXY=off`. El testigo que crea después sí escucha exclusivamente en `127.0.0.1` (líneas 136-156), y no hay `curl` ni otro cliente de red explícito.

Cómo reproducirlo: ejecutar el modo completo con una caché de módulos vacía y un proxy Go observable; el `go build` puede acceder a red. El modo `comprueba RECIBO_BLOQUE RECIBO_EVENTO POLITICA` no tiene esa dependencia.

Arreglo propuesto: documentar que el modo generador requiere dependencias Go ya disponibles, o ejecutar su compilación con `GOPROXY=off` y fallar si la caché no basta; alternativamente recibir un binario ya compilado. Test: ejecutar el modo `comprueba` con `PATH` limitado y sin utilidades de red, y un test de integración del modo generador con `GOPROXY=off`.

### H10 - INFO - CONFIRMADO - Los bordes Windows de `filepath.Clean` se razonan, pero no están en el test de shell real

Ficheros: `cmd/nucleo/comillas.go:31-39`, `cmd/nucleo/comillas_shell_test.go:48-83`.

Evidencia: la implementación Windows llama `filepath.Clean` antes de citar. Según el comportamiento Windows de `filepath.Clean`, `C:` pasa a `C:.`, `./x` pasa a `x`, y se mantienen espacios/puntos finales y la raíz UNC. La cita single-quote de PowerShell no permite que una barra invertida escape el cierre, por lo que la antigua rotura de PowerShell 5.1 con comillas dobles no persiste. Sin embargo, el conjunto de 13 rutas de `rutasConTrampa` no contiene `C:`, una raíz UNC `\\servidor\recurso\` con espacio y barra final, `./x`, ni componente con espacio/punto final.

Cómo reproducirlo: revisar `rutasConTrampa`; los casos no están. En este host está disponible `powershell.exe` 5.1.19041.6456, pero el test Go ejecutado como `GOOS=linux` solo corre su rama `sh`.

Arreglo propuesto: añadir esos cuatro casos a la rama Windows de `rutasConTrampa` y ejecutarlos en `windows-2025`, donde el test exige `powershell.exe` y `pwsh` si CI está activo. Es una mejora de cobertura, no encontré comportamiento incorrecto en el código actual.

## Tabla de cierre verificada

| fila | commit/test citado | veredicto |
|---|---|---|
| H1 | `0e3f9b4`; `TestReconcileJSONConVerifyFullFallidoEsUnSoloObjeto` | Correcto. `cmd/nucleo/reconcile.go:111-116` usa `reported: e.json`; JSON conserva informe único y salida 2. Sin JSON `reported:false`, de modo que stderr conserva `error:`. Ambos caminos están fijados por test. |
| H1, propiedad general | `cli_test.go#unSoloValorJSON`; vectores CLI JSON | Correcto dentro del arnés `cli`: `cli.run` llama `unSoloValorJSON` para cada argv que contiene `--json`; exige objeto y EOF. `TestVectoresCLIJSON` también lo comprueba por vector. No es un interceptor global de binarios externos, sino de todas las invocaciones del arnés. |
| H2 | `4f247c1`; `TestLasOrdenesImpresasFuncionanEnLaConsolaDeVerdad` | Correcto para el alcance prometido: Windows apunta a PowerShell, siempre con comillas simples; duplica `'`, U+2018, U+2019, U+201A y U+201B. El modelo cubre las cinco; la shell real cubre `'` y U+2019. No promete `cmd.exe`. |
| H3 | `4f247c1`; mismo test | Correcto como cambio de alcance, no como soporte de cmd: `%USERNAME%` y `!x!` se pasan literales en PowerShell. G46/CLI-JSON/ayuda delimitan que cmd no se promete. |
| H4, ausencia de cosign | `9d7278b` | Correcto. Sin `cosign` y sin `NUCLEO_ENSAYO_SIN_FIRMA=1`, líneas 89-101 salen 2 antes de construir URLs o ejecutar `curl`. Con la variable, imprime explícitamente que se ensaya sin firma. H8 mantiene el problema de orden de la ruta con cosign. |
| H5/H6 | `4bb191f` | Correcto como documentación de alcance y comentario actualizado: la autorización la comprueba Go/CLI, no SDK TS/PHP; no hay test porque no es código nuevo. |
| H7 | `be6a18f`, `711af7a`; compuerta | Correcto. `git ls-files -s -- scripts/*.sh` muestra todos en `100755`; la compuerta y CI los verifican. |
| G42 | `66b2af8`; `TestReconocerNoAutorizaUnaSupresion` | Correcto. El subtest forjado + ack sigue dando exit 2, finding `supresión no autorizada` y `erased:[]`; el autorizado + ack da exit 0 y un elemento erased. Coincide con G42 y ADR-032 §G. |
| otro origin | `6a462ce`; `TestReconcileJSONConPoliticaDeOtroOrigin` | Correcto. Salida 2, un objeto, `ok:false`, `error_class:integrity`, y no hay `findings`, `erased` ni `full_verify` porque no abre el ledger. |
| G45 | `72cab08`, `9afa871`; `tercero-supresion.sh` | Correcto para la comprobación: `comprueba` reconstruye relaciones con Python/sha256sum y verifica Ed25519 con OpenSSL, sin `nucleo`; el negativo falla específicamente por firma con otra erasureKey. Lo llama compuerta y job scripts. Ver H9 sobre la creación de fixture con Go. |
| CI #70 | `7b68521`, `756b586`, `60e53d6` | Correcto por código: fixtures generales usan `constrained`; `TestKDFProfileEnInit` y `TestRestoreFijaPassphraseNueva` retienen default; CI y compuerta pasan `-timeout 15m`. No puedo confirmar localmente la medición específica de macos-26; es una medición de CI, no una propiedad de test. |

## Comillas y órdenes impresas

Todos los comandos copyable con ruta interpolada pasan por `argShell`:

- Autorización: `cmd/nucleo/erasure_key.go#ordenAutorizar`.
- Sync/status programados: `cmd/nucleo/policy.go#ordenesProgramadas`.
- Ledger inexistente: `cmd/nucleo/env.go`.
- Recomendaciones de restore: `cmd/nucleo/env.go` y `cmd/nucleo/backup.go`.
- Recomendación de backup: `cmd/nucleo/init.go`.

El grep de `nucleo ` en `cmd/nucleo` no reveló otra orden con ruta interpolada que evitase `argShell`; los demás resultados son ayuda, texto estático o consejos sin ruta. Las seis órdenes modeladas empiezan por `nucleo ` y el test lo exige con `HasPrefix`.

`comillas_shell_test.go` captura desde los helpers reales tres formas: autorización y las dos órdenes programadas. Reconstruye estas cuatro salidas `printf` en vez de capturarlas de la CLI:

- `env.go`: `nucleo init --dir ...` para ledger inexistente.
- `env.go`: consejo `restore --new-passphrase`.
- `backup.go`: consejo `restore --new-passphrase`.
- `init.go`: consejo `backup --dir ...`.

G46 lo declara expresamente. El test tiene seis líneas modelo para siete sitios porque los dos consejos de restore comparten forma.

## KDF, CI y documentación

- El perfil default está ejercido de punta a punta por `TestRestoreFijaPassphraseNueva`: `init → seal → backup → restore → seal`, explícitamente con `default`.
- `TestKDFProfileEnInit` crea también un vault sin `--kdf-profile` y comprueba `default`/64 MiB; el constrained se prueba como opt-in.
- `internal/vault#TestArgon2idGolden` sigue fijando los parámetros/derivación de Argon2id.
- Las fixtures generales de CLI usan `perfilDeLosTests = constrained`; no encontré un test cuyo sujeto fuese el comportamiento de producción y que ahora solo pase por constrained. Los tests caros de default están conservados a propósito.
- `.github/workflows/ci.yml` define `permissions: contents: read` globalmente. El job `scripts` fija ShellCheck `v0.11.0`, verifica SHA-256 antes de ejecutarlo y exige `100755`. Ambos test jobs usan `-timeout 15m`; `compuerta.sh` usa el mismo presupuesto.
- G42, G44, G45 y G46 coinciden con el código y tests citados. La enmienda ADR-032 §F coincide con `erase`: autorización antes de abrir vault, tarjetas de supresión en `authorize`, y passphrase en `erase`.
