<!--
Este preámbulo lo añade el repositorio; el informe empieza donde lo dice y no se ha
tocado una coma. Si alguna vez hay que separar las dos cosas, el corte es la línea
"FIN DEL PREÁMBULO".
-->

# Nota de procedencia

**Versionado el 2026-10-17 desde la copia que el dev dejó en
`C:\Users\C-SERMIL\Documents\nucleo-revisiones\`** (`revision-externa-sprint22-20261017.md`).
El texto de abajo es esa copia **sin modificar**: SHA-256
`3e3e9ee1e561b849e4dfb8b6c607efd34190476f4a271c5368f8b2e4e9141b74`, el mismo que da
`sed '1,/^FIN DEL PREÁMBULO$/d' | tail -n +4` sobre este fichero.

| | |
|---|---|
| **Modelo** | `GPT-5.6 Terra Fast` (OpenAI), vía OpenCode |
| **Encargo** | contrastar el informe del Sprint 22 (`8756f22..63e6d25`, solo documentación y la guardia de documentos) antes del tag de `v0.4.0-alpha` |
| **Fecha del informe** | 2026-10-17 |
| **Commit revisado** | `63e6d25` (`63e6d25d5b99760f364dcb139420e280fa88b320`) |
| **Método** | contraste estático, los tres tests de la guardia de documentos y `git tag -v` de cuatro tags; **no** reprodujo la compuerta ni consultó GitHub o npm, y el propio informe lo dice |
| **Longitud** | 7.925 caracteres, 85 líneas |

FIN DEL PREÁMBULO

---

# Revisión externa del Sprint 22 (pre-tag v0.4.0-alpha)

**Fecha:** 2026-10-17  
**Base revisada:** `63e6d25d5b99760f364dcb139420e280fa88b320`  
**Rango documental:** `8756f22..63e6d25` (cinco commits)  
**Ámbito:** contraste estático y pruebas focalizadas del informe del Sprint 22. Este informe no modifica el repositorio.

## Veredicto

No encontré una contradicción técnica en los cinco commits revisados. La documentación vigente queda mejor alineada con las garantías y límites documentados, y la nueva guardia automatiza una parte concreta de esa alineación.

La conclusión `LISTO_PARA_TAG_V040=SI` es **razonable como estado de preparación del árbol** si se toman como evidencia los resultados de compuerta y CI proporcionados. No equivale a afirmar que el release ya esté verificado: faltan las acciones deliberadamente posteriores al tag (crear/publicar el tag y comprobar sus artefactos desde un directorio limpio) y la revisión manual pre-tag que prescribe `docs/RELEASING.md`.

No hay hallazgos bloqueantes para crear el tag a partir de esta revisión. Hay dos matices que deben conservarse:

- La guardia documental valida estructura y referencias; no demuestra que la prosa sea semánticamente cierta. El código y `RELEASING.md` lo declaran expresamente.
- Queda un pendiente P2 ya anotado en `TODO.md`: `SECURITY.md` debe mencionar tanto los ADR como `docs/revision-externa-*` al decir que no ha habido auditoría externa profesional. No invalida la preparación técnica, pero impide describir el trabajo documental como completamente terminado.

## Evidencia comprobada localmente

| Afirmación | Resultado | Evidencia |
|---|---|---|
| Base y alcance | Conforme | `63e6d25` resuelve al SHA indicado; `8756f22` es ancestro; `git rev-list --count 8756f22..63e6d25` da 5. |
| Árbol de trabajo | Conforme al comenzar y al terminar las comprobaciones | `git status --short --branch` mostró únicamente `## main...origin/main`. |
| Cambios del Sprint 22 | Conforme | Solo afectan `SECURITY.md`, `README.md`, `PLAN.md`, `TODO.md`, `AUTHORS`, `cmd/nucleo/docs_vigentes_test.go`, `docs/GARANTIAS.md` y `docs/RELEASING.md`; `git diff --check` no informó errores de espacios. |
| Guardias documentales | Conforme | `go test ./cmd/nucleo -run 'Test(SecurityRemiteCadaLimiteAGarantias|ReadmeYTodoNombranLaVersionVigente|LaGuardiaDeLosDocumentosMuerde)$' -v` pasó: 3/3. |
| La guardia muerde | Conforme para sus siete mutaciones | `TestLaGuardiaDeLosDocumentosMuerde` vuelve inválidos Lnn, enlaces, uso de Gnn, una viñeta falsa y versiones README/TODO/CHANGELOG; todas las mutaciones son detectadas. |
| SECURITY y GARANTIAS | Conforme estructuralmente | La guardia exige que cada viñeta de `Out of scope` enlace `docs/GARANTIAS.md`, cite Lnn existentes y no cite Gnn. `L22` añade el límite de truncamiento/completitud. |
| README y TODO con la versión preparada | Conforme | La guardia toma la primera versión no `Unreleased` de `CHANGELOG.md` y exige que README Status comience por ella y que el párrafo Estado de TODO la mencione. |
| Tags SSH citados | Conforme | `git tag -v v0.3.0-alpha`, `v0.3.1-alpha`, `vsdk-0.3.0-alpha.0` y `vsdk-0.4.0-alpha.0` devolvieron `Good "git" signature` con la huella ED25519 `SHA256:Cv6P5z+97iMwHvEUsn+VGeKqdV+jGdDcYGPuiYJTaCI`. |
| AUTHORS sobre los commits | Conforme parcialmente | `b894337` y `5237867` tienen estado Git `%G? = E`: no llevan firma Git verificable localmente. Esto concuerda con AUTHORS. La frase adicional sobre firma/verificación por GitHub requiere comprobar GitHub, no `git` local. |

## Revisión de los cambios

### SECURITY y GARANTIAS

El cambio elimina dos formulaciones históricas que contradecían garantías ya existentes y convierte la sección `Out of scope` en referencias a límites `Lnn`. Es una mejora material: separa lo que el programa promete de lo que explícitamente no puede prometer.

`L22` documenta correctamente el límite esencial de completitud: un fichero controlado por el atacante no puede acreditar por sí mismo que no fue truncado; la detección requiere memoria externa de testigo en un `sync` posterior. La formulación es consistente con la arquitectura y con el test citado para apertura no atestiguada tras borrar checkpoints.

### README, PLAN y TODO

Los documentos pasan a distinguir con claridad:

- SDK `0.4.0-alpha.0` publicado frente a core `v0.4.0-alpha` preparado pero sin etiquetar.
- Último core publicado (`v0.3.1-alpha`) frente a la versión cuyo CHANGELOG ya está preparado (`v0.4.0-alpha`).
- Evidencia reproducida del release anterior frente a trabajo pendiente de creación y verificación del nuevo release.

Esa separación evita presentar como publicado lo que todavía es un estado pre-tag. El bloque "Cierre de v0.4.0-alpha" permanece sin marcar y es correcto que siga así.

### AUTHORS

El cambio evita una afirmación engañosa sobre firma de commits. Las firmas SSH verificadas localmente son las de los cuatro tags comprobados, no las de los commits `b894337` y `5237867`. Es una precisión importante para trazabilidad.

### Guardia documental

`cmd/nucleo/docs_vigentes_test.go` cubre dos regresiones que ya ocurrieron: límites mal descritos en SECURITY y versiones atrasadas en README/TODO. La prueba de mutación es especialmente útil porque evita una guardia vacía que solo pase contra sus propios documentos actuales.

Su límite es correcto y explícito: no compara el significado de cada viñeta con el texto de su `Lnn`, ni puede establecer que el resto de README, TODO o PLAN sea verdadero. Este riesgo no está oculto; `docs/RELEASING.md` exige releerlo antes del tag. Debe mantenerse ese paso humano y no presentar la guardia como verificador semántico.

## Evidencia aportada, no reproducida en esta revisión

Los siguientes datos fueron aportados en el informe del Sprint y son coherentes con el estado revisado, pero no se reprodujeron aquí:

| Afirmación | Estado de esta revisión |
|---|---|
| `./scripts/compuerta.sh` verde en 850 s con PHP/sodium | No reproducida localmente; se acepta como evidencia reportada. La compuerta es la validación integral adecuada antes del tag. |
| CI #75 verde en GitHub Actions | No consultado en GitHub; reportado como verde (12m47s) sobre `63e6d25`. |
| CodeQL #26 verde | No consultado en GitHub; reportado como verde (1m40s) sobre `63e6d25`. |
| SDK publicado en npm con procedencia | No consultado en npm/GitHub; los tags y las referencias locales son consistentes con la afirmación, pero no prueban la publicación ni su provenance. |
| Compilación byte a byte y verificación cosign de releases previos | Documentado en el repositorio; no repetido desde directorio limpio en esta revisión. |

## Acciones que siguen siendo obligatorias para el release

Estas no son defectos del Sprint 22; son el flujo intencional posterior o inmediatamente previo al tag:

1. Repetir la compuerta en el commit final y completar la lista "Antes del tag" de `docs/RELEASING.md`, incluido el ensayo de actualización con firma verificada.
2. Realizar la revisión humana de coherencia de SECURITY, README, TODO y PLAN requerida por `RELEASING.md`.
3. Verificar `git status` limpio, firmar y publicar `v0.4.0-alpha`.
4. Desde un directorio limpio, verificar checksums, firma cosign, procedencia y recompilación conforme a `docs/RELEASING.md`; registrar el resultado en la nota de release y su tabla.
5. Resolver el P2 documental de `SECURITY.md` cuando se aborde la siguiente ronda de documentación.

## Conclusión para revisión en Claude web

El Sprint 22 cierra una deriva real de documentación y añade una protección útil contra su repetición. La evidencia local confirma los cambios, los tests focalizados y las firmas SSH de los tags citados. La afirmación más precisa es: **el árbol `63e6d25` está preparado para seguir el procedimiento de etiquetado de `v0.4.0-alpha`; el release todavía no existe ni puede considerarse verificado hasta completar los controles posteriores al tag.**
