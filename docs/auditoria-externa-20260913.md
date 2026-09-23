<!--
Este preámbulo lo añade el repositorio; el informe empieza donde lo dice y no se ha
tocado una coma. Si alguna vez hay que separar las dos cosas, el corte es la línea
"FIN DEL PREÁMBULO".
-->

# Nota de procedencia

**Recuperado el 2026-09-22 de la sesión de OpenCode donde se produjo**, y versionado
entonces. Hasta ese día este fichero no existía en el repositorio aunque cinco ADR lo
citaran, que es exactamente la clase de referencia que no se puede comprobar. La
recuperación se intentó antes de escribir cualquier sustituto: la alternativa preparada
era una nota de pérdida, y no hizo falta.

| | |
|---|---|
| **Modelo** | `gpt-6-astra` (OpenAI), vía OpenCode 1.15.12 |
| **Sesión** | «Auditoría adversarial de criptografía», `ses_f871559b1ffeqreA4WwQzx7F8F` |
| **Instante del informe** | 2026-09-13 18:36 UTC (`prt_09c0e424c001AmD1ttTuOBkyMy`) |
| **Commit revisado** | `1c53e1c61e04931d7941123bf5cbbdb67f7058d6` |
| **Método** | acceso de lectura al árbol público; el auditor ejecutó la maquinaria del propio repositorio —suites, diferencial, oráculo, criterio de éxito— y **detuvo las ejecuciones** a mitad por instrucción del dev, así que los hallazgos nuevos son análisis estático y el propio informe lo dice en su segundo párrafo |
| **Alcance** | PROTOCOL 0.3-draft |
| **Longitud** | 30.278 caracteres, tal como se recuperaron |

## Dónde se cerró cada hallazgo

El informe pedía un orden y se siguió. Esta tabla es el mapa entre lo que dijo y lo que se
hizo; cada commit lleva su propia explicación y su prueba de que falla sin el arreglo.

| hallazgo del informe | cerrado en | decisión escrita |
|---|---|---|
| H1 — el atajo podía quedar ligado a una raíz distinta de la atestiguada | `281955a` (Sprint 7f) | refuerza [ADR-016](adr/ADR-016-atestacion-en-la-apertura.md) |
| H2 — pedir otro POST no demuestra que la respuesta sea nueva | `281955a`, y el umbral propio del aviso en `a34849e` (Sprint 8) | acotado, no cerrado: cerrarlo exige un nonce en `tlog-witness` |
| H3 — un header malformado provocaba un pánico en Go | `e6e445f` | — |
| H4.1 — nanosegundos: un recibo real de Go lo rechazaban el SDK y la página | `13541cc` | [ADR-019](adr/ADR-019-resolucion-temporal.md), PROTOCOL 0.4-draft |
| H4.2 y H4.3 — TS miraba el orden de claves, no la canonicidad JCS; Go no comparaba el índice | `cb73f17` | — |
| H5 — TS perdía un testigo llamado `__proto__` | `00f1392` | — |
| H6 — la frescura mezclaba «primera evidencia» con «último contacto» | `4d2a4cd` | — |
| H7 — la comparación de identidad se omitía cuando faltaban metadatos | `29ffa0a` (Sprint 8) | [ADR-022](adr/ADR-022-comparacion-imposible-no-es-veredicto.md) |
| H8 — el sellado no ofrecía reintentos idempotentes ni atomicidad | `1e8d964`, `87ccbe6`, `b034509` (Sprint 8) | [ADR-020](adr/ADR-020-idempotencia-y-atomicidad-del-sellado.md) |
| H9 — la independencia de los golden estaba exagerada | `c92870b` (el oráculo Python), `de794c0` (el último vector) | [ADR-024](adr/ADR-024-material-mldsa-de-los-vectores.md) |
| H10 — la afirmación de privacidad era más amplia que la implementación | `b5eed42` (Sprint 8) | [ADR-023](adr/ADR-023-payload-hash-y-enumeracion.md), PROTOCOL 0.5-draft §5 |
| §2 — el fuzzer no podía aceptar un recibo; el diferencial comparaba un booleano | `5e5ddcd` | — |
| §6 — seis afirmaciones publicadas | enmendadas a la vista en README, PROTOCOL y CHANGELOG (Sprints 7f y 8) | — |

La revisión siguiente, del 2026-09-19 y del mismo auditor, está en
[`auditoria-externa-20260919.md`](auditoria-externa-20260919.md) y comprobó estos cierres
uno por uno.

FIN DEL PREÁMBULO

---

# Revisión técnica de Núcleo — PROTOCOL 0.3-draft

**Conclusión: la maquinaria existente aporta evidencia útil de regresión e interoperabilidad, pero no basta para sostener todas las garantías publicadas.** Encontré puntos ciegos concretos en los catálogos, diferencias entre verificadores y dos rutas de seguridad que merecen prioridad: la vinculación entre la raíz reconstruida y el checkpoint realmente atestiguado, y la reproducción de respuestas antiguas de sincronización.

**Versión revisada:** commit público `1c53e1c61e04931d7941123bf5cbbdb67f7058d6`.

Respetando tu última instrucción, terminé exclusivamente por lectura. **Los hallazgos nuevos que siguen son análisis estáticos, no exploits ejecutados.** Las severidades expresan el impacto de las rutas identificadas; no presento como reproducción experimental lo que no ejecuté.

---

## 1. Evidencia que sí se obtuvo

Antes de detener las ejecuciones:

| Comprobación | Resultado |
|---|---|
| `gofmt -l .` | Sin archivos pendientes de formato |
| `go vet ./...` | Correcto |
| `go test ./... -race` | Todos los paquetes pasaron; incluye el exploit de regresión de `internal/store` y los tests Go de vectores |
| `npm test` | **186 tests**, 8 archivos, correctos |
| Typecheck y compilación TS | Correctos |
| `scripts/demo-criterio-exito.sh` | Los siete pasos pasaron |
| Diferencial: bytes del recibo | **2.741 casos** |
| Diferencial: notas re-firmadas | **148 casos** |
| Diferencial: políticas | **9.929 casos** |
| Resultado diferencial | **0 divergencias booleanas**, 0 excepciones TS |

La ejecución cronometrada del diferencial tomó **2,12 s para generar y evaluar el catálogo Go**, y **4,84 s para contrastarlo con el bundle**.

**No se ejecutaron las tandas adicionales de fuzzing.** La suite normal ejercitó las semillas/corpus que ejecuta `go test`; eso no equivale a una campaña exploratoria con `-fuzz`.

---

# 2. Entregable principal: cobertura ausente

Los tres catálogos tienen una estructura bastante precisa:

- El primero modifica líneas y algunos bytes, **sin reparar las firmas**.
- El segundo modifica el bloque de firmas de la nota y **re-firma el recibo**, conservando su header y su texto visible.
- El tercero modifica textos de políticas, pero compara únicamente **si el parser acepta o rechaza**.

Por tanto, miles de casos no equivalen a miles de clases de ataque independientes.

### Clases que faltan o están insuficientemente cubiertas

| Prioridad | Campo o superficie y transformación ausente | Implementación afectada y por qué no llega el catálogo |
|---|---|---|
| **Alta** | **`checkpoints.tree_size` frente al tamaño del cuerpo firmado:** desalinear el índice SQL de la nota; conservar dos notas con igual tamaño declarado y raíces distintas, una atestiguada y otra solo firmada por el log. | `store`. El diferencial no abre bases de datos. El exploit existente inserta un checkpoint cuyo índice SQL coincide con el tamaño de la nota; no ataca la relación entre los dos selectores de checkpoints. |
| **Alta** | **Respuestas HTTP:** reproducir tanto el GET de monitorización como la respuesta POST `add-checkpoint`, utilizando una cosignature antigua auténtica del estado restaurado. | `logsync` y CLI. `replay_test.go:33–56` reproduce el GET, pero **reenvía el POST al testigo real**. No cubre al adversario que controla ambos sentidos del intercambio. |
| **Alta** | **Header firmado no canónico:** claves duplicadas, espacios, escapes alternativos o miembros adicionales; mantener coherentes firma de bloque, hoja, raíz y firma del recibo. | TS/página frente a Go. El primer catálogo rompe la criptografía; el segundo solo sustituye la nota. Ninguno permite observar qué acepta el validador de header cuando todas las firmas pertinentes son válidas. |
| **Alta** | **`header.index` frente a `proof.index`:** incluir un bloque en una posición distinta del índice que declara, con prueba y firmas coherentes. | Go frente a TS. Los fixtures se producen por la ruta normal, que asigna índices coherentes. Cambiar solo el índice del recibo rompe otras comprobaciones y oculta la comparación ausente. |
| **Alta** | **`header.signer_pubkey` corto**, con política completa y estructura suficiente para llegar al mensaje de discrepancia. | Go. El fuzzer del recibo carece de `SignerKey`; corta antes de alcanzar la ruta peligrosa. |
| **Media** | **`timestamp` con fracción de segundo**, conservando un recibo emitido correctamente por Go. | TS/página. Las escenas usan tiempos fijos a resolución de segundos/minutos: `internal/receipt/receipt_test.go:75–78`. No representan el reloj de producción con nanosegundos. |
| **Media** | **Nombre de testigo `__proto__`** y conservación exacta del mapa tras parsear, serializar y validar de nuevo. | TS/página. Los vectores usan nombres ordinarios; el diferencial compara éxito del parser, no sus miembros resultantes. |
| **Media** | **Política válida → objeto → verificación real del recibo.** Comparar nombres, claves, quórum y comportamiento después de la segunda validación. | Las tres superficies. `sdk/ts/scripts/diferencial.mjs:54–69` descarta el objeto parseado; los tests de política también se centran en aceptación. |
| **Media** | **Bytes originales del archivo:** UTF-8 inválido, BOM y normalización al arrastrar archivos al navegador. | Go frente a la página. El catálogo de políticas trabaja por runas y excluye expresamente bytes UTF-8 rotos (`diferencial_politica_test.go:60–62`). La página llama a `File.text()` antes de validar. |
| **Media** | **Tamaños e índices en los límites de representación**, con verificaciones positivas: fronteras de `2^53`, `int64`, `uint64` y límites de `Date`. | Go/TS. Hay pruebas BigInt, pero las pruebas de inclusión enormes usan caminos inválidos y solo esperan `false`; no acreditan interoperabilidad positiva en esos límites. |
| **Media** | **Timestamps de cosignature válidamente firmados fuera del rango temporal común**, y elección del mínimo. | Go/TS. El catálogo re-firmado usa desfases de −10 minutos y +5 horas, no los límites de conversión de enteros y fechas. |
| **Media** | **Repeticiones de `sync` sin crecimiento durante varios días**, cambio de testigo y acumulación de cosignatures al mismo tamaño. | CLI/store. El test de reintento comprueba que se conserva la primera nota, pero no contrasta esa decisión con el posterior cálculo de frescura. |
| **Media** | **Fallos entre escrituras de `seal`:** después del blob, después del bloque y antes de metadatos/respuesta; repetir la operación. | CLI/store. Los catálogos de formatos no modelan interrupciones, concurrencia entre procesos ni reintentos de negocio. |
| **Media** | **Dictamen estructurado completo:** tiempos, firmantes, firmas ignoradas, clasificación del fallo y datos que sobreviven a un rechazo. | Go/TS/página. El diferencial compara `valid`; si ambos rechazan por causas diferentes, pasa. Tampoco contrasta todos los campos de resultados aceptados. |
| **Media** | **Interacción real del navegador:** cambiar entradas mientras verifica, pulsaciones concurrentes y correspondencia entre lo visible y el resultado terminado. | Página. Los tests ejecutan bundle y funciones en `node:vm`; no ejercitan el ciclo completo de eventos del DOM. |

### Dos limitaciones especialmente importantes del oráculo

#### A. El fuzzer del recibo no puede aceptar ningún recibo completo

En `internal/receipt/fuzz_test.go:22–27`, la política no tiene `SignerKey`.

La ruta acaba exigiéndola en:

- `internal/receipt/receipt.go:336–337`;
- `internal/proof/proof.go:336–340`.

Por ello, las propiedades de la rama de aceptación del fuzzer —incluido el round-trip de `fuzz_test.go:45–63`— **no se alcanzan con esa política**.

No es un problema de ejecutar el fuzzer más minutos: primero hay que hacer alcanzable la ruta.

Además, `FuzzVerifyNote` ejercita `checkpoint.Verify`, **no** `proof.VerifyNote`, donde vive el conteo endurecido de ADR-018 (`internal/checkpoint/fuzz_test.go:128–129`).

#### B. El diferencial no compara dictámenes equivalentes

En `sdk/ts/scripts/diferencial.mjs:49` y `:68`, la condición es desigualdad entre booleanos.

Esto acredita:

> «Ambos aceptan o ambos rechazan estos casos».

No acredita:

> «Ambos interpretan la misma política, autentican los mismos testigos y producen el mismo dictamen».

Para tu criterio de revisión, faltaría un resultado normalizado con categorías de error y campos autenticados comparables. No hace falta exigir mensajes humanos idénticos.

---

# 3. Hallazgos por severidad

## ALTA — H1. El atajo puede quedar ligado a una raíz distinta de la atestiguada

**Referencias:**

- `internal/store/checkpoints.go:59`: selecciona el último checkpoint por `tree_size` SQL.
- `internal/store/checkpoints.go:104–116`: selecciona por separado el último con forma de cosignado.
- `internal/store/integrity.go:325–328`: concede el atajo por la atestación de esa segunda nota.
- `internal/store/integrity.go:713–719`: comprueba su raíz separadamente **solo si los tamaños de ambas notas difieren**.

**Problema:** igualdad de tamaño no implica igualdad de raíz ni identidad de nota. Esa inferencia depende de que las filas hayan entrado por `PutCheckpoint`, pero el modelo de amenaza permite manipulación directa de SQLite.

Si las dos selecciones devuelven notas distintas con el mismo tamaño declarado:

1. La cosignature válida puede respaldar la raíz A.
2. El árbol reconstruido puede contrastarse contra la raíz B de la otra nota.
3. La condición de tamaños iguales omite la comprobación explícita contra A.
4. El resultado conserva `AttestationVerified`.

**Condición relevante:** la variante descrita requiere una nota conflictiva firmada por la clave del log —por ejemplo, un emisor deshonesto o compromiso de esa clave— y escritura en la base. **No exige que el testigo firme la raíz nueva.**

Es precisamente un caso donde la independencia del testigo debería seguir protegiendo.

**Prueba faltante:** desalineación índice SQL/cuerpo firmado y dos checkpoints de igual tamaño con raíces distintas. La apertura debe rechazar antes de conceder el atajo.

---

## ALTA — H2. Pedir otro POST no demuestra que la respuesta sea nueva

**Referencias:**

- `internal/logsync/logsync.go:138–148`: firma y solicita el checkpoint.
- `internal/witness/client.go:155–161`: acepta una cosignature que verifica.
- `internal/logsync/logsync.go:197–209`: contrasta origin, tamaño y raíz.
- `internal/logsync/logsync.go:181–187`: obtiene el tiempo y declara atestación.
- `internal/logsync/replay_test.go:33–56`: el ataque existente deja pasar el POST.

**Problema:** las comprobaciones autentican el contenido histórico, pero no ligan la respuesta a la ejecución actual mediante una garantía de actualidad.

Sobre una copia restaurada que coincide con un checkpoint antiguo, la cosignature antigua sigue verificando sobre el mismo cuerpo. Un intermediario capaz de reproducir GET y POST puede suministrar esa evidencia sin consultar la memoria actual del testigo.

`SyncWithWitness` tampoco rechaza por antigüedad del timestamp; `cmdSync` no aplica la alarma de frescura antes de anunciar éxito.

**Alcance:** afecta al transporte que el atacante pueda controlar, particularmente HTTP sin autenticación de servidor. No implica falsificar Ed25519 ni romper HTTPS correctamente autenticado.

**Prueba faltante:** extender el escenario de replay existente para controlar ambos endpoints y comprobar que una respuesta histórica no acredita contacto actual.

**Afirmación que queda sin sostener:** que impedir la detección mediante red necesariamente sea ruidoso o termine en fallo de sincronización.

---

## MEDIA — H3. Un header malformado puede provocar un pánico en Go

**Referencia principal:** `internal/receipt/receipt.go:342–344`.

Al detectar que el firmante difiere de la política, el mensaje utiliza:

```go
r.Header.SignerPubKey[:16]
```

sin haber comprobado previamente esa longitud.

`Parse` reconstruye el header y compara su canonicalización, pero eso no valida su semántica. Después llega a `renderText` y a esta comparación.

Con una política completa y un `signer_pubkey` menor de 16 caracteres, la ruta puede terminar en **pánico en vez de rechazo**. No hace falta una firma válida para alcanzar el mensaje.

Existe un patrón similar en `internal/store/integrity.go:432–433` al abreviar la clave pública leída de metadatos.

**Por qué escapó:** el fuzzer sin `SignerKey` devuelve antes un error de política.

**Prueba faltante:** entradas malformadas con política válida que alcancen cada mensaje de error; afirmar rechazo sin pánico.

---

## MEDIA — H4. Hay divergencias de header entre Go y TS

### H4.1. Nanosegundos: un recibo normal de Go puede ser rechazado en TS

- Producción usa `time.Now().UTC()`: `cmd/nucleo/hooks_off.go:24`.
- El header conserva nanosegundos: `internal/ledger/block.go:79`.
- Go imprime el tiempo declarado sin fracción: `internal/receipt/format.go:19`, `:169–170`.
- TS re-renderiza el timestamp literal del header: `sdk/ts/src/receipt.ts:610`.
- TS exige igualdad del texto: `sdk/ts/src/receipt.ts:440–445`.

La representación visible no coincide cuando el timestamp firmado lleva fracción.

**Prueba faltante:** recibo end-to-end emitido con timestamp fraccionario, aceptado por Go, SDK y bundle.

### H4.2. TS comprueba orden de claves, no canonicalidad JCS completa

- `sdk/ts/src/receipt.ts:303–306`.
- `sdk/ts/src/jcs.ts:16–28`.

`JSON.parse` seguido de `Object.keys` no detecta por sí solo:

- miembros repetidos;
- espacios no canónicos;
- escapes alternativos;
- miembros adicionales;
- todas las reglas semánticas del header.

Go reconstruye un `ledger.Header`, lo recanonicaliza y exige igualdad: `internal/receipt/format.go:227–239`; además valida el header al formatear, en `:32–34`.

**Consecuencia:** un emisor que produzca bytes no canónicos y firme coherentemente sus artefactos puede llegar a resultados distintos. El catálogo que rompe firmas no comprueba este caso.

### H4.3. Go no exige que el índice declarado sea la posición demostrada

TS compara explícitamente `proof.index` y `headerIndex` en `sdk/ts/src/receipt.ts:433–437`.

La ruta Go `internal/receipt/receipt.go:331–357` verifica firma y hoja y después llama a la prueba, pero no compara `Header.Index` con `Proof.Index`. `internal/proof/proof.go:369–377` valida la posición de la prueba, no el índice interno del header.

**Prueba faltante:** una hoja correctamente firmada incluida en una posición diferente de la que declara su header. Ambos deben rechazar.

---

## MEDIA — H5. TS pierde un testigo llamado `__proto__`

**Referencias:**

- `sdk/ts/src/policy.ts:233`: crea `witnesses` con `{}`.
- `sdk/ts/src/policy.ts:270`: asigna `witnesses[w.nombre] = ...`.
- `sdk/ts/src/policy.ts:272–286`: valida quórum usando el número de miembros leídos.
- `sdk/ts/src/policy.ts:297–307`: serializa y vuelve a parsear.
- Go conserva los nombres en un mapa: `internal/policy/policy.go:339–352`.

`__proto__` es un nombre permitido por la gramática publicada. Sin embargo, sobre un objeto JavaScript ordinario esa asignación encuentra el setter heredado; asignarle la cadena de la clave no crea el miembro esperado.

El parser puede considerar válida la entrada mientras devuelve un mapa que ha perdido ese testigo. La validación posterior o el conteo de firmas cambia entonces el resultado.

**Impacto identificado:** pérdida semántica e interoperabilidad. No atribuyo a esta ruta una reducción silenciosa del quórum: el quórum numérico se conserva.

**Prueba faltante:** comparar el mapa exacto y verificar un recibo cuya política incluya ese nombre, también después del round-trip.

---

## MEDIA — H6. La frescura mezcla «primera evidencia» con «último contacto»

**Referencias:**

- `internal/logsync/adapter.go:96–111`: conserva la primera nota para cada tamaño y descarta las siguientes.
- `internal/logsync/replay_test.go:173–180`: el test exige ese comportamiento.
- `internal/store/integrity.go:365–367`: toma el tiempo de la nota guardada.
- `cmd/nucleo/stale.go:84–92`: con política, usa ese tiempo para frescura.

Con un log sin nuevos bloques:

1. El testigo puede seguir respondiendo correctamente cada hora.
2. La nueva cosignature no sustituye ni complementa la evidencia persistida de ese tamaño.
3. `status --policy-file` sigue calculando antigüedad desde la primera.
4. Acaba sugiriendo que el cron lleva días roto aunque siga funcionando.

Conservar la evidencia más antigua sirve al **tiempo de existencia**. No sirve como única evidencia del **último contacto**.

También limita añadir otro testigo al mismo tamaño: `RecordCosigned` devuelve sin incorporar su nota.

**Prueba faltante:** varias sincronizaciones a tamaño fijo separadas por más del umbral; preservar el tiempo histórico y actualizar una evidencia verificable de actividad reciente.

---

## MEDIA — H7. La comparación de identidad puede omitirse cuando faltan metadatos

**Referencia:** `internal/store/integrity.go:415–435`.

- Si falta `MetaOriginKey`, no falla la comparación de origin.
- Si falla la lectura de `MetaLogPubKey`, devuelve `nil`.

Esto no implementa estrictamente la regla de `PROTOCOL.md:233–235`: las identidades aportadas por la política deben coincidir con las declaradas por el ledger.

**Matiz:** no significa que un ledger sin claves obtenga automáticamente atestación. La ruta de checkpoints puede fallar después. El defecto es tratar «no pude comparar» como «la comparación no presenta problema», especialmente sin checkpoints.

**Prueba faltante:** política completa y ausencia, longitud inválida o error de lectura de cada metadato obligatorio.

---

## MEDIA — H8. El sellado no ofrece reintentos idempotentes ni atomicidad de la operación completa

**Referencias:**

- `cmd/nucleo/seal.go:119–143`: blob → bloque → compromisos, en escrituras separadas.
- `internal/store/blobs.go:37–41`: `INSERT` sin tratamiento idempotente.
- `internal/store/schema.go:13–18`: unicidad global por `payload_hash`.

Consecuencias por lectura:

- Repetir un contenido ya almacenado falla en el blob.
- Si el proceso muere después del blob y antes del bloque, queda un huérfano que bloquea el reintento normal.
- Si falla después del bloque, puede comunicar error aunque el registro ya esté sellado.
- Con `--no-encrypt`, desaparece ese obstáculo, pero un reintento puede añadir otro bloque.
- El identificador del blob no incluye tenant, aunque el cifrado sí lo vincula al tenant mediante AAD.

La observación del código «sobra un blob […] inofensivo» es demasiado fuerte: puede ser inocuo para la cadena, pero no para la recuperación operativa.

**Prueba faltante:** fallo en cada frontera de escritura, reintento del mismo evento y sellado de contenido idéntico por tenants distintos.

---

## MEDIA — H9. La independencia de los golden está exagerada

**Referencias:**

- Afirmación universal: `README.md:167`.
- Generación: `internal/receipt/vectors_export_test.go:64–118`.
- Escritura de fixtures durante el test: `:149–165`.

Los recibos golden y sus valores esperados se producen usando `Format`, `LeafData`, `DeclaredTime` y `ProvableTime` del propio proyecto. El test escribe esos archivos y después comprueba los valores que acaba de generar.

Esto sirve como fixture de interoperabilidad, pero **no como oráculo independiente de la implementación Go**. Un error compartido puede trasladarse al fixture.

Los vectores oficiales de primitivas y los calculados externamente siguen siendo valiosos; la objeción es a **«Every golden value»**, no a toda la suite.

**Prueba faltante:** recibos completos calculados externamente, inmutables durante los tests, y comprobación explícita de que ejecutar la suite no modifica los vectores.

---

## MEDIA — H10. La afirmación de privacidad es más amplia que la implementación

**Referencias:**

- `README.md:125`.
- `docs/PROTOCOL.md:274–275`.
- `docs/adr/ADR-003-compromisos-vrf-hmac.md:40–42`.
- `cmd/nucleo/seal.go:103–110`.
- `internal/ledger/block.go:82`.
- `cmd/nucleo/profile.go:49–76`.

El header publica **SHA-256 de los bytes completos del payload**. Los HMAC de campos sensibles se guardan aparte, en `vault_meta`, y no forman parte del header firmado.

Por tanto:

- Un payload completo de baja entropía sigue permitiendo comparación por diccionario.
- Si casi todo el documento es conocido, también puede quedar un espacio pequeño de candidatos.
- Añadir HMAC de campos no elimina ese canal.
- La asociación de los metadatos por `payload_hash` no equivale a incorporar sus bytes a la raíz atestiguada.

**Prueba faltante:** casos de privacidad a nivel de documento completo, además de tests unitarios del HMAC.

No propongo cambiar aquí el formato: existe una tensión entre la regla de hash exacto y la garantía universal de privacidad que requiere una decisión de protocolo.

---

# 4. Conformidad con §3.2 y §3.3

## Política — §3.2

| Regla | Evaluación |
|---|---|
| Objeto único, miembros exactos, duplicados tras desescapar | Implementada en ambos parsers |
| Rechazar `null`, variantes de mayúsculas y contenido posterior | Implementado |
| Hexadecimal minúsculo de 64 caracteres | Implementado en los parsers de política |
| Quórum literal entero, positivo y alcanzable | Implementado |
| No reutilizar una clave bajo dos nombres de testigo | Implementado |
| Conservar todos los nombres admitidos | **Incumplimiento TS: `__proto__`** |
| `signerKey` obligatorio para verificar recibos | Implementado en las puertas de recibo |
| Comparar origin y logKey al abrir con política | **Incompleto ante metadatos ausentes/ilegibles** |
| UTF-8 sin BOM, aplicado a los bytes del archivo | Go lo aplica; la página decodifica antes, por lo que falta equivalencia en la frontera de archivos |

## Bloque de firmas — §3.3

**En la ruta de recibos**, la implementación principal está razonablemente alineada:

- TS aplica estructura, controles, nombres, base64 canónico y máximo de 100 líneas en `sdk/ts/src/note.ts:88–123`.
- Go valida inicialmente mediante `checkpoint.Verify`/`x/mod` y luego recorre todas las líneas en `internal/proof/proof.go:205–241`, endureciendo base64 y límites en `:285–315`.
- Ambos vuelven a exigir que toda firma de clave conocida verifique.
- Ambos cuentan una sola vez cada testigo.
- Ambos buscan el tiempo más temprano.

**No identifiqué por lectura una nueva evasión de duplicación del quórum en esa ruta.** Los casos existentes también pasaron.

Pero hay dos reservas:

1. **La regla no está unificada en todos los consumidores.**  
   `witness.Client.CosignatureTime`, en `internal/witness/client.go:89–106`, usa directamente `note.Open` y toma la primera firma aceptada. No aplica el recorrido endurecido de ADR-018 ni el mínimo de todas las repeticiones. Una respuesta puede ser aceptada por el cliente de sincronización y rechazada posteriormente por `proof.VerifyNote`.

2. **Las conversiones temporales no comparten rango.**  
   Go convierte `uint64` a `int64` en `internal/witness/cosignature.go:160`; TS usa `BigInt` y después `Number`/`Date` en `sdk/ts/src/receipt.ts:623–628`. Falta un dominio temporal común y vectores firmados en sus fronteras.

También divergen los rangos de índices/tamaños: Go usa `uint64` y después límites de `int`; TS admite `BigInt` sin el mismo techo en sus parsers.

---

# 5. Qué demuestra realmente la cadena de confianza

| Eslabón | Ancla |
|---|---|
| Documento recibido → `payload_hash` | Comparar externamente el hash del documento con el del recibo; el verificador del recibo no recibe el documento |
| Header → firma de bloque | `policy.signerKey`, traída de fuera |
| Firma del recibo → destinatario y texto | La misma clave esperada del emisor |
| Bloque → hoja `leaf/v2` | Hash del header y firma del bloque |
| Hoja → raíz | Prueba de inclusión y posición |
| Raíz → log esperado | `policy.origin` y `policy.logKey` |
| Checkpoint → testigos aceptados | Claves y quórum de la política |
| Claves → entidades reales e independientes | **Distribución autenticada de la política y decisiones organizativas externas** |
| Evidencia histórica → estado actual/completo | **No lo establece un recibo offline por sí solo** |

La conclusión justificable es:

> Este bloque, firmado por la clave esperada, está incluido en este checkpoint, avalado por estos testigos bajo esta política.

No equivale automáticamente a:

> Esta es toda la historia actual, todos sus bloques son semánticamente válidos y los testigos son organizaciones independientes.

**El ancla que sigue fuera del teorema es la procedencia de la política.** Si recibo y política llegan juntos por un canal no autenticado y ambos se aceptan como autoridad, la cadena puede ser autoconsistente sin identificar a quien el usuario cree.

Y en H1 aparece otra dependencia indebida: se usa la coherencia de índices del propio archivo para inferir que dos checkpoints de igual tamaño son el mismo compromiso.

---

# 6. Afirmaciones publicadas que necesitan corrección o precisión

Sí: quedan más afirmaciones problemáticas.

| Afirmación | Contraste |
|---|---|
| **«Every golden value … is computed outside the code under test»** — `README.md:167` | **Falsa como afirmación universal:** los golden completos de recibos se generan con el código Go bajo prueba. |
| **El ledger nunca publica hashes desnudos de valores adivinables** — `README.md:125` | **Demasiado amplia:** siempre hay SHA-256 del payload completo; HMAC de campos no neutraliza documentos enumerables. |
| **El adversario de red solo impide detección de forma ruidosa** — `README.md:217`, ADR-011:189–201 | **No respaldada por la ruta actual:** falta cubrir la reproducción de la respuesta POST, además del GET. |
| **La frescura expresa cuándo vio por última vez un tercero esta historia** — `docs/CLI-JSON.md:54–78` | **No siempre:** a tamaño fijo se conserva la primera cosignature. |
| **El recibo y su política eliminan el intercambio fuera de banda** — `PROTOCOL.md:185–190` | Solo si la política ya está autenticada. El propio README posterior explica mejor esta condición. |
| **Borrar el blob satisface derechos de supresión** — `README.md:67`, `PROTOCOL.md:275` | No se deduce solo de un `DELETE`: quedan política de backups, copias, retención de claves y posible enumerabilidad del hash. Es una conclusión demasiado absoluta. |

La contradicción documental más directamente demostrable por lectura es la de **la generación independiente de todos los golden**.

---

# 7. Riesgos de diseño y operación que deben quedar explícitos

### Restauración

`cmd/nucleo/backup.go:60–112` reconstruye la KEK y comprueba que desenvuelve la DEK del vault. **No restaura la historia, no recupera bloques perdidos y no configura una nueva passphrase para continuar operando.**

Una copia antigua de SQLite con evidencia antigua auténtica puede seguir verificando como prefijo histórico. Hace falta una comprobación contra memoria externa actual antes de confundirla con la historia vigente.

Debe existir un procedimiento de recuperación probado que distinga:

- recuperación de claves;
- recuperación de archivos;
- detección de rollback;
- reanudación del servicio.

### Cron detenido

Los avisos se producen **cuando alguien ejecuta un comando**. Si dejan de correr cron y aplicación, no hay un proceso autónomo que avise.

Además, `status` y `verify` mantienen salida 0 ante atestación vieja: está documentado y no es por sí mismo un bug. La integración debe interpretar el estado de atestación, cobertura, frescura y desfase de reloj, no solo `ok`.

El envío de stderr por correo depende de la configuración real de cron/MTA.

### Red del testigo

Hay límite de cuerpo de 64 KiB en `internal/witness/server.go:38`, pero el servidor de la CLI se crea sin tiempos límite en `cmd/nucleo/sync.go:231`.

**Riesgo de disponibilidad:** clientes lentos y conexiones retenidas. El límite de bytes no limita el tiempo. Deben documentarse las condiciones para exponerlo en red y el uso de transporte autenticado.

### Errores y salida

- `internal/witness/server.go:90–92` devuelve errores internos en respuestas HTTP.
- `internal/witness/client.go:172–173` propaga cuerpos del servidor.
- `internal/receipt/format.go:303–304` incluye texto completo del recibo en algunos errores.
- `cmd/nucleo/env.go:49–51` informa de fallos al escribir JSON, pero no los propaga al código de salida.

No he identificado una fuga concreta de clave privada por estas rutas. Sí existen riesgos de exposición de contenido en logs y de éxito de proceso con salida no entregada.

### Quórum e independencia

Varias claves distintas no prueban varios operadores independientes. Asimismo, tomar el **mínimo** de los tiempos aceptados significa que un testigo aceptado que antedate puede influir en la fecha aunque otros sean honestos. El quórum no convierte automáticamente ese mínimo en una fecha tolerante a testigos maliciosos.

### Límites adicionales

Deben quedar claros:

- integración transaccional con el ERP y tratamiento de eventos nunca enviados;
- autenticación, versionado y distribución de políticas;
- rotación/revocación de claves y conservación de políticas históricas;
- protección y recuperación de la memoria del testigo;
- ausencia de prueba offline de actualidad o completitud global;
- alcance limitado de ML-DSA: firma adicional, no cadena poscuántica completa.

---

# Dictamen final

**Núcleo tiene una base de pruebas útil y las regresiones revisadas pasan. El problema principal es que el alcance de algunas garantías supera lo que esas pruebas ejercitan.**

El orden que recomiendo para preparar una auditoría profesional es:

1. **Cerrar o refutar mediante regresión H1 y H2:** raíz realmente atestiguada y actualidad de sincronización.
2. **Corregir el pánico y las diferencias de header:** nanosegundos, JCS, índice declarado/posición demostrada.
3. **Comparar semántica, no solo booleanos:** políticas parseadas y dictámenes completos.
4. **Hacer alcanzable el fuzzer de recibos y separar fixtures generados de golden independientes.**
5. **Definir reintentos, frescura a tamaño fijo y recuperación operativa.**
6. **Ajustar las afirmaciones de privacidad, completitud e independencia a sus condiciones reales.**

Ese trabajo aumentaría la confianza de forma medible. **Añadir más mutaciones del mismo tipo, sin corregir estas ausencias, aumentaría principalmente el contador.**
