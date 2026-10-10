<!--
Este preámbulo lo añade el repositorio; el informe empieza donde lo dice y no se ha
tocado una coma. Si alguna vez hay que separar las dos cosas, el corte es la línea
"FIN DEL PREÁMBULO".
-->

# Nota de procedencia

**Versionado el 2026-10-10 desde el clon donde lo escribió el modelo**, que esta vez seguía en
`/tmp/opencode/nucleo-20261010/`. Se contrastó con la base de la sesión de OpenCode
(`opencode.db`, leída de una copia): el fichero en disco es **idéntico byte a byte** al texto
del parche con el que el modelo lo creó (`apply_patch`, *Add File*), y coincide línea a línea
—las 255— con la lectura que el propio modelo hizo de él un minuto después. No hay ninguna
otra escritura sobre él en la sesión.

| | |
|---|---|
| **Modelo** | `gpt-5.5` (OpenAI), vía OpenCode 1.15.12 |
| **Sesión** | «Auditoría adversarial de criptografía», `ses_f871559b1ffeqreA4WwQzx7F8F` |
| **Encargo** | 2026-10-10 18:45 UTC: contrastar `docs/GARANTIAS.md` y `docs/ARQUITECTURA.md` contra el código y los tests, sobre un clon nuevo en el commit `2c592f0` |
| **Instante del informe** | 2026-10-10 19:50 UTC (`prt_1275da31c001xab8eYMHXPkZjI`) |
| **Commit revisado** | `2c592f0` |
| **Método** | ejecutó `go test ./... -race`, la suite de TypeScript y el criterio de éxito; **no** la suite de PHP, el diferencial ni el ensayo del testigo mutuo, y el propio informe lo dice |
| **Longitud** | 17.652 caracteres, 255 líneas |

## Dónde se cerró cada hallazgo

Triaje del Sprint 17. Cada hallazgo se contrastó con el código antes de aceptarlo; ninguno
resultó falso, uno tenía razón solo a medias.

| hallazgo | veredicto del triaje | dónde se cerró |
|---|---|---|
| **ALTA** — con `--out`, `receipt` escribe el recibo antes de autoverificarlo | **con razón**: el orden era escribir y después verificar | `5c7f821`: verifica primero y escribe de forma atómica (`cmd/nucleo/seal.go#entregaRecibo`); `cmd/nucleo/entrega_test.go#TestUnReciboQueNoVerificaNoSeEscribe` falla con el orden viejo. Una verificación que falle de verdad no se puede provocar desde fuera —un testigo equivocado falla antes, al emitir—, así que el test la inyecta, y el commit lo dice |
| MEDIA — el flujo de `receipt` misatribuye pasos | **con razón**: faltaba el desbloqueo, y la firma la hace `Issue` (`internal/receipt/format.go#Sign`), no `Format` | `906421f`, ARQUITECTURA §2.4 |
| MEDIA — el orden de verificación no es común a los tres verificadores | **con razón**: Go para en el primer fallo; PHP acumula motivos y compara el texto al final | `906421f`, ARQUITECTURA §2.5: «las mismas propiedades», no «el mismo orden» |
| MEDIA — «tres verificadores» depende de PHP | **con razón a medias**. La afirmación ya estaba documentada con su receta (README, CONTRIBUTING), y el job `diferencial` del CI la comprueba en cada push con `NUCLEO_DIFERENCIAL_EXIGE_PHP=1`. Lo que sí faltaba: G13 no lo decía, y la compuerta local era una lista copiada a mano | `906421f`: G13 lo dice; Sprint 17: `scripts/compuerta.sh` corre la suite de PHP y el diferencial con PHP exigido, y falla sin PHP |
| MEDIA — GARANTIAS no recoge afirmaciones de PROTOCOL y del README | **con razón** | GARANTIAS §3, nueva: las veinte afirmaciones de la lista del informe, cada una con su estado comprobado —con test, sin test, sin implementar o límite—, y L19 con «nadie lo usa en producción». PROTOCOL §3, §6 y §9 llevan además enmiendas a la vista con lo que no está implementado (`811c63f`) |
| BAJA — `sync`, `verify`, `reconcile` y el testigo, imprecisos | **con razón, las cuatro** | `906421f`: `validaURLDeTestigo` primero y `ClearRollback` antes de `PutLastCosignature` (§2.3); `checkLeafRule` en `store.open`, antes de `VerifyIntegrity` (§2.5); JSONL perezoso y `--full` activado por omisión (§2.6); clave nueva `O_EXCL 0600` frente a `checkKeyPerms` para la existente, y `ErrOldSize` antes de `Advance` (§2.8) |
| Tabla de flujos: a §2.2 `seal` le faltaban la búsqueda de duplicados y la relectura de la idempotencia en cada intento | **con razón** | ARQUITECTURA §2.2, paso 6 |
| Veredictos G22 y L18: la supresión no tenía comando | **con razón**, y era el hallazgo 1 del Sprint 16 | `dc15885`: `nucleo erase` y ADR-031; G22 y L18 actualizados, G38–G40 nuevas |
| Veredictos G35, G36 y G37: «sin test» | ya lo decía GARANTIAS | nada que cambiar: el informe confirma lo que el documento declara |

FIN DEL PREÁMBULO

---

# Revisión externa técnica — garantías y arquitectura

Proyecto: `github.com/nucleoledger/nucleo`.

Commit revisado: `2c592f0`.

Clon: `/tmp/opencode/nucleo-20261010`.

Fecha: 2026-10-10.

Alcance: contraste documental de `docs/GARANTIAS.md`, `docs/ARQUITECTURA.md`, `README.md` y `docs/PROTOCOL.md` contra código y tests existentes. No se generaron entradas manipuladas nuevas.

## Ejecutado

```text
go test ./... -race
```

Resultado: pasa.

```text
npm ci && npm test
```

Directorio: `sdk/ts`.

Resultado: pasa. `8` ficheros, `197` tests.

Nota: `npm test` sin `npm ci` falló primero con `vitest: not found`; faltaban dependencias instaladas en el clon limpio.

```text
./scripts/demo-criterio-exito.sh /tmp/opencode/nucleo-demo-20261010
```

Resultado: pasa. Los 7 pasos del criterio de éxito terminan en verde.

No ejecuté `sdk/php/test/run.php`, el diferencial completo ni `scripts/ensayo-testigo-mutuo.sh`, porque no estaban en la maquinaria solicitada explícitamente para esta revisión. Cuando una garantía depende de esos artefactos, el veredicto distingue esa cobertura.

## Hallazgos por severidad

### Alta — `ARQUITECTURA.md` afirma un orden falso en `receipt --out`

Archivo y funciones:

- `docs/ARQUITECTURA.md`, flujo 2.4 `receipt`
- `cmd/nucleo/seal.go#cmdReceipt`
- `internal/receipt/format.go#Receipt.Verify`

El flujo 2.4 dice: “Antes de entregarlo, lo verifica”. Eso no es cierto para el camino con `--out`: el comando escribe el recibo al fichero antes de llamar a `Receipt.Verify`. Si la autoverificación fallara, ya existiría un artefacto entregable en disco.

Comando que lo cubre parcialmente:

```text
go test ./cmd/nucleo -run Receipt -race
```

Qué falta: un test específico que fuerce fallo de autoverificación tras escribir, o mejor, reordenar el código para verificar antes de escribir y testear ese orden. Si se decide que el orden actual es aceptable, `ARQUITECTURA.md` debe decir “lo escribe y luego lo verifica” para `--out`.

### Media — `ARQUITECTURA.md` misatribuye pasos de `receipt`

Archivo y funciones:

- `docs/ARQUITECTURA.md`, flujo 2.4
- `cmd/nucleo/seal.go#cmdReceipt`
- `cmd/nucleo/env.go#env.unlock`
- `internal/receipt/receipt.go#Issue`
- `internal/receipt/format.go#Format`
- `internal/receipt/format.go#Sign`

El flujo omite que `receipt` desbloquea el vault y carga la identidad para firmar el recibo. También atribuye a `Format` la firma del recibo entero; en el código, `Issue` llama a `Sign` después de formatear.

Impacto: el mapa hace parecer que emitir un recibo es solo store/proof/format, cuando en realidad toca la ruta de claves del emisor.

Prueba faltante: no hace falta un test funcional nuevo si se corrige el mapa; el código ya se ejercita en tests de recibos. Falta que `mapa_test.go` o una revisión documental futura compruebe atribución, no solo existencia.

### Media — `ARQUITECTURA.md` muestra un orden común de verificación de recibos que no es común a los tres verificadores

Archivo y funciones:

- `docs/ARQUITECTURA.md`, flujo 2.5.b
- `internal/receipt/format.go#Receipt.Verify`
- `sdk/ts/src/receipt.ts#verifyReceipt`
- `sdk/php/src/Verifier.php#Verifier::verify`

El documento dice que los tres verificadores hacen “lo mismo” y lista el orden: firma del emisor, firma del bloque/hoja, nota/quórum, inclusión. La verificación de Go, TS y PHP sí converge en el dictamen, pero no ejecuta exactamente los mismos pasos en ese orden. En TS/PHP se acumulan comprobaciones de bloque, nota, inclusión y texto en un flujo que no corresponde a esa secuencia común estricta.

Impacto: no es bug criptográfico si los dictámenes coinciden, pero el mapa de arquitectura exagera la igualdad operacional.

Prueba faltante: no conviene probar orden interno salvo que sea contrato. La corrección adecuada es cambiar el texto a “comprueban las mismas propiedades” y no “los tres hacen lo mismo” paso a paso.

### Media — La afirmación “tres verificadores independientes” depende de PHP, pero la ruta local solicitada solo ejecuta dos

Garantía relacionada: G13.

Archivos:

- `docs/GARANTIAS.md:36`
- `README.md:108-116`
- `sdk/ts/scripts/diferencial.mjs`
- `sdk/php/test/run.php`

El repositorio documenta correctamente que para reproducir la afirmación de tres verificadores se necesita PHP con `ext-sodium` y configuración que haga fallar si PHP falta. En esta revisión solo se ejecutaron Go y TS; PHP no formaba parte de los comandos pedidos.

Veredicto documental: G13 **DEMUESTRA EN PARTE** si se evalúa solo con `go test`, `npm test` y demo; demuestra completamente solo si también se ejecuta la suite PHP y el diferencial con PHP exigido.

Prueba faltante para la afirmación local: ejecutar `php sdk/php/test/run.php` y el diferencial con `NUCLEO_DIFERENCIAL_EXIGE_PHP=1` en CI/local.

### Media — `GARANTIAS.md` no incorpora varias afirmaciones normativas de `PROTOCOL.md`

Archivos:

- `docs/GARANTIAS.md`
- `docs/PROTOCOL.md`
- `README.md`

Faltan o están solo parcialmente representadas afirmaciones materiales: SLSA/npm provenance, modo de despliegue “un binario, sin daemon/base externa” frente al daemon opcional en PROTOCOL, PRAGMA SQLite/WAL/synchronous=FULL/single writer, detalles de C2SP wire format, límites de índice `2^53-1`, timestamps UTC sin fracción, formato exacto de signed-note §3.3, distribución autenticada de la política, TSA tokens mencionados en PROTOCOL, reglas futuras de leaf-version/segmentos, identidad rotation y tlog-tiles.

Impacto: `GARANTIAS.md` es útil, pero todavía no es un índice completo de todas las afirmaciones de README/PROTOCOL. Algunas claims pueden derivar sin que el test de mapa lo detecte.

Prueba faltante: ampliar `GARANTIAS.md` o añadir una sección “claims normativos no garantizados todavía” para esos puntos.

### Baja — `ARQUITECTURA.md` tiene imprecisiones menores en `sync`, `verify`, `reconcile` y witness

Archivos y funciones:

- `docs/ARQUITECTURA.md`, flujos 2.3, 2.5, 2.6, 2.8
- `cmd/nucleo/sync.go#cmdSync`
- `cmd/nucleo/testigo_errores.go#validaURLDeTestigo`
- `internal/store/store.go#open`
- `internal/store/integrity.go#Store.VerifyIntegrity`
- `cmd/nucleo/reconcile.go#cmdReconcile`
- `internal/reconcile/reconcile.go#Reconcile`
- `cmd/nucleo/sync.go#witnessKey`
- `internal/witness/witness.go#Witness.cosign`

Detalles:

- `sync`: falta el prepaso de validación de URL; el documento pone `ClearRollback` después de `PutLastCosignature`/`PutLastAttested`, pero el código limpia rollback antes de esos registros.
- `verify`: el documento ubica `checkLeafRule` dentro de `VerifyIntegrity`; el código lo llama en `store.open` antes de `VerifyIntegrity`.
- `reconcile`: el documento simplifica el orden; el código construye una fuente JSONL lazy, carga bloques y luego procesa registros vivos. Además `--full` corre por defecto salvo que se desactive, no solo “con `--full`”.
- witness: `witnessKey` comprueba permisos de clave existente; la clave nueva se crea 0600, no pasa por el mismo `checkKeyPerms`. En `Witness.cosign`, algunas comprobaciones de tamaño/estado preceden a `PersistentState.Advance` y no ocurren exactamente como el texto sugiere.

Impacto: bajo. Son errores de mapa, no de implementación.

## Veredictos G1-G37

| garantía | veredicto | nota |
|---|---|---|
| G1 | DEMUESTRA | Vectores JCS Go/TS cubren canonicalización RFC 8785 citada. |
| G2 | DEMUESTRA | Tests de cadena y sabotajes cubren firma/encadenado y alteración. |
| G3 | DEMUESTRA | Vectores RFC 6962/9162 cubren inclusión y consistencia en Go/TS. |
| G4 | DEMUESTRA | Leaf/v2 y firma inválida bajo atestación prueban que la raíz fija firma. |
| G5 | DEMUESTRA | Triggers append-only están probados. |
| G6 | DEMUESTRA | Exploit de checkpoint falso y apertura atestiguada cubren “solo si verifica con claves externas”. |
| G7 | DEMUESTRA | Reescritura autofirmada, política vacía y cadena ajena con política están cubiertas. |
| G8 | DEMUESTRA EN PARTE | Go/TS y vectores de política están fuertes; PHP depende de ejecutar `sdk/php/test/run.php`/CI con PHP. |
| G9 | DEMUESTRA | Witness rechaza historia reescrita. |
| G10 | DEMUESTRA EN PARTE | Tests cubren rollback local y alarma persistente; el ensayo mutuo citado no se ejecutó en esta revisión y parte de la prueba de potencia sigue como script/CI. |
| G11 | DEMUESTRA | `Log.Sign` y durable lock cubren no firmar dos raíces por tamaño, incluso muerte entre firmar/cosignar. |
| G12 | DEMUESTRA | Test HTTP cubre memoria persistente tras reinicio. |
| G13 | DEMUESTRA EN PARTE | Go/TS/demo ejecutados; la frase “tres verificadores” exige PHP y diferencial con PHP. |
| G14 | DEMUESTRA | Tests cubren ambos relojes, sin cosignature y cosignature no confiable. |
| G15 | DEMUESTRA | Destinatario cubierto y caso de destinatario que imita firma están cubiertos. |
| G16 | DEMUESTRA | Resolución temporal cubierta. |
| G17 | DEMUESTRA | Idempotencia, atomicidad y dos workers cubiertos. |
| G18 | DEMUESTRA | HMAC inútil sin clave y compromisos del perfil cubiertos. |
| G19 | DEMUESTRA | AAD de blob atado a tenant y payload hash cubierto. |
| G20 | DEMUESTRA | Golden Argon2id y fallo ruidoso de DEK corrupta/ajena cubiertos. |
| G21 | DEMUESTRA | Round-trip antes de devolver tarjetas y vectores SLIP-0039 cubiertos. |
| G22 | DEMUESTRA EN PARTE | Biblioteca prueba borrado sin romper ledger/recibos; el propio documento acota que no hay comando CLI. |
| G23 | DEMUESTRA | ML-DSA adicional y compatibilidad hacia atrás cubiertas. |
| G24 | DEMUESTRA | H7 cubre que comparación imposible no se da por buena. |
| G25 | DEMUESTRA EN PARTE | Vectores y clases de error cubren contrato; no prueba exhaustivamente “todo error posible” fuera de los casos vectorizados. |
| G26 | DEMUESTRA | Alarma persistente hasta cierre y seal que sigue sellando están cubiertos. |
| G27 | DEMUESTRA | Frescura con política no cae al registro local y sale de cosignature. |
| G28 | DEMUESTRA | Restore con passphrase nueva e interrupciones cubiertos. |
| G29 | DEMUESTRA | Multi-log, retiro, memoria y clave incorrecta cubiertos. |
| G30 | DEMUESTRA EN PARTE | El script de ensayo fija el flujo; no lo ejecuté aquí y no es `go test`. |
| G31 | DEMUESTRA | Reconcile detecta factura alterada. |
| G32 | DEMUESTRA | Dígito verificador golden y rechazo CLI cubiertos. |
| G33 | DEMUESTRA | Test de packaging TS cubre ausencia de dependencias runtime. |
| G34 | DEMUESTRA | Test compila binario sin `testhooks` y rechaza variables. |
| G35 | NO DEMUESTRA | El documento dice “sin test”; es verificación manual de release. |
| G36 | DEMUESTRA EN PARTE | La firma ocurre en workflow/release y verificación manual; no hay test local del repo. |
| G37 | DEMUESTRA EN PARTE | Bundle da mismo veredicto, pero no hay test de “sin red”. |

## Veredictos L1-L19

| límite | veredicto | nota |
|---|---|---|
| L1 | bien acotado | Correcto: sin memoria del testigo no hay rollback detectable. Matiz: parte del ensayo de potencia sigue no automatizada. |
| L2 | bien acotado | Testigos compinchados/controlados queda correctamente declarado; no es testeable como propiedad interna. |
| L3 | bien acotado | Control total sin recibos externos es límite real. |
| L4 | bien acotado | Replay con log parado y atestación que no rejuvenece está bien descrito. |
| L5 | bien acotado | Verdad del contenido queda fuera por construcción. |
| L6 | bien acotado | Compromiso antes del sellado puede impedir evidencia correcta; límite real no parece más estrecho. |
| L7 | bien acotado | `payload_hash` confirma documentos enumerables; límite está bien explicado. |
| L8 | bien acotado | Recibo no prueba entrega ni unicidad de recibo por destinatario. |
| L9 | bien acotado | Sin política, frescura local no verificada. |
| L10 | bien acotado | Testigos no verifican firmas de bloques; la política/recibos hacen esa parte. |
| L11 | bien acotado | Cambio de passphrase no rota DEK ni claves; además está testado el caso de `seal` ya desbloqueado. |
| L12 | bien acotado | Correcto: copias anteriores siguen abriendo con material viejo. |
| L13 | bien acotado | Borrado de memoria no es garantía absoluta. |
| L14 | bien acotado | ML-DSA cubre solo firma adicional del log, no testigos ni cadena end-to-end. |
| L15 | bien acotado | VRF no implementado y no da privacidad si publica prueba. |
| L16 | bien acotado | Acta SAS modelada pero no CLI; README ya lo matiza. |
| L17 | bien acotado | Operativamente correcto: si el testigo mutuo de la otra empresa cae, tu alarma suena por algo que no controlas. |
| L18 | bien acotado | Supresión técnica existe en biblioteca, no CLI, y no es dictamen legal. |
| L19 | bien acotado | No hay auditoría profesional; README además añade no producción. |

## Flujos de `ARQUITECTURA.md`

| flujo | veredicto | diferencias |
|---|---|---|
| 2.1 `init` | coincide | Hay preflight de directorio/db y perfil KDF antes de leer/crear, pero no contradice el flujo. |
| 2.2 `seal` | coincide en lo esencial | Omite detalles útiles: búsqueda de duplicados y relectura de idempotencia dentro de cada reintento. |
| 2.3 `sync` | coincide en parte | Falta validación de URL; `ClearRollback` está documentado después de registros de atestación, pero el código lo hace antes. |
| 2.4 `receipt` | no coincide del todo | Omite unlock/identidad; atribuye firma a `Format`; afirma verificar antes de entregar aunque con `--out` se escribe antes de verificar. |
| 2.5 `verify` | coincide en parte | `checkLeafRule` ocurre antes de `VerifyIntegrity`; orden común de verificación de recibos no es exacto para Go/TS/PHP. |
| 2.6 `reconcile` | coincide en parte | JSONL es lazy; el orden real carga bloques y procesa live records; `--full` corre por defecto salvo desactivación. |
| 2.7 `restore --new-passphrase` | coincide | El flujo refleja código y tests de ADR-029. |
| 2.8 witness serve | coincide en parte | Permisos de clave nueva vs existente y orden interno de `Witness.cosign` están simplificados. |
| 2.9 retire log | coincide | Pasos se ajustan al código. |
| 2.10 testigo mutuo | coincide | Describe correctamente el ensayo/script. |

## Claims README/PROTOCOL fuera de `GARANTIAS.md`

Estos claims son materiales y no aparecen, o aparecen solo parcialmente, en `GARANTIAS.md`:

- `README.md:11-13`, `README.md:337-340`: no auditoría profesional y nadie en producción. L19 cubre auditoría, no producción.
- `README.md:30-33`: SLSA provenance y npm provenance/`npm audit signatures`; G35/G36 cubren rebuild/cosign solo parcialmente.
- `README.md:69` y `PROTOCOL.md:326-330`: un binario/sin daemon/sin base externa frente a daemon opcional en PROTOCOL. Falta garantía/límite de modo de despliegue.
- `PROTOCOL.md:322-324`: SQLite pure-Go, WAL, `synchronous=FULL`, single writer y triggers como guardrail. G5 cubre solo triggers.
- `README.md:83-92`: códigos de salida y `--json` sin prosa. G25 cubre JSON, pero no todos los códigos como contrato.
- `README.md:98`, `PROTOCOL.md:125-131`: full HTTP witness protocol, monitoring endpoint, QR con URL+entry hash. Cobertura parcial.
- `PROTOCOL.md:127-129`: reglas exactas de checkpoint, origin line, key IDs 0x01/0x04/0x06, persistencia atómica del witness antes de responder. Cobertura parcial.
- `PROTOCOL.md:29-43`: índice `≤ 2^53-1`, UTC `Z`, no fracción al firmar, aceptación legacy de fracción, rechazo de offsets, orden por índice y no por reloj. G2/G16 cubren solo parte.
- `PROTOCOL.md:47`: convención de consistency same-size, nodos base64 y raíces exactas de 32 bytes. G3 cubre Merkle general, no todo wire format.
- `PROTOCOL.md:111-121`: reglas futuras de versión de hoja y migración de segmentos. G4 cubre solo leaf/v2 actual.
- `PROTOCOL.md:144-215`: recibo con texto re-renderizado byte a byte, aviso legal protegido, encoding exacto de sección machine y relación firma/política. G13/G15 cubren parte.
- `PROTOCOL.md:197-203`: política debe llegar autenticada por otro medio. G7 no lo declara como límite específico.
- `PROTOCOL.md:252-275`: gramática estricta del bloque signed-note y conteo de cosignatures. Cobertura parcial por G8/G14.
- `PROTOCOL.md:280`: provable time menciona RFC 3161 TSA si se configura. No aparece como garantía ni límite; si no está implementado, debería ser límite/pending.
- `PROTOCOL.md:285-302`: documentos externos byte-for-byte, JSON de perfiles JCS, importes/IDs como strings, perfiles con 16 bytes aleatorios, integradores deberían aportar entropía, Núcleo no debe añadirla. G18/L7 cubren parte.
- `PROTOCOL.md:315`: umbrales SLIP-0039 2-de-3 / 3-de-5. G21 cubre round-trip, no política de umbrales.
- `PROTOCOL.md:316`: rotación de identidad y recuperación de llave perdida. No aparece como garantía ni límite; si no existe, debe figurar como pendiente.
- `PROTOCOL.md:131`, `PROTOCOL.md:320`: segmentos archivados/tlog-tiles y consistencia entre segmentos. No aparece.
- `README.md:106`: PHP sin Composer, solo `ext-sodium`, escrito desde spec. G13 cubre veredicto, no dependencia/independencia PHP.
- `PROTOCOL.md:334`: legal/compliance out of scope, “designed to align with” y nunca “certified”. L5/L18/L19 cubren partes, no el claim de certificación.

## Conclusión

`GARANTIAS.md` cumple bien su función como mapa inicial: la mayoría de garantías fuertes están respaldadas por tests concretos. Las zonas más débiles no son criptografía central sino alcance del mapa: garantías que dependen de scripts/CI/manual release, la afirmación de tres verificadores sin ejecutar PHP localmente, la ausencia de test “sin red” para la página, y claims normativos de PROTOCOL que todavía no tienen entrada propia.

`ARQUITECTURA.md` es útil, pero el flujo de `receipt` necesita corrección porque contiene una afirmación de orden falsa para `--out`. Los demás desajustes son de precisión y atribución.
