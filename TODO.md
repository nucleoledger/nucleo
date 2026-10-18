# TODO.md — Backlog atómico

Estado: el último release es **`v0.4.0-alpha`** (tag firmado con SSH, commit `978156f`),
**publicado** como pre-release el 2026-10-17 (19:16:30 UTC), verificado ese día desde un
directorio limpio —cosign con las dos recetas, sha256, procedencia SLSA— y recompilado byte
a byte desde el tag (la tabla de RELEASING). El anterior, `v0.3.1-alpha`.
`@nucleoledger/verify@0.4.0-alpha.0` **publicado** en npm con procedencia el 2026-10-15
(tag `vsdk-0.4.0-alpha.0`, commit `ec21632`; `latest` y `alpha`).
Lo detallado de cada versión vive en `CHANGELOG.md`.

El histórico de tareas cumplidas se resume por sprint: el detalle vive en los
commits, en `CHANGELOG.md` y en `docs/adr/`, que es donde hay que buscarlo. Una
lista de 70 casillas marcadas no es memoria del proyecto, es ruido.

## Hecho, por sprint
- [x] **Fase D + Fase 0** — JCS RFC 8785 nativo con vectores oficiales y fuzzing;
      bloque firmado y cadena; Merkle RFC 6962 con inclusión y consistencia;
      checkpoint C2SP; cosignature simulada; recibo tlog-proof; CI en tres SO.
- [x] **Sprint 2** — `internal/store` SQLite append-only; `internal/vault`
      (Argon2id → KEK → DEK, XChaCha20-Poly1305 con AAD no ambiguo); respaldo
      SLIP-0039 con los 45 vectores de Trezor; apertura rápida respaldada por
      checkpoint cosignado (10^5 bloques: 8,66 s → 412 ms) y `VerifyFull`.
- [x] **Sprint 3** — testigo HTTP real completo; reconciliación; detección de
      rollback por memoria del testigo; segunda firma ML-DSA-44 vía extensión
      `0xff`; cerrojo anti-retroceso duradero (`log_state`).
- [x] **Sprint 4** — `cmd/nucleo` con códigos de salida 0/1/2/3; vectores de
      recibo cross-lenguaje; `sdk/ts` con cero dependencias de runtime;
      `web/verify` estático.
- [x] **Sprint 5** — compromisos HMAC con subclave por tenant; perfil Ecuador
      (`sri.factura.v1`, `sas.acta.v1`); el criterio de éxito como script
      ejecutable; tutorial con salidas reales; spike VRF (ADR-012).
- [x] **Sprint 6 + pre-lanzamiento** — README y CHANGELOG; release firmado
      (goreleaser + cosign keyless + procedencia SLSA); los 6 hallazgos de la
      auditoría pre-pública (ADR-013); publicación npm con trusted publishing.

## Tareas del dev (fuera del código)
- [x] Organizaciones `nucleoledger` en GitHub y `@nucleoledger` en npm; dominio; 2FA; LICENSE
- [x] Configurar el trusted publisher de `@nucleoledger/verify` en npmjs.com —
      verificado el 2026-09-25: el tag `vsdk-0.2.0-alpha.0` publicó sin token y
      `npm audit signatures` da «1 package has a verified attestation»
      (publish-npm.yml, commit `669eaf2`)
- [x] Crear el buzón `security@nucleoledger.com` — operativo, confirmado por el dev
      el 2026-09-25
- [x] Publicar `v0.2.0-alpha` y verificarla desde un directorio limpio con la receta
      de RELEASING — hecho por el dev el 2026-09-25 (cosign v3.1.3)
- [x] Activar el reporte privado de vulnerabilidades en GitHub — activado por el dev el
      2026-09-25; comprobado el 2026-09-26 con la API
      (`repos/nucleoledger/nucleo/private-vulnerability-reporting` → `{"enabled":true}`)
- [x] Publicar `v0.3.0-alpha` y `vsdk-0.3.0-alpha.0` con los tags firmados con SSH —
      hecho por el dev; el release, verificado por el dev desde un directorio limpio y
      recompilado aquí byte a byte desde el tag el 2026-10-02 (sha256 en RELEASING); el
      SDK, en npm como `latest` y `alpha`
- [x] Completar el sha256 y la verificación en `docs/releases/v0.3.0-alpha.md`
- [x] Subir `examples/erp-node` a `@nucleoledger/verify@0.3.0-alpha.0`
- [x] Aplicar las notas al borrador (`gh release edit v0.3.0-alpha --notes-file …`) y
      publicarlo — notas aplicadas el 2026-10-02; publicado por el dev como pre-release
      (2026-10-03T04:43:29Z UTC)
- [x] Publicar `v0.3.1-alpha` (tag firmado con SSH) y completar el sha256 y la
      verificación en `docs/releases/v0.3.1-alpha.md` — publicada por el dev como
      pre-release el 2026-10-10 (02:30:55 UTC); verificada y recompilada byte a byte desde
      el tag; notas aplicadas
- [ ] Cronometrar el tutorial con alguien de fuera del proyecto, sobre el ejemplo
      Node (`examples/erp-node`) — verificar: una hora medida, no estimada por quien
      lo escribió. La parte mecánica ya está medida (de clon a recibo verificado,
      ~15 s en caliente, ~35 s en frío); falta la de comprensión, que es la que
      cierra CONCEPTO §18
- [ ] Decidir sobre ADR-012 (VRF). ADR-014 y ADR-015 están aceptadas e implementadas
      desde el Sprint 7b
- [x] Decidir si `restore` debe poder fijar una passphrase nueva (re-envolviendo la clave
      de datos) — decidido que sí por el dev el 2026-09-28: ADR-029, Sprint 14
- [x] Decidir si `sync` debe aceptar una política con varios testigos y elegir uno por
      nombre — decidido que sí por el dev el 2026-09-28; hecho en el Sprint 14

## Sprint 7 — cerrar la revisión externa
- [x] Ningún binario compilado en el árbol; `.gitignore` con rutas ancladas (P0)
- [x] PLAN/CLAUDE/AGENTS/TODO dicen la verdad del repo (deriva documental)
- [x] README: ML-DSA-44 es firma ADICIONAL del log vía extensión `0xff`; las
      cosignatures de testigo siguen Ed25519 — nada de post-cuántico de punta a punta
- [x] Disclaimer legal en español EN el recibo y en el verificador HTML
- [x] El destinatario del recibo se etiqueta "(anotado por el emisor, no firmado)"
- [x] `docs/adr/ADR-014-hoja-y-firma.md` — spike de decisión, sin implementar
- [x] `docs/adr/ADR-015-destinatario.md` — spike de decisión, sin implementar
- [x] Política *fail-stale*: umbral configurable (72 h por omisión); `status` y
      `seal` avisan por stderr y en `--json`; `verify` lo reporta. Reloj inyectado
- [x] `init --kdf-profile {default,constrained}` con los parámetros persistidos y
      honrados por `Unlock`, y el coste de ambos perfiles MEDIDO
- [x] Fuzzers de todos los formatos de cable: note firmada, checkpoint,
      cosignature, recibo y cuerpo de la petición del testigo

## Sprint 12 — que funcione como promete y se opere sin ayuda
- [x] ADR-028: la alarma de frescura durable, `alert status|ack`, `--fail-on-stale` y el hook
      `onStale` en el SDK de PHP y el ejemplo Node — test sin leer stderr
- [x] `docs/OPERACION.md`, cada instrucción comprobada
- [x] Los requisitos del hosting, lo primero del README del SDK de PHP
- [x] Las «auditorías externas» renombradas como lo que fueron: revisiones de un modelo

## Sprint 13 — higiene de seguridad y procedencia
- [x] CodeQL, conversiones de enteros (6): tamaños de árbol que llegan de fuera, con
      comprobación de rango y test en el límite
- [x] CodeQL, reserva de memoria (1): tope explícito `MaxNoteBody` al cuerpo cosignado
- [x] CodeQL, hash débil (2): falso positivo —es el key ID de signed-note, sobre el origin y la clave pública—, descartado en GitHub con la justificación
- [x] CodeQL, registro en claro (3): falso positivo —setup.js imprime rutas, no contenido—, ahora comprobado en CI
- [x] CodeQL, permisos de los workflows (6): `ci.yml`, y revisar `release.yml` y `publish-npm.yml`
- [x] `NOTICE` (y `AUTHORS`) dentro de los archivos del release
- [x] El nombre legal completo del titular en los avisos de copyright
- [x] La procedencia de los vectores RFC 6962: transparency-dev/merkle, contrastada valor a valor

## Sprint 14 — las dos decisiones pendientes del Sprint 12, y preparar v0.3.0-alpha
- [x] ADR-029: el cambio de passphrase atómico en el vault (`store.ReplaceMeta`,
      `vault.PrepareRekey`), probado matando el proceso a medias de la transacción
- [x] `restore --new-passphrase[-file]` con tarjetas nuevas y confirmación tecleada,
      probado matando el proceso en cada frontera; el `Sealer` acepta `0640 root:www-data`;
      OPERACION y el tutorial corregidos
- [x] `sync` con la política de los clientes: varios testigos y `--witness-name` para elegir
- [x] Preparar v0.3.0-alpha: CHANGELOG, notas del release, `sdk/ts` 0.3.0-alpha.0, tag
      firmado con SSH en RELEASING — sin tag ni push

## Revisión del 2026-10-03 (ADR-029) y v0.3.1-alpha
- [x] El informe, recuperado de la sesión de OpenCode y versionado tal cual
- [x] MEDIA: el seal ya desbloqueado durante restore — se deja, con test y razón escrita
- [x] La enmienda de ADR-029: passphrase olvidada frente a robada, en la CLI, OPERACION y
      el tutorial
- [x] BAJA: KEK, DEK y passphrase borradas de memoria en cuanto sobran, con el límite escrito
- [x] BAJA documental: el tutorial repite lo de las copias antiguas, con test
- [x] Preparar v0.3.1-alpha: CHANGELOG y notas, sin tag ni push
- [x] El lint del CI en rojo (run 38002811302): golangci-lint v2.14.0, y `scripts/lint.sh`
      para que el lint local use la versión y el Go que fija ci.yml

## Sprint 15 — el producto-testigo como software, para que lo opere un tercero
- [x] 0. El Go fijado en go.mod (`toolchain go1.27.2`), en local y en todos los workflows;
      reproducible byte a byte, comprobado
- [x] 1. ADR-030: un testigo para varios logs (`witness serve --config`), con altas, bajas,
      logs retirados y memoria aislada por log; `--log-origin`/`--log-key` siguen igual
- [x] 2. El testigo mutuo, ensayado con dos procesos en local y en el CI
      (`scripts/ensayo-testigo-mutuo.sh`); qué garantiza y qué no, en OPERACION §1
- [x] 3. El kit del operador (`deploy/witness/`), validado en el CI
      (`scripts/valida-kit-testigo.sh`), con su guía
- [x] 4. El CONCEPTO enmendado a la vista: no hay `nucleod`, y el VRF no va en el ledger

## Sprint 16 — el mapa del sistema, y que no se desfase
- [x] 1. `docs/ARQUITECTURA.md`: componentes con el grafo real de imports, los flujos con
      fichero y función, fronteras de confianza y estados persistentes; once bloques Mermaid
      validados
- [x] 2. `docs/GARANTIAS.md`: 37 garantías con su ADR y su test, 19 límites; lo que no tiene
      test, marcado
- [x] 3. `cmd/nucleo/mapa_test.go`: el CI falla si el mapa cita algo que no existe, con un
      autotest que demuestra que muerde
- [x] 4. La clave de un log retirado comprueba su memoria (enmienda de ADR-030)
- [x] 5. Decidir sobre los hallazgos del mapa (informe del Sprint 16): decididos en el
      Sprint 17

## Sprint 17 — la revisión del 2026-10-10, y los hallazgos del mapa
- [x] 1. El informe de OpenCode versionado tal cual
      (`docs/revision-externa-modelo-20261010.md`)
- [x] 2. ALTA: con `--out`, `receipt` ya no deja en disco un recibo que no verificó
- [x] 3. Medias y bajas del informe: ARQUITECTURA y GARANTIAS corregidas donde tenía razón
- [x] 4. Supresión: ADR-031 (propuesta) y `nucleo erase`, con evento sellado sin datos
      personales, `reconcile` que la distingue de un faltante y el dato fuera del disco
- [x] 5. Enmiendas a la vista: PROTOCOL §3, §6 y §9, y ADR-005; `internal/keys` anotado en
      PLAN; verificar recibos ajenos desde la CLI, anotado en TODO
- [x] 6. Mermaid en el CI: `tools/mermaid/` con su lockfile, autoprueba que demuestra que
      rechaza un bloque roto, y el job `mermaid`
- [x] 7. `scripts/compuerta.sh` sustituye a `Taskfile.yml`: la compuerta completa con una
      orden, sale con 1 si falla un paso; documentada en CONTRIBUTING, CLAUDE.md y AGENTS.md

## Sprint 18 — la enmienda de ADR-031, y v0.4.0-alpha
- [x] 1. La supresión ya no sirve para borrar huellas: el ataque con el fichero de la
      passphrase, reproducido y luego invertido; `erase` exige dos tarjetas tecleadas en una
      consola, y cada supresión abre una alarma (`erasure_alert`, `onErasure` en PHP y en el
      ejemplo Node) que solo cierra `alert ack`; L20 en GARANTIAS
- [x] 2. PROTOCOL 0.6-draft: `nucleo.erasure.v1` registrado, y §5 nombra la excepción; el
      Taskfile, enmendado en CONCEPTO
- [x] 3. v0.4.0-alpha preparada: CHANGELOG, notas y el coste de venir de v0.3.1-alpha

## Sprint 19 — la autorización de las supresiones (ADR-032), antes de publicar v0.4.0-alpha
- [x] 1. ADR-032 (propuesta): la clave de supresión fuera del servidor, `erasureKey` en la
      política de los tres parsers con vectores de `generar.py`, la autorización en el
      `payload_cid` del evento con `through`; las tarjetas del vault dejan de pedirse en
      `erase` y `alert ack` sigue sin firma. PROTOCOL 0.7-draft
- [x] 2. Tests de la regla: el evento firmado solo por el tenant no cuenta (fallaba con el
      código anterior: salía 0), la supresión autorizada sí y su recibo la demuestra a un
      tercero sin Núcleo, y la autorización de otra clave o de otro hash no cuenta
- [x] 3. GARANTIAS (G40–G46, L20–L21) y ARQUITECTURA al día
- [x] 4. CHANGELOG y notas de v0.4.0-alpha: las dos rondas, tal como fueron
- [x] 5. Dependabot #5 (KaTeX en `tools/mermaid/`): sin versión de mermaid que admita la
      corregida, y no alcanzable en el validador; justificado en `tools/mermaid/AVISOS.md` y
      descartado en GitHub

## Sprint 19b — lo que impide publicar v0.4.0-alpha
- [x] 0. ADR-032 aceptado por el dev
- [x] 1. Las órdenes impresas se entrecomillan según la plataforma (CI rojo en windows-2025)
- [x] 2. Una sola política: `@nucleoledger/verify` 0.4.0-alpha.0 preparado, con su migración;
      el ejemplo pasa a una sola política cuando el paquete esté en npm
- [x] 3. El ensayo de actualización desde v0.3.1-alpha, repetido con el código final
- [x] 4. Revisión de ARQUITECTURA, GARANTIAS y CLI-JSON; el diagrama de la supresión con los
      dos equipos

## Sprint 20a — el límite de tiempo del CI #70, y la revisión del 2026-10-11
- [x] 0. La revisión externa del 2026-10-11, versionada tal cual con su procedencia
- [x] 1. CI #70: la suite de `cmd/nucleo` agotó los 10 min en macos-26. Medida, los tests por
      `--kdf-profile constrained` salvo los que prueban el perfil, y `-timeout` explícito
- [x] 2. H1: `reconcile --json` emite un solo objeto también si falla `VerifyFull`; un valor
      JSON y EOF, exigido en todos los tests `--json`
- [x] 3. H5 y H6: G44 dice que la autorización de supresión solo la comprueba Go; el
      comentario de `internal/erasure` con el formato de 0.7-draft
- [x] 4. H7: la compuerta exige el bit de ejecución de `scripts/*.sh` en el índice
- [x] 5. Los huecos de G42 (`alert ack` no cuenta una supresión) y de la política de otro origin
- [x] 6. ADR-033 candidato anotado: la rotación de `erasureKey`
- [x] 7. Cierre parcial: tabla en la revisión, CHANGELOG, compuerta en verde

## Sprint 20b — PowerShell, el ensayo con firma, shellcheck y el tercero en el CI
- [x] 1. H2/H3: en Windows, las órdenes impresas son para PowerShell; test con la consola de
      verdad (powershell.exe, pwsh, sh) y enmienda de ADR-032 §F
- [x] 2. cosign y shellcheck en esta máquina, con el checksum comprobado
- [x] 3. H4: el ensayo exige la firma, o `NUCLEO_ENSAYO_SIN_FIRMA=1` y lo dice
- [x] 4. G45: `scripts/tercero-supresion.sh`, sin red, en el ensayo, la compuerta y el CI
- [x] 5. shellcheck en todos los `scripts/*.sh`, y el job `scripts` del CI
- [x] 6. Cierre: tabla de la revisión, CHANGELOG, notas, compuerta y ensayo con cosign

## Sprint 21 — la revisión del 2026-10-14, y v0.4.0-alpha lista para etiquetar
- [x] 0. La revisión externa del 2026-10-14, versionada tal cual con su procedencia
- [x] 1. H8: el ensayo autentica `checksums.txt` antes de usarlo; `scripts/test-ensayo-orden.sh`
      fija el orden sin red (y H4, que no tenía test)
- [x] 2. H9: `tercero-supresion.sh` de verdad sin red (`GOPROXY=off`, `NUCLEO_BIN`)
- [x] 3. H10: los bordes de Windows en el test de la consola de verdad
- [x] 4. El ejemplo con una sola política y `@nucleoledger/verify` 0.4.0-alpha.0 de npm
- [x] 5. El ensayo verifica también con el paquete 0.4.0-alpha.0 del registro
- [x] 6. Documentación: notas del release, RELEASING, versión de Go en CLAUDE/AGENTS
- [x] 7. Cierre: tabla de la revisión, compuerta y ensayo con cosign

## Sprint 22 — documentación vigente veraz antes de etiquetar v0.4.0-alpha
- [x] 1. Auditoría de los documentos vigentes contra GARANTIAS, tags, tests y ficheros
- [x] 2. SECURITY «Out of scope» sin las dos viñetas falsas (G4, G15), cada límite con su Lnn (L22 nuevo)
- [x] 3. README «Status», rondas contadas, recompilación hasta v0.3.1-alpha, lo de v0.4
- [x] 4. PLAN y TODO con el estado real; AUTHORS con lo que se firma de verdad
- [x] 5. La guardia: `cmd/nucleo/docs_vigentes_test.go` y el paso de RELEASING antes del tag

## Sprint 22b — las decisiones del dev antes del tag
- [x] 1. La revisión externa del 2026-10-17, versionada tal cual con su procedencia
- [x] 2. README «Security & audits» y exploits estrechados a lo comprobable; el testigo, sin
      operador todavía (notas y CHANGELOG); SECURITY remite a `docs/revision-externa-*`
- [x] 3. El checklist «Antes del tag» contra el HEAD final; CHANGELOG con la fecha del tag

### P2 del Sprint 22, para después
- [x] `SECURITY.md` «No external audit yet»: las revisiones están en los ADR **y** en
      `docs/revision-externa-*`; nombrar los dos sitios

## Cierre de v0.4.0-alpha (lo hace el dev)
- [x] Etiquetar `v0.4.0-alpha` (firmado con SSH) y hacer push; el release lo crea el CI
      (run 39047178630, en verde)
- [x] Verificar el release desde un directorio limpio y completar la línea PENDIENTE de
      `docs/releases/v0.4.0-alpha.md` y la tabla de RELEASING (Sprint 23, 2026-10-17)
- [x] Aplicar las notas (`gh release edit v0.4.0-alpha --notes-file
      docs/releases/v0.4.0-alpha.md`) y publicar el borrador — publicado por el dev como
      pre-release el 2026-10-17 (19:16:30 UTC)
- [ ] Volver a aplicar las notas, con el ancla del CHANGELOG corregida en main (Sprint 24):
      el mismo `gh release edit`; no toca los artefactos

## Sprint 24 — lo que dejó el release de v0.4.0-alpha, y `nucleo version`
- [x] 1. El ancla rota de las notas de v0.4.0-alpha, y su guardia en `docs_vigentes_test.go`
- [x] 2. RELEASING: la receta de la procedencia SLSA (`gh attestation verify`)
- [x] 3. `nucleo version`, y la reproducibilidad con los tres `-X` comprobada
- [x] 4. TODO al día tras la publicación de v0.4.0-alpha

## Sprint 25 — la firma ML-DSA-44 se emite, y ningún verificador publicado la comprueba
- [x] 1. GARANTIAS: G23 dice solo lo que fijan sus tests (se emite, y no rompe a los
      verificadores C2SP); L23 nuevo; L14 sin «protege»
- [x] 2. README: «emitted as an additional signature; no shipped verifier checks it yet»,
      con enlace a L23, y fuera «post-quantum hygiene»
- [x] 3. SECURITY «Out of scope» cita L23
- [x] 4. El ADR candidato, anotado aquí y en PLAN

## Sprint 26 — diseño, sin código: ADR-033 y ADR-034 propuestos, una sola subida de la política
- [x] 0. CONCEPTO: enmienda a la vista, la ML-DSA-44 se emite y nadie la comprueba; el
      candidato pasa a llamarse ADR-034
- [x] 1. ADR-033 PROPUESTO: la rotación de `erasureKey` (`retiredErasureKeys`, corte por
      índice del evento), con el plan conjunto
- [x] 2. ADR-034 PROPUESTO: verificar la ML-DSA-44 del log (`logMLDSAKey`), con el mismo plan

## Sprint 27 — ADR-033 y ADR-034 ACEPTADOS; el exploit del recibo de ADR-017, como test
- [x] 1. ADR-033 y ADR-034 ACEPTADOS: «Decisiones del dev (2026-10-18)» en cada uno, y cada
      pregunta abierta del plan conjunto con su respuesta
- [x] 2. TODO y PLAN: los dos ADR aceptados, y su implementación como los sprints de la 0.5
- [x] 3. El recibo del bloque firmado por una clave ajena, bajo el checkpoint real (ADR-017):
      vector del oráculo y rechazo en Go, TS, PHP y la página; GARANTIAS y README

## La 0.5: implementación de ADR-033 y ADR-034 (sprints futuros, en este orden)
La 0.5 se publica solo con los dos implementados (decisión 10). El plan conjunto de los dos ADR
es el detalle; aquí, un sprint por paso, cada uno con la compuerta en verde.
- [ ] **Sprint A — PROTOCOL 0.8-draft** (por instrucción del dev): `retiredErasureKeys` y
      `logMLDSAKey` en §3.2, la regla ML-DSA en §3.3, las claves retiradas y la regularización
      en §5.1, con la nota de cabecera de la subida
- [ ] **Sprint B — los vectores, antes que el código**: `policy/` (los dos miembros, con el
      array `[{key, until}]` rechazado); `erasure/` (la segunda clave y `rotacion.json`, con
      las filas de la regularización); OpenSSL ≥ 3.5 instalado con su versión y su sha256,
      `mldsa/` y los recibos ML-DSA desde él, más el subconjunto sigVer del ACVP; ADR-024
      revisado y `material/mldsa.json` fuera
- [ ] **Sprint C — Go**: `internal/policy`; `internal/erasure` y `internal/reconcile` (claves
      retiradas, `TestClaveRetiradaDespuesDelCorteNoCuenta`, la regularización y
      `TestSupresionNoAutorizadaRegularizada`); `internal/proof` (ML-DSA con `crypto/mldsa`,
      `LogMLDSA`); la CLI: `sync` con `logMLDSAKey` y el fragmento de `retiredErasureKeys`
      (`erasure_rotation` en `--json`), la apertura que coteja la clave, `erasure-key
      authorize` que rechaza una clave retirada, `reconcile --json` con la clave y
      `regularized`, y `nucleo verify-receipt`
- [ ] **Sprint D — TypeScript, PHP y la página**: los dos miembros en el parser, `logMLDSA`
      con `"present-unverified"` (opción B); el diferencial con los miembros nuevos y la
      divergencia declarada
- [ ] **Sprint E — documentación y ensayo**: GARANTIAS (L14, L21, L23: la comprobación
      post-cuántica solo la hace el verificador de Go), OPERACION §3 (rotar con el fragmento
      de `sync`), CLI-JSON, README; `ensayo-actualizacion.sh` con los pasos del plan conjunto
      y `tercero-supresion.sh` con la clave retirada
- [ ] **Publicación** (el dev): primero el SDK `vsdk-0.5.0-alpha.0`, después `v0.5.0-alpha`

## Después del release de v0.4.0-alpha
- [x] El exploit del recibo de ADR-017 (un bloque firmado por una clave ajena, bajo el
      checkpoint real) como test de regresión en Go, TypeScript, PHP y la página: hecho en el
      Sprint 27 (vector `invalido-bloque-de-clave-ajena`); el README ya no lo exceptúa
- [ ] G46: las cuatro órdenes que `comillas_shell_test.go` reconstruye con `printf` (`init` y
      el ledger que no existe en `env.go`, `restore --new-passphrase` en `env.go` y
      `backup.go`, `backup` en `init.go`), capturarlas de la salida real de la CLI
- [ ] `release.yml`: `-timeout` explícito en su `go test`, como `ci.yml` y la compuerta. Es
      configuración de release: decisión del dev

## Pendiente de producto
- [x] **Sealer PHP** — Sprint 8 (ADR-021): verificador nativo y sellador envoltorio.
- [ ] **Producto-testigo.** Sin testigos que el emisor no controle, el tiempo
      demostrable no existe para una pyme. Testigo mutuo entre instalaciones, o
      un tercero con incentivo (contador, certificadora, colegio de abogados).
      El software ya está (Sprint 15: varios logs, retirada, testigo mutuo y el kit
      del operador); lo que falta no es código: que alguien de fuera lo opere.
- [ ] **Verificar recibos ajenos desde la CLI.** Decidido el 2026-10-18 (ADR-034, decisión 8):
      entra en la 0.5 como `nucleo verify-receipt`, en el Sprint C de arriba. Hasta entonces, un
      recibo se verifica con `@nucleoledger/verify`, con el SDK de PHP o con la página de
      `web/verify/`, y la CLI solo autoverifica los que emite.
- [ ] **ADR-033 (ACEPTADO el 2026-10-18, sin implementar): rotación de erasureKey.**
      `retiredErasureKeys` (clave → corte) en la política, para que rotar no invalide las
      supresiones históricas (hoy, el límite L21), y la regularización con la clave nueva.
      Implementación: los sprints de la 0.5, arriba.
- [ ] **ADR-034 (ACEPTADO el 2026-10-18, sin implementar): verificar ML-DSA-44.**
      `logMLDSAKey` en la política; Go la verifica con `crypto/mldsa`; TS, PHP y la página
      dicen `"present-unverified"` (opción B). Hoy, el límite L23. Implementación: los sprints
      de la 0.5, arriba.
- [ ] Identidad de registro estable y eventos `issued`/`voided` en el perfil
      genérico: las facturas se anulan y hoy `reconcile` no lo modela (pide ADR)

## Fuera de alcance hasta nuevo aviso
- **Dual-license con texto y precio** — decisión de negocio del dev, no de ingeniería.
- **Auditoría humana pagada** — cuando haya ingresos. Hasta entonces el README
  dice, en su primera frase, que no hay auditoría profesional, y eso no se maquilla.
- **HSM** — v1 es software-only. Documentado como límite, no como pendiente.
