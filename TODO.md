# TODO.md — Backlog atómico

## Hecho (estado real del proyecto)
- [x] Documento de concepto v1.2 con las 5 decisiones de protocolo cerradas y fundamentadas (`docs/CONCEPTO-v1.2-es.md`)
- [x] Investigación profunda: C2SP, SLIP-0039, VRF/RFC 9381, TSA Ecuador, hosting compartido, segmentación (informe con fuentes)
- [x] Verificación de nombre: GitHub `nucleoledger` libre, npm `@nucleoledger` libre → elegido
- [x] JCS RFC 8785 nativo con vectores oficiales en verde (`internal/jcs`)
- [x] Bloque firmado: header + SHA-256(JCS) + Ed25519 + validación de cadena con firmante esperado (`internal/ledger/block.go`)
- [x] Merkle RFC 6962 con prueba de inclusión y verificación RFC 9162 (`internal/ledger/merkle.go`)
- [x] Demo de ataques: edición, refirma, reescritura total (`cmd/nucleo-demo`)
- [x] Migración del módulo a `github.com/nucleoledger/nucleo` (tests en verde)
- [x] Documentos fundacionales: README, PROTOCOL.md, ADRs, CLAUDE/AGENTS/PLAN/TODO

## Tareas del dev (fuera del código, hacer YA)
- [x] Crear organización `nucleoledger` en GitHub (plan Free) — verificar: la URL github.com/nucleoledger existe y es tuya
- [ ] Crear organización `@nucleoledger` en npm (reserva el scope) — verificar: aparece en tu perfil npm
- [ ] Verificar dominio `nucleoledger.com` (y opcional `nucleo.ec` en nic.ec) — verificar: whois/registrador
- [x] Subir este esqueleto como primer commit y push — verificar: CI corre en Actions
- [ ] Añadir LICENSE AGPL-3.0 desde el selector de licencias de GitHub (texto canónico) — verificar: archivo LICENSE con texto completo oficial

## Fase D — Laboratorio
- [x] Externalizar vectores JCS a `testdata/vectors/jcs/` y hacer que los tests los lean de ahí — tocar: `internal/jcs/jcs_test.go` — verificar: tests en verde leyendo archivos
- [x] Fuzz test de JCS (round-trip y no-pánico) — tocar: `internal/jcs/jcs_fuzz_test.go` — verificar: `go test -fuzz=FuzzJCS -fuzztime=30s ./internal/jcs`
- [ ] Añadir golangci-lint config mínima — tocar: `.golangci.yml` — verificar: `golangci-lint run` limpio (requiere aprobación de instalación de la herramienta)
- [x] Validar workflow CI en los 3 SO — tocar: `.github/workflows/ci.yml` — verificar: badge verde tras el push

## Fase 0 — Prueba de concepto C2SP
- [x] Prueba de consistencia RFC 9162 §2.1.4 (`ConsistencyProof` + `VerifyConsistency`) — tocar: `internal/ledger/merkle.go` + test nuevo — verificar: test con árbol extendido (pasa) y árbol reescrito (falla)
- [x] Formato de checkpoint (nota firmada: origin, size, root) con Ed25519 — tocar: `internal/checkpoint/` nuevo — verificar: golden test del formato exacto
- [x] Cosignature v1 simulada (testigo local: timestamp + firma sobre el checkpoint) — tocar: `internal/witness/` nuevo — verificar: test de rechazo ante checkpoint inconsistente (detecta reescritura)
- [x] Recibo estilo tlog-proof (checkpoint + índice + inclusion path) serializado — tocar: `internal/proof/` nuevo — verificar: verificación offline sin acceso al ledger + medir bytes
- [x] Benchmark de sellado y tamaño de recibo — tocar: `internal/ledger/bench_test.go` — verificar: `go test -bench` reporta cifras; anotarlas en README
- [x] Evaluar spike `golang.org/x/mod/sumdb/note` vs formato manual (decisión → ADR-008) — verificar: ADR escrito con conclusión

## Después (Sprint 2 — no empezar sin cerrar lo anterior)
- [x] `internal/store`: SQLite append-only (4 tablas + triggers; caché de subárboles DIFERIDA — ADR-009; el benchmark dispara la condición pero el cuello no es la raíz: ver reporte)
- [x] `internal/vault`: KEK/DEK + XChaCha20-Poly1305 con AAD (SLIP-0039 evaluado en ADR-010, dependencia NO añadida)
- [x] Enmienda ADR-009: la apertura verifica desde el último checkpoint cosignado (la condición de >5 s se cumplió, pero el cuello no era el árbol)
- [x] Apertura O(árbol) respaldada por checkpoint cosignado + `VerifyFull()` para auditorías — 10^5 bloques en 412 ms (antes 8,66 s)
- [x] Respaldo de la KEK con SLIP-0039 (`shurlinet/go-slip39` v0.1.0 fijada, aislada tras `BackupKEK`/`RestoreKEK` en `internal/vault/backup.go`)
- [x] 45 vectores oficiales SLIP-0039 en nuestra suite (`testdata/vectors/slip39/`, descargados del repo canónico de Trezor)
- [x] El respaldo corrupto falla ruidosamente: palabra mutada, shares de respaldos distintos y k-1 shares (RS1024)
- [x] AAD no ambiguo: `payload_hash` de longitud fija validado en cifrado y descifrado (hallazgo MEDIO de la auditoría GPT-5.5)
- [x] `Open` expone el estado atestiguado (`OpenResult`); el rollback local con borrado de checkpoints queda SEÑALADO (hallazgo ALTO de la auditoría GPT-5.5)
- [x] Contrato de restauración documentado y probado: `RestoreKEK` + `UnwrapDEK` (hallazgo BAJO de la auditoría GPT-5.5)
- [x] `BackupKEK` verifica el round-trip antes de entregar shares (condición 1 de ADR-010, CERRADA)
- [x] `cmd/nucleo-poc3`: testigo HTTP en su propia base, reinicio del log, rollback simulado y detectado
- [ ] Recibos con destinatario (`issueReceipt`)

## Sprint 3
- [x] Testigo HTTP real (`c2sp.org/tlog-witness`): servidor, cliente y estado persistente en su propio SQLite — ADR-011 fija la versión del spec
- [x] Detección de rollback por memoria del testigo (hallazgo ALTO de auditoría GPT) — `logsync.SyncWithWitness` consulta al testigo antes de firmar y devuelve `RollbackError` con ambos tamaños

