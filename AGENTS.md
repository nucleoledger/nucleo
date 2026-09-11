# CLAUDE.md — Contexto para agentes (Claude Code / OpenCode)

# 🚀 STACK & ARCHITECTURE
- **Lenguaje:** Go. Objetivo: **Go 1.27+** (por `crypto/mldsa` en stdlib). Versión local instalada: Go 1.27.1.
- **Módulo:** `github.com/nucleoledger/nucleo`
- **Producto:** binario CLI `nucleo` (implementado: init/seal/status/verify/receipt/reconcile/sync/witness/backup/restore, códigos de salida 0/1/2/3) + SDK TypeScript publicado en `sdk/ts` (`@nucleoledger/verify`). El daemon `nucleod` sigue sin existir y no está planificado para v1.
- **Sin Docker, sin base de datos externa, sin migraciones**: SQLite embebido (pure-Go, `modernc.org/sqlite`) append-only, con WAL y `synchronous=FULL`. Implementado en `internal/store`.
- **Sin despliegue**: esto es un producto de software (releases firmados con goreleaser + cosign keyless; ver `.goreleaser.yaml` y `docs/RELEASING.md`). Nunca hay servidores que tocar.
- **Criptografía fijada por `docs/PROTOCOL.md`** (normativo): JCS RFC 8785, Ed25519 sobre digest SHA-256, Merkle RFC 6962/9162, C2SP (checkpoint/cosignature/witness/proof/tiles), XChaCha20-Poly1305 + Argon2id, SLIP-0039, VRF vrf-r255.

# 📁 PROJECT STRUCTURE MAP
```
nucleo/
├── cmd/
│   ├── nucleo/             # LA CLI. El producto. Aquí se trabaja.
│   ├── nucleo-demo/        # demo end-to-end del Sprint 1     [HISTÓRICO — no editar]
│   └── nucleo-poc{,2,3}/   # pruebas de concepto C2SP         [HISTÓRICO — no editar]
├── internal/
│   ├── jcs/                # RFC 8785 nativo + vectores oficiales        [ESTABLE — NO TOCAR]
│   ├── ledger/             # block.go (cadena firmada) + merkle.go        [ESTABLE — ampliar]
│   ├── keys/               # Ed25519 helpers                             [ESTABLE]
│   ├── store/              # SQLite append-only, apertura con atestación
│   ├── vault/              # Argon2id → KEK → DEK, XChaCha20-Poly1305, SLIP-0039
│   ├── identity/           # identidad del log y rotación
│   ├── checkpoint/         # notas firmadas C2SP + firma extra ML-DSA-44 (0xff)
│   ├── witness/            # testigo HTTP completo (c2sp.org/tlog-witness)
│   ├── logsync/            # sincronización con testigo y detección de rollback
│   ├── proof/ receipt/     # tlog-proof y recibos verificables offline
│   ├── reconcile/          # comparar el sistema vivo contra lo sellado
│   ├── commit/             # compromisos HMAC-SHA-256 con subclave por tenant
│   └── integration/        # tests de extremo a extremo entre paquetes
├── profiles/ecuador/       # sri.factura.v1 y sas.acta.v1
├── sdk/ts/                 # @nucleoledger/verify — cero dependencias de runtime
├── web/verify/             # verificador HTML estático, sin red
├── scripts/                # demo-criterio-exito.sh: el criterio de éxito ejecutable
├── docs/
│   ├── PROTOCOL.md         # LA LEY. Todo cambio de formato exige ADR + bump aquí
│   ├── adr/                # decisiones registradas (leer antes de diseñar nada)
│   ├── RELEASING.md        # publicar y verificar un release; config de npm
│   ├── TUTORIAL-es.md      # integrar en una hora, con salidas reales
│   └── CONCEPTO-v1.2-es.md # visión completa del proyecto
├── testdata/vectors/       # vectores compartidos Go↔TS  [NO MODIFICAR SIN ADR]
└── .github/workflows/      # ci.yml, release.yml, publish-npm.yml (no tocar sin instrucción)
```
La IA **lee** en `docs/` y `internal/`; **escribe** en `internal/`, `cmd/nucleo/`,
`profiles/`, `sdk/ts/` y tests; **no toca**: `testdata/vectors/`, `.github/`,
`docs/PROTOCOL.md`, `docs/adr/`, ni los `cmd/nucleo-demo` y `cmd/nucleo-poc*`
(salvo instrucción explícita del dev).

# 🛡️ STRICT DEVELOPMENT RULES
- Trabajar en la rama actual (`git branch --show-current`). NO crear ramas ni cambiar de rama salvo instrucción explícita.
- ANTES de cualquier bloque de tareas: `git status` limpio. Si hay cambios sin commitear, DETENERSE y avisar.
- Tipado estricto e idiomático Go; `gofmt` obligatorio; identificadores en inglés, comentarios en español (estilo ya establecido).
- PROHIBIDO instalar dependencias nuevas sin aprobación explícita. Las únicas pre-aprobadas están listadas en `docs/CONCEPTO-v1.2-es.md` §10.
- PROHIBIDO tocar .env, secretos, credenciales, configuración de releases.
- **Regla criptográfica:** ningún código que firme, hashee o canonicalice se escribe sin su vector de prueba primero. Ningún cambio puede romper los vectores existentes: si un vector falla, el código está mal, no el vector.
- **Regla anti-circularidad:** todo valor golden (hashes, key IDs, firmas, bytes canónicos) se calcula FUERA del código bajo prueba (sha256sum, cómputo manual, implementación independiente). Un test que verifica una función usando esa misma función no verifica nada.
- **PROTOCOL.md manda:** si una tarea contradice el protocolo, DETENERSE y preguntar; el cambio de protocolo es decisión del dev vía ADR.
- No borrar comentarios ni código existente salvo que la tarea lo pida.
- REGLA DE CIERRE: tarea completa = `gofmt -l .` vacío + `go vet ./...` + `go test ./... -race` en verde. Tras cada tarea: 1 commit atómico descriptivo + marcar checkbox en TODO.md. Reversible con un solo `git revert`.
- PROHIBIDO `git push` — lo hace siempre el dev tras revisar.
- Tarea ambigua o riesgosa → DETENERSE y preguntar.

# ⚙️ RECURRENT COMMANDS & LOGS
```bash
go build ./...                 # compilar todo
gofmt -l . && go vet ./...     # formato + análisis estático (salida vacía = OK)
go test ./... -race            # tests con detector de carreras
go test ./internal/jcs -run TestRFC8785Vector -v   # vectores oficiales JCS
go run ./cmd/nucleo-demo       # demo end-to-end (cadena + Merkle + 3 ataques)
go test -bench=. ./internal/store ./internal/vault  # benchmarks
./scripts/demo-criterio-exito.sh  # el criterio de éxito de la v1, de punta a punta
cd sdk/ts && npm test          # verificador TS contra los MISMOS vectores
```
No hay logs de servicio: la salida de la CLI y de los tests es el log.

Nota: AGENTS.md y CLAUDE.md son copias espejo; todo cambio se aplica en ambos.
