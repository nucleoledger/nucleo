# CLAUDE.md — Contexto para agentes (Claude Code / OpenCode)

# 🚀 STACK & ARCHITECTURE
- **Lenguaje:** Go. Objetivo: **Go 1.27+** (por `crypto/mldsa` en stdlib). Versión local instalada: Go 1.27.1.
- **Módulo:** `github.com/nucleoledger/nucleo`
- **Producto:** binario CLI `nucleo` + daemon opcional `nucleod` (aún no implementados) + SDK TypeScript futuro en `sdk/`
- **Sin Docker, sin base de datos externa, sin migraciones**: SQLite embebido (pure-Go, `modernc.org/sqlite`) llegará en el Sprint 2. Hoy no hay persistencia.
- **Sin despliegue**: esto es un producto de software (releases firmados con goreleaser, `<PENDIENTE: configurar goreleaser>`). Nunca hay servidores que tocar.
- **Criptografía fijada por `docs/PROTOCOL.md`** (normativo): JCS RFC 8785, Ed25519 sobre digest SHA-256, Merkle RFC 6962/9162, C2SP (checkpoint/cosignature/witness/proof/tiles), XChaCha20-Poly1305 + Argon2id, SLIP-0039, VRF vrf-r255.

# 📁 PROJECT STRUCTURE MAP
```
nucleo/
├── cmd/
│   └── nucleo-demo/        # demo end-to-end (leer; se reemplazará por cmd/nucleo CLI)
├── internal/
│   ├── jcs/                # RFC 8785 nativo + tests con vectores oficiales  [ESTABLE — NO TOCAR]
│   ├── ledger/             # block.go (cadena firmada) + merkle.go (RFC 6962) [ESTABLE — ampliar, no reescribir]
│   └── keys/               # Ed25519 helpers                                  [ESTABLE]
├── docs/
│   ├── PROTOCOL.md         # LA LEY. Todo cambio de formato exige ADR + bump aquí
│   ├── adr/                # decisiones registradas (leer antes de diseñar nada)
│   └── CONCEPTO-v1.2-es.md # visión completa del proyecto (leer para contexto)
├── testdata/vectors/       # vectores compartidos Go↔TS  [NO MODIFICAR SIN ADR]
├── sdk/                    # (futuro) cliente TypeScript
├── clients/                # (futuro) PHP, Python, Java
└── .github/workflows/      # CI (no tocar sin instrucción)
```
La IA **lee** en `docs/` y `internal/`; **escribe** en `internal/`, `cmd/` y tests; **no toca**: `testdata/vectors/`, `.github/`, `docs/PROTOCOL.md` y `docs/adr/` (salvo instrucción explícita del dev).

# 🛡️ STRICT DEVELOPMENT RULES
- Trabajar en la rama actual (`git branch --show-current`). NO crear ramas ni cambiar de rama salvo instrucción explícita.
- ANTES de cualquier bloque de tareas: `git status` limpio. Si hay cambios sin commitear, DETENERSE y avisar.
- Tipado estricto e idiomático Go; `gofmt` obligatorio; identificadores en inglés, comentarios en español (estilo ya establecido).
- PROHIBIDO instalar dependencias nuevas sin aprobación explícita. Las únicas pre-aprobadas están listadas en `docs/CONCEPTO-v1.2-es.md` §10.
- PROHIBIDO tocar .env, secretos, credenciales, configuración de releases.
- **Regla criptográfica:** ningún código que firme, hashee o canonicalice se escribe sin su vector de prueba primero. Ningún cambio puede romper los vectores existentes: si un vector falla, el código está mal, no el vector.
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
go test -bench=. ./...         # benchmarks (cuando existan)
```
No hay logs de servicio: la salida de la CLI y de los tests es el log.
