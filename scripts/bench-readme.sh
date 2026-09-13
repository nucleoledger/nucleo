#!/usr/bin/env bash
# Regenera la tabla de benchmarks del README sobre el commit actual.
#
# Imprime la tabla en Markdown, con fecha, commit y máquina, para pegarla tal cual.
# Cada cifra de tiempo es la MEDIANA de N muestras, con el rango (mínimo–máximo) al
# lado: este proyecto midió un 36 % de diferencia entre dos ejecuciones del mismo
# código en la misma máquina, y una cifra suelta sin dispersión hace pasar esa
# variación por un dato. Un número sin fecha ni commit no es una medición: es un
# recuerdo; y uno sin rango, una anécdota.
#
#   ./scripts/bench-readme.sh              # N=5 (~10 min)
#   ./scripts/bench-readme.sh -n 3         # otro N
#   ./scripts/bench-readme.sh --quick      # N=1, para comprobar el script (sin rango)
#
# ABORTA con el árbol sucio. La tercera auditoría encontró la tabla anterior citando un
# commit cuyo script no podía producirla: se había medido con el script modificado y
# sin commitear. El commit del pie tiene que ser, byte a byte, el código medido.
set -euo pipefail
cd "$(dirname "$0")/.."

n=5
while [[ $# -gt 0 ]]; do
  case "$1" in
    --quick) n=1 ;;
    -n) n="$2"; shift ;;
    *) echo "uso: $0 [--quick | -n N]" >&2; exit 2 ;;
  esac
  shift
done

if [[ -n "$(git status --porcelain)" ]]; then
  echo "✘ el árbol de trabajo tiene cambios sin commitear:" >&2
  git status --short >&2
  echo "  La tabla cita un commit; tiene que medirse exactamente ese commit. Commitea o guarda los cambios." >&2
  exit 1
fi

commit="$(git rev-parse --short HEAD)"
fecha="$(date -u +%Y-%m-%d)"
cpu="$(grep -m1 'model name' /proc/cpuinfo 2>/dev/null | sed 's/.*: //' | sed 's/ \+/ /g' || sysctl -n machdep.cpu.brand_string 2>/dev/null || echo desconocida)"
gover="$(go env GOVERSION)"

tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT

# Las aperturas y verify --full de 10^5 bloques: una operación por muestra, N muestras.
go test -run='^$' -bench='BenchmarkOpen(Unattested)?/bloques=1e5$|BenchmarkVerifyFull/bloques=1e5$' \
  -benchtime=1x -count="$n" ./internal/store > "$tmp"
# El desbloqueo del vault: ~decenas de ms, 10 operaciones por muestra.
go test -run='^$' -bench='BenchmarkUnlock' -benchtime=10x -count="$n" ./internal/vault >> "$tmp"
# Lo que dura microsegundos o milisegundos: por tiempo.
go test -run='^$' -bench='BenchmarkSeal$|BenchmarkAppendBlock$|BenchmarkRoot/hojas=100000$|BenchmarkReceipt/hojas=100000$' \
  -benchtime=1s -count="$n" ./internal/ledger ./internal/store >> "$tmp"

# resumen <regex del benchmark> <campo: ns | nombre de métrica> <formato: tiempo | entero>
# Imprime "mediana (mín–máx, n=N)" o solo la mediana si N=1.
resumen() {
  python3 - "$tmp" "$1" "$2" "$3" "$n" <<'PY'
import re, statistics, sys
path, pat, campo, fmt, n = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4], int(sys.argv[5])
vals = []
for line in open(path):
    if not re.match(pat, line):
        continue
    toks = line.split()
    if campo == "ns":
        vals.append(float(toks[2]))
    else:
        for i, t in enumerate(toks):
            if t == campo:
                vals.append(float(toks[i - 1]))
if len(vals) != n:
    sys.exit(f"'{pat}' ({campo}): {len(vals)} muestras, se esperaban {n}")
def f(x):
    if fmt == "entero":
        return f"{x:,.0f}"
    if x >= 1e9: return f"{x/1e9:.2f} s"
    if x >= 1e6: return f"{x/1e6:.0f} ms"
    if x >= 1e3: return f"{x/1e3:.0f} µs"
    return f"{x:.0f} ns"
med = statistics.median(vals)
if n == 1:
    print(f"**{f(med)}**")
else:
    print(f"**{f(med)}** ({f(min(vals))}–{f(max(vals))}, n={n})")
PY
}

open_att="$(resumen '^BenchmarkOpen/bloques=1e5' ns tiempo)"
open_un="$(resumen '^BenchmarkOpenUnattested/bloques=1e5' ns tiempo)"
full="$(resumen '^BenchmarkVerifyFull/bloques=1e5' ns tiempo)"
unlock_def="$(resumen '^BenchmarkUnlockDefault' ns tiempo)"
unlock_con="$(resumen '^BenchmarkUnlockConstrained' ns tiempo)"
seal_ps="$(resumen '^BenchmarkSeal-' 'bloques/s' entero)"
append_ps="$(resumen '^BenchmarkAppendBlock-' 'bloques/s' entero)"
root="$(resumen '^BenchmarkRoot/hojas=100000' ns tiempo)"
proof_bytes="$(resumen '^BenchmarkReceipt/hojas=100000' 'bytes/recibo' entero)"

# Tamaño real de un recibo emitido por la CLI. Es determinista —mismas semillas,
# mismo reloj—, así que se mide una vez. Si algo falla, el script falla: antes
# imprimía "?" y la tabla salía con un hueco.
recibo="$(bash -c '
set -euo pipefail
export NUCLEO_TEST_CLOCK=2026-09-07T10:00:00Z NUCLEO_TEST_PASSPHRASE=x NUCLEO_TEST_SEED=$(printf "%064d" 7)
w=$(mktemp -d); trap "kill \${p:-0} 2>/dev/null || true; rm -rf $w" EXIT
go build -tags testhooks -o "$w/nucleo" ./cmd/nucleo
"$w/nucleo" --dir "$w/l" init --origin nucleoledger.com/bench --assume-confirmed >/dev/null 2>&1
printf "{\"factura\":1}" > "$w/p.json"
"$w/nucleo" --dir "$w/l" seal --tenant 1790012345001 --type sri.factura.v1 --payload "$w/p.json" >/dev/null 2>&1
export NUCLEO_TEST_SEED=$(printf "%064d" 9)
wk=$("$w/nucleo" witness key --db "$w/t.db" 2>/dev/null)
lp=$("$w/nucleo" --dir "$w/l" --json status 2>/dev/null | python3 -c "import json,sys;print(json.load(sys.stdin)[\"log_pubkey\"])")
"$w/nucleo" witness serve --addr 127.0.0.1:18997 --db "$w/t.db" --name w/1 --log-origin nucleoledger.com/bench --log-key "$lp" >"$w/t.log" 2>&1 &
p=$!; for _ in $(seq 1 50); do grep -q escuchando "$w/t.log" && break; sleep 0.2; done
unset NUCLEO_TEST_SEED
"$w/nucleo" --dir "$w/l" sync --witness http://127.0.0.1:18997 --witness-name w/1 --witness-key "$wk" >/dev/null 2>&1
"$w/nucleo" --dir "$w/l" receipt --block 0 --recipient "María Pérez (cédula 1712345678)" --out "$w/r.txt" --witness-name w/1 --witness-key "$wk" >/dev/null 2>&1
wc -c < "$w/r.txt" | tr -d " "')"

cat <<EOF
<!-- generado por scripts/bench-readme.sh · $fecha · commit $commit (árbol limpio) · $cpu · $gover · n=$n -->
| what | figure (median, range) | how it was measured |
|---|---|---|
| block sealing (JCS + SHA-256 + Ed25519), in memory | $seal_ps blocks/s | \`BenchmarkSeal\`, 1 s per sample |
| durable append (\`synchronous=FULL\`, one fsync each) | $append_ps blocks/s | \`BenchmarkAppendBlock\`, 1 s per sample |
| open, 10⁵ blocks, attestation **verified** (fast path) | $open_att | \`BenchmarkOpen\`, policy supplied, 1 open per sample |
| open, 10⁵ blocks, no policy (every signature recomputed) | $open_un | \`BenchmarkOpenUnattested\`, 1 open per sample |
| \`verify --full\`, 10⁵ blocks | $full | \`BenchmarkVerifyFull\`, 1 run per sample |
| Merkle root, 10⁵ leaves | $root | \`BenchmarkRoot\`, 1 s per sample |
| unlock the vault, \`default\` KDF profile (64 MiB) | $unlock_def | \`BenchmarkUnlockDefault\`, 10 unlocks per sample |
| unlock the vault, \`constrained\` KDF profile (19 MiB) | $unlock_con | \`BenchmarkUnlockConstrained\`, 10 unlocks per sample |
| one receipt, 1 witness, 1-block log: legal notice, block and issuer signatures, the log's Ed25519 and ML-DSA-44 signatures | **$recibo bytes** | emitted by the CLI and measured with \`wc -c\` (deterministic) |
| inclusion proof section alone (\`tlog-proof\`), 10⁵-entry log | $proof_bytes bytes | \`BenchmarkReceipt\`; the proof grows with log₂(n), the rest of the receipt does not |

Measured $fecha on commit \`$commit\`, clean tree ($cpu, $gover). Each time is the median of $n samples with the range beside it. Regenerate with \`./scripts/bench-readme.sh\`; it refuses to run on a dirty tree.
EOF
