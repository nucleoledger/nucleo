#!/usr/bin/env bash
# Regenera la tabla de benchmarks del README sobre el commit actual.
#
# Imprime la tabla en Markdown, con fecha, commit y máquina, para pegarla tal cual.
# Corre con la máquina en reposo: los benchmarks de apertura con 10^5 bloques son
# sensibles a la carga, y este proyecto ya midió un 20 % de varianza entre días con
# el mismo código. Un número sin fecha ni commit no es una medición: es un recuerdo.
#
#   ./scripts/bench-readme.sh            # tabla completa (~3 min)
#   ./scripts/bench-readme.sh --quick    # 1x en vez de 3x, para comprobar el script
set -euo pipefail
cd "$(dirname "$0")/.."

veces=3x
[[ "${1:-}" == "--quick" ]] && veces=1x

commit="$(git rev-parse --short HEAD)"
fecha="$(date -u +%Y-%m-%d)"
cpu="$(grep -m1 'model name' /proc/cpuinfo 2>/dev/null | sed 's/.*: //' | sed 's/ \+/ /g' || sysctl -n machdep.cpu.brand_string 2>/dev/null || echo desconocida)"

# ns/op → texto legible.
humano() {
  python3 -c '
import sys
ns=float(sys.argv[1])
if ns>=1e9: print("%.2f s"%(ns/1e9))
elif ns>=1e6: print("%.0f ms"%(ns/1e6))
elif ns>=1e3: print("%.0f µs"%(ns/1e3))
else: print("%.0f ns"%ns)' "$1"
}

tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT
go test -run='^$' -bench='BenchmarkOpen(Unattested)?/bloques=1e5|BenchmarkVerifyFull/bloques=1e5|BenchmarkUnlock' \
  -benchtime="$veces" -benchmem ./internal/store ./internal/vault 2>/dev/null > "$tmp"

valor() { grep -E "^$1" "$tmp" | awk '{print $3}' | head -1; }

open_att="$(humano "$(valor 'BenchmarkOpen/bloques=1e5')")"
open_un="$(humano "$(valor 'BenchmarkOpenUnattested/bloques=1e5')")"
full="$(humano "$(valor 'BenchmarkVerifyFull/bloques=1e5')")"
unlock_def="$(humano "$(valor 'BenchmarkUnlockDefault')")"
unlock_con="$(humano "$(valor 'BenchmarkUnlockConstrained')")"

# Tamaño real de un recibo: se emite uno con el criterio de éxito y se mide.
recibo="$(bash -c '
set -e
export NUCLEO_TEST_CLOCK=2026-09-07T10:00:00Z NUCLEO_TEST_PASSPHRASE=x NUCLEO_TEST_SEED=$(printf "%064d" 7)
w=$(mktemp -d); trap "rm -rf $w" EXIT
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
kill $p 2>/dev/null || true
wc -c < "$w/r.txt"' 2>/dev/null || echo "?")"

cat <<EOF
<!-- generado por scripts/bench-readme.sh · $fecha · commit $commit · $cpu -->
| what | figure | how it was measured |
|---|---|---|
| open, 10⁵ blocks, attestation **verified** (fast path) | **$open_att** | \`BenchmarkOpen\`, policy supplied, $veces |
| open, 10⁵ blocks, no policy (every signature recomputed) | **$open_un** | \`BenchmarkOpenUnattested\`, $veces |
| \`verify --full\`, 10⁵ blocks | **$full** | \`BenchmarkVerifyFull\`, $veces |
| unlock the vault, \`default\` KDF profile (64 MiB) | **$unlock_def** | \`BenchmarkUnlockDefault\` |
| unlock the vault, \`constrained\` KDF profile (19 MiB) | **$unlock_con** | \`BenchmarkUnlockConstrained\` |
| one receipt, 1 witness, 1-block log, with legal notice and both signatures | **$recibo bytes** | emitted by the CLI and measured with \`wc -c\` |

Measured $fecha on commit \`$commit\` ($cpu). Regenerate with \`./scripts/bench-readme.sh\`.
EOF
