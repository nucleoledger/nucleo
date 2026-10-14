#!/usr/bin/env bash
# tercero-supresion.sh — un tercero comprueba una supresión sin Núcleo (G45, PROTOCOL §5.1).
#
# Con el recibo del bloque suprimido, el del evento de supresión y la política, alguien que
# no tiene Núcleo comprueba que la supresión la autorizó la clave de supresión: python3
# para leer el JSON, sha256sum y openssl para la firma Ed25519. Es la receta de PROTOCOL
# §5.1, ejecutada; hasta el Sprint 20b vivía solo dentro del ensayo de actualización, que
# necesita red y no corre en el CI (G45 decía «sin test automatizado»).
#
#   ./scripts/tercero-supresion.sh
#       compila el HEAD, crea un ledger con una supresión autorizada —testigo en
#       127.0.0.1, sin red—, emite los dos recibos y los comprueba como un tercero. Y
#       comprueba que la comprobación muerde: con la erasureKey de otra clave, falla.
#       Lo llaman la compuerta y el CI.
#
#   ./scripts/tercero-supresion.sh comprueba RECIBO_BLOQUE RECIBO_EVENTO POLITICA
#       solo la comprobación del tercero, sobre recibos que ya existen. Lo llama
#       ensayo-actualizacion.sh con los de un despliegue que viene de un release anterior.
#
# Necesita: python3, sha256sum, openssl y xxd; sin argumentos, además go y `script` de
# util-linux (simula la consola donde la custodia teclea sus tarjetas). Sale con 0 si
# todo cuadra y con 1 si no.
#
# Lo que NO comprueba: que los recibos verifiquen como recibos (eso lo hacen los SDK y la
# CLI, con sus propios tests y el diferencial de los tres verificadores).
set -euo pipefail

RAIZ="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# comprueba RECIBO_BLOQUE RECIBO_EVENTO POLITICA: la receta de PROTOCOL §5.1. Escribe una
# línea ✔ o ✘ por comprobación y devuelve 1 si alguna falla.
comprueba() {
	local rb="$1" re="$2" pol="$3" d mal=0
	d="$(mktemp -d)"
	# El header de cada recibo es la primera línea de su sección de máquina.
	python3 - "$rb" "$re" "$pol" <<'EOF' >"$d/tercero.env"
import json, shlex, sys
def cabecera(f):
    return json.loads(open(f).read().split("--- prueba verificable ---\n")[1].split("\n")[0])
b, e = cabecera(sys.argv[1]), cabecera(sys.argv[2])
p = json.load(open(sys.argv[3]))
_, k, sig = e["payload_cid"].split(":")
for n, v in (("ORIGIN", p["origin"]), ("H", b["payload_hash"]), ("K", k), ("SIG", sig),
             ("ERASURE_KEY", p["erasureKey"]), ("BI", b["index"]), ("EI", e["index"]), ("EPH", e["payload_hash"])):
    print(f"{n}={shlex.quote(str(v))}")
EOF
	local ORIGIN H K SIG ERASURE_KEY BI EI EPH
	# shellcheck disable=SC1091 # lo escribe el bloque de arriba
	. "$d/tercero.env"
	if [ "$BI" -le "$K" ] && [ "$K" -lt "$EI" ]; then
		printf '   ✔ la autorización cubre el bloque (%s ≤ %s < %s)\n' "$BI" "$K" "$EI"
	else
		printf '   ✘ la autorización no cubre el bloque (%s, %s, %s)\n' "$BI" "$K" "$EI"
		mal=1
	fi
	if [ "$(printf '{"erased_payload_hash":"%s"}' "$H" | sha256sum | cut -d' ' -f1)" = "$EPH" ]; then
		printf '   ✔ el evento suprime el contenido del bloque\n'
	else
		printf '   ✘ el evento no suprime ese contenido\n'
		mal=1
	fi
	printf 'nucleo.org/erasure-authorization@v1\norigin %s\nerased_payload_hash %s\nthrough %s\n' \
		"$ORIGIN" "$H" "$K" | sha256sum | cut -d' ' -f1 | xxd -r -p >"$d/digest.bin"
	(printf '302a300506032b6570032100' && printf %s "$ERASURE_KEY") | xxd -r -p |
		openssl pkey -pubin -inform DER -out "$d/erasure.pem"
	printf %s "$SIG" | xxd -r -p >"$d/sig.bin"
	if openssl pkeyutl -verify -rawin -pubin -inkey "$d/erasure.pem" -in "$d/digest.bin" -sigfile "$d/sig.bin" >/dev/null 2>&1; then
		printf '   ✔ la firma de la autorización verifica con openssl y la erasureKey de la política\n'
	else
		printf '   ✘ la firma de la autorización no verifica con openssl\n'
		mal=1
	fi
	rm -rf "$d"
	return $mal
}

if [ "${1:-}" = comprueba ]; then
	[ $# -eq 4 ] || {
		echo "uso: $0 comprueba RECIBO_BLOQUE RECIBO_EVENTO POLITICA" >&2
		exit 1
	}
	comprueba "$2" "$3" "$4"
	exit
fi
[ $# -eq 0 ] || {
	echo "uso: $0   o   $0 comprueba RECIBO_BLOQUE RECIBO_EVENTO POLITICA" >&2
	exit 1
}

for orden in go python3 sha256sum openssl xxd script; do
	command -v "$orden" >/dev/null || {
		echo "falta \`$orden\`: el script lo necesita (ver su cabecera)" >&2
		exit 1
	}
done

T="$(mktemp -d)"
PID_TESTIGO=""
limpia() {
	[ -n "$PID_TESTIGO" ] && kill "$PID_TESTIGO" 2>/dev/null || true
	wait 2>/dev/null || true
	rm -rf "$T"
}
trap limpia EXIT
trap 'exit 130' INT TERM

# Un binario de producción: sin ganchos de prueba.
for v in NUCLEO_TEST_SEED NUCLEO_TEST_CLOCK NUCLEO_TEST_PASSPHRASE NUCLEO_TEST_DIE_AT NUCLEO_TEST_PAUSE_AT NUCLEO_TEST_CARDS; do
	unset "$v"
done
campo() { python3 -c "import json,sys; print(json.load(sys.stdin)$1)"; }
# corre ORDEN…: la ejecuta con la salida en $T/ult.out y $T/ult.err; si falla, la enseña.
corre() {
	if ! "$@" >"$T/ult.out" 2>"$T/ult.err"; then
		echo "✘ falló: $*" >&2
		tail -n 20 "$T/ult.err" "$T/ult.out" >&2
		exit 1
	fi
}

N="$T/nucleo"
(cd "$RAIZ" && go build -o "$N" ./cmd/nucleo)
E="$T/emp"
O=tercero.example/empresa
printf 'passphrase del tercero, larga de verdad\n' >"$T/pass"
chmod 600 "$T/pass"
P=(--passphrase-file "$T/pass")

# El ledger, con dos registros. El perfil constrained: es un ledger de usar y tirar.
corre "$N" --dir "$E" init --origin "$O" "${P[@]}" --assume-confirmed --kdf-profile constrained
for i in 0 1; do
	printf '{"venta":"00%s","nonce":"%s"}' "$i" "$(openssl rand -hex 16)" >"$T/d$i.json"
	corre "$N" --dir "$E" seal --tenant 1790012345001 --type sri.factura.v1 --payload "$T/d$i.json" "${P[@]}"
done

# El testigo, en 127.0.0.1: los recibos llevan su cosignature.
mkdir -p "$T/testigo"
LOGPUB="$("$N" --dir "$E" --json status 2>/dev/null | campo "['log_pubkey']")"
WKEY="$("$N" witness key --db "$T/testigo/t.db")"
"$N" witness serve --addr 127.0.0.1:0 --db "$T/testigo/t.db" --name tercero.example/w1 \
	--log-origin "$O" --log-key "$LOGPUB" >"$T/testigo/log" 2>&1 &
PID_TESTIGO=$!
URL=""
for _ in $(seq 1 100); do
	if grep -q "escuchando en" "$T/testigo/log"; then
		URL="$(grep -o 'http://[^ ]*' "$T/testigo/log" | head -1)"
		break
	fi
	sleep 0.1
done
[ -n "$URL" ] || {
	echo "el testigo no arrancó:" >&2
	cat "$T/testigo/log" >&2
	exit 1
}
corre "$N" --dir "$E" --json sync --witness "$URL" --witness-name tercero.example/w1 --witness-key "$WKEY" "${P[@]}"
cp "$T/ult.out" "$T/sync.json"

# La clave de supresión, y la política que da sync con su erasureKey. Otra clave más, para
# comprobar al final que la comprobación muerde.
corre "$N" --json erasure-key init --assume-confirmed
cp "$T/ult.out" "$T/clave.json"
corre "$N" --json erasure-key init --assume-confirmed
cp "$T/ult.out" "$T/otra.json"
python3 - "$T" <<'EOF'
import json, sys
T = sys.argv[1]
p = json.load(open(T + "/sync.json"))["policy"]
k = json.load(open(T + "/clave.json"))
p["erasureKey"] = k["erasure_key"]
json.dump(p, open(T + "/politica.json", "w"))
p["erasureKey"] = json.load(open(T + "/otra.json"))["erasure_key"]
json.dump(p, open(T + "/politica-otra.json", "w"))
# Dos tarjetas de supresión y la línea vacía con que se termina de teclearlas.
open(T + "/tarjetas", "w").write("\n".join(k["shares"][:2]) + "\n\n")
EOF

# Suprimir el bloque 0 como se hace: erase sin autorización da la orden para la custodia,
# la custodia la ejecuta tal cual y teclea sus tarjetas en una consola —`script` la
# simula; la salida no se enseña, porque la consola repite lo tecleado—, y erase suprime
# con esa autorización.
"$N" --dir "$E" erase --block 0 --policy-file "$T/politica.json" "${P[@]}" --assume-confirmed >/dev/null 2>"$T/erase.err" || true
ORDEN="$(grep -o 'nucleo erasure-key authorize .*' "$T/erase.err" || true)"
[ -n "$ORDEN" ] || {
	echo "✘ erase sin autorización no dio la orden para la custodia:" >&2
	cat "$T/erase.err" >&2
	exit 1
}
script -qec "$(printf '%q --json %s' "$N" "${ORDEN#nucleo }")" /dev/null <"$T/tarjetas" >"$T/aut.out" 2>&1 || true
AUT="$(grep -o 'nucleo-erasure-auth@v1:[0-9]*:[0-9a-f]\{128\}' "$T/aut.out" | head -1 || true)"
[ -n "$AUT" ] || {
	echo "✘ erasure-key authorize no dio la autorización" >&2
	exit 1
}
corre "$N" --dir "$E" erase --block 0 --policy-file "$T/politica.json" --authorization "$AUT" "${P[@]}" --assume-confirmed
corre "$N" --dir "$E" sync --witness "$URL" --policy-file "$T/politica.json" "${P[@]}"
EV=$(($("$N" --dir "$E" --json status 2>/dev/null | campo "['tree_size']") - 1))
corre "$N" --dir "$E" receipt --block 0 --recipient "Auditoría" --out "$T/recibo-bloque.txt" --policy-file "$T/politica.json" "${P[@]}"
corre "$N" --dir "$E" receipt --block "$EV" --recipient "Auditoría" --out "$T/recibo-evento.txt" --policy-file "$T/politica.json" "${P[@]}"
printf '   ledger nuevo con el HEAD (%s): bloque 0 suprimido con autorización, evento en el bloque %s\n' \
	"$(cd "$RAIZ" && git log --oneline -1 | cut -c1-7)" "$EV"

# Lo que hace el tercero, sin Núcleo.
mal=0
comprueba "$T/recibo-bloque.txt" "$T/recibo-evento.txt" "$T/politica.json" || mal=1
# Y que muerde: con la erasureKey de otra clave, la firma no verifica.
if comprueba "$T/recibo-bloque.txt" "$T/recibo-evento.txt" "$T/politica-otra.json" >"$T/otra.out"; then
	printf '   ✘ con la erasureKey de OTRA clave, la comprobación también pasa: no muerde\n'
	mal=1
elif grep -q '✘ la firma de la autorización no verifica' "$T/otra.out"; then
	printf '   ✔ y con la erasureKey de otra clave, la firma no verifica: la comprobación muerde\n'
else
	printf '   ✘ con la erasureKey de otra clave falla, pero no por la firma:\n'
	sed 's/^/     /' "$T/otra.out"
	mal=1
fi
if [ "$mal" = 0 ]; then
	echo "✔ el tercero comprueba la supresión con sha256sum y openssl"
else
	echo "✘ la comprobación del tercero falló"
	exit 1
fi
