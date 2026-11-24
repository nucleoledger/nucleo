#!/usr/bin/env bash
# tercero-anulacion.sh — un tercero comprueba una anulación sin Núcleo (ADR-035, PROTOCOL
# 0.9-draft §5.2, «A third party, without Núcleo»).
#
# Con el recibo de la factura y el de su anulación, alguien que no tiene Núcleo comprueba
# que el evento anula ESA factura: python3 para leer el header de cada recibo, y printf y
# sha256sum para el contenido del evento. No hay firma que comprobar aparte: la anulación la
# firma el tenant, como cualquier bloque, y esa firma ya va en el recibo.
#
#   ./scripts/tercero-anulacion.sh
#       el modo completo: compila el HEAD, crea un ledger con dos facturas, anula la segunda
#       con `nucleo void --block 1` —testigo en 127.0.0.1—, emite los dos recibos y los
#       comprueba como un tercero. Comprueba además que la comprobación muerde (con el
#       recibo de OTRA factura, falla) y que reconcile la enseña en voided con código 0. Lo
#       llaman la compuerta y el CI.
#
#   NUCLEO_BIN=<binario ya compilado> ./scripts/tercero-anulacion.sh
#       el modo completo con ese binario, sin compilar (y entonces sin go).
#
#   ./scripts/tercero-anulacion.sh comprueba RECIBO_FACTURA RECIBO_ANULACION
#       solo la comprobación del tercero, sobre recibos que ya existen. Sin Núcleo y sin red.
#
# La red: «comprueba» no la necesita. El modo completo no abre más conexión que la del
# testigo en 127.0.0.1 y compila con GOPROXY=off y GOFLAGS=-mod=readonly, como
# tercero-supresion.sh; si faltan módulos en la caché, sale con 1 y dice la orden que los baja.
#
# Necesita: python3 y sha256sum; en el modo completo, además openssl (para el nonce de las
# facturas) y go con los módulos en caché, o NUCLEO_BIN. Sale con 0 si todo cuadra y con 1
# si no.
#
# Lo que NO comprueba: que los recibos verifiquen como recibos (eso lo hacen los SDK y la
# CLI, con sus tests y el diferencial; el de una anulación es valido-anulacion), ni que el
# SRI anulara la factura: la anulación es la declaración del emisor (GARANTIAS L24).
set -euo pipefail

RAIZ="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# comprueba RECIBO_FACTURA RECIBO_ANULACION: las cuatro comprobaciones de PROTOCOL §5.2.
# Escribe una línea ✔ o ✘ por comprobación y devuelve 1 si alguna falla.
comprueba() {
	local rf="$1" ra="$2" d mal=0
	d="$(mktemp -d)"
	# El header de cada recibo es la primera línea de su sección de máquina.
	python3 - "$rf" "$ra" <<'EOF' >"$d/tercero.env"
import json, shlex, sys
def cabecera(f):
    return json.loads(open(f, encoding="utf-8").read().split("--- prueba verificable ---\n")[1].split("\n")[0])
f, a = cabecera(sys.argv[1]), cabecera(sys.argv[2])
for n, v in (("FI", f["index"]), ("FH", f["payload_hash"]), ("FT", f["tenant"]),
             ("AI", a["index"]), ("AH", a["payload_hash"]), ("AT", a["tenant"]),
             ("ATYPE", a["type"]), ("ACID", a["payload_cid"])):
    print(f"{n}={shlex.quote(str(v))}")
EOF
	local FI FH FT AI AH AT ATYPE ACID
	# shellcheck disable=SC1091 # lo escribe el bloque de arriba
	. "$d/tercero.env"
	rm -rf "$d"
	if [ "$ATYPE" = nucleo.void.v1 ]; then
		printf '   ✔ el segundo recibo es de un evento de anulación (nucleo.void.v1)\n'
	else
		printf '   ✘ el segundo recibo no es de un evento de anulación: su tipo es %s\n' "$ATYPE"
		mal=1
	fi
	if [ "$ACID" = "nucleo-void@v1:$FI" ]; then
		printf '   ✔ su payload_cid es nucleo-void@v1:%s, el índice de la factura\n' "$FI"
	else
		printf '   ✘ su payload_cid es %s, y la factura es el bloque %s\n' "$ACID" "$FI"
		mal=1
	fi
	if [ "$FI" -lt "$AI" ]; then
		printf '   ✔ la factura es anterior a la anulación (%s < %s)\n' "$FI" "$AI"
	else
		printf '   ✘ la factura no es anterior a la anulación (%s, %s)\n' "$FI" "$AI"
		mal=1
	fi
	if [ "$FT" = "$AT" ]; then
		printf '   ✔ las dos son del mismo tenant (%s)\n' "$FT"
	else
		printf '   ✘ la factura es de %s y la anulación de %s\n' "$FT" "$AT"
		mal=1
	fi
	if [ "$(printf '{"voided_index":"%s","voided_payload_hash":"%s"}' "$FI" "$FH" | sha256sum | cut -d' ' -f1)" = "$AH" ]; then
		printf '   ✔ el payload_hash de la anulación es el SHA-256 de su contenido para esa factura\n'
	else
		printf '   ✘ el payload_hash de la anulación no corresponde a esa factura\n'
		mal=1
	fi
	return $mal
}

if [ "${1:-}" = comprueba ]; then
	[ $# -eq 3 ] || {
		echo "uso: $0 comprueba RECIBO_FACTURA RECIBO_ANULACION" >&2
		exit 1
	}
	comprueba "$2" "$3"
	exit
fi
[ $# -eq 0 ] || {
	echo "uso: $0   o   $0 comprueba RECIBO_FACTURA RECIBO_ANULACION" >&2
	exit 1
}

necesita=(python3 sha256sum openssl)
[ -n "${NUCLEO_BIN:-}" ] || necesita+=(go)
for orden in "${necesita[@]}"; do
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

if [ -n "${NUCLEO_BIN:-}" ]; then
	[ -x "$NUCLEO_BIN" ] || {
		echo "NUCLEO_BIN=$NUCLEO_BIN no es un fichero ejecutable" >&2
		exit 1
	}
	N="$NUCLEO_BIN"
else
	N="$T/nucleo"
	# Sin red: solo con los módulos que ya están en la caché, y sin tocar go.mod ni go.sum.
	if ! (cd "$RAIZ" && GOPROXY=off GOFLAGS=-mod=readonly go build -o "$N" ./cmd/nucleo) 2>"$T/build.err"; then
		cat "$T/build.err" >&2
		if grep -q 'GOPROXY=off\|module lookup disabled\|toolchain not available' "$T/build.err"; then
			echo "✘ faltan módulos (o la toolchain que pide go.mod) en la caché de Go, y este script no usa la red para bajarlos." >&2
			echo "  Bájalos aparte —eso sí usa red— y repite:" >&2
			printf '    (cd %q && go mod download)\n' "$RAIZ" >&2
			echo "  o pásale un binario ya compilado: NUCLEO_BIN=<binario> $0" >&2
		fi
		exit 1
	fi
fi
E="$T/emp"
O=tercero.example/anulacion
printf 'passphrase del tercero, larga de verdad\n' >"$T/pass"
chmod 600 "$T/pass"
P=(--passphrase-file "$T/pass")

# El ledger, con dos facturas. El perfil constrained: es un ledger de usar y tirar.
corre "$N" --dir "$E" init --origin "$O" "${P[@]}" --assume-confirmed --kdf-profile constrained
: >"$T/vivo.jsonl"
for i in 0 1; do
	printf '{"factura":"00%s","nonce":"%s"}' "$i" "$(openssl rand -hex 16)" >"$T/f$i.json"
	corre "$N" --dir "$E" seal --tenant 1790012345001 --type sri.factura.v1 --payload "$T/f$i.json" "${P[@]}"
	printf '{"index":%s,"payload_b64":"%s"}\n' "$i" "$(base64 -w0 "$T/f$i.json")" >>"$T/vivo.jsonl"
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
python3 -c "import json,sys; json.dump(json.load(open(sys.argv[1]))['policy'], open(sys.argv[2], 'w'))" \
	"$T/ult.out" "$T/politica.json"

# La anulación, como la hace el ERP: con el índice que guardó al sellar (OPERACION §6).
corre "$N" --dir "$E" --json void --block 1 --policy-file "$T/politica.json" "${P[@]}"
EV="$(campo "['index']" <"$T/ult.out")"
corre "$N" --dir "$E" sync --witness "$URL" --policy-file "$T/politica.json" "${P[@]}"
for b in 0 1 "$EV"; do
	corre "$N" --dir "$E" receipt --block "$b" --recipient "Auditoría" --out "$T/recibo-$b.txt" --policy-file "$T/politica.json" "${P[@]}"
done
printf '   ledger nuevo con el HEAD (%s): la factura del bloque 1, anulada en el bloque %s\n' \
	"$(cd "$RAIZ" && git log --oneline -1 | cut -c1-7)" "$EV"

# Lo que hace el tercero, sin Núcleo.
mal=0
comprueba "$T/recibo-1.txt" "$T/recibo-$EV.txt" || mal=1
# Y que muerde: con el recibo de OTRA factura, la anulación no es suya.
if comprueba "$T/recibo-0.txt" "$T/recibo-$EV.txt" >"$T/otra.out"; then
	printf '   ✘ con el recibo de OTRA factura, la comprobación también pasa: no muerde\n'
	mal=1
elif grep -q '✘ su payload_cid es nucleo-void@v1:1, y la factura es el bloque 0' "$T/otra.out" &&
	grep -q '✘ el payload_hash de la anulación no corresponde a esa factura' "$T/otra.out"; then
	printf '   ✔ y con el recibo de otra factura, ni el payload_cid ni el hash casan: la comprobación muerde\n'
else
	printf '   ✘ con el recibo de otra factura falla, pero no por el payload_cid y el hash:\n'
	sed 's/^/     /' "$T/otra.out"
	mal=1
fi

# reconcile la enseña en voided, y la factura anulada sigue cotejándose: código 0.
codigo=0
"$N" --dir "$E" --json reconcile --source "$T/vivo.jsonl" --policy-file "$T/politica.json" >"$T/rec.json" 2>/dev/null || codigo=$?
if [ "$codigo" = 0 ] && python3 - "$T/rec.json" "$EV" <<'EOF'; then
import json, sys
r = json.load(open(sys.argv[1]))
assert r["findings"] == [], r["findings"]
assert [(v["index"], v["voided_by"]) for v in r["voided"]] == [(1, int(sys.argv[2]))], r["voided"]
assert r["verified"] == 2, r["verified"]
EOF
	printf '   ✔ reconcile: la factura 1, anulada por el bloque %s (voided), y las dos verificadas; código 0\n' "$EV"
else
	printf '   ✘ reconcile no enseña la anulación como debe (código %s)\n' "$codigo"
	sed 's/^/     /' "$T/rec.json" | head -40
	mal=1
fi

if [ "$mal" = 0 ]; then
	echo "✔ el tercero comprueba la anulación con printf y sha256sum"
else
	echo "✘ la comprobación del tercero falló"
	exit 1
fi
