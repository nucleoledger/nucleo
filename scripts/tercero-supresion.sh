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
#       el modo completo: compila el HEAD, crea un ledger con una supresión autorizada
#       —testigo en 127.0.0.1—, emite los dos recibos y los comprueba como un tercero. Y
#       comprueba que la comprobación muerde: con la erasureKey de otra clave, falla.
#       Después rota la clave de supresión como dice docs/OPERACION.md §3 (ADR-033: la
#       vieja a retiredErasureKeys con el corte que imprime sync) y exige que la supresión
#       de la clave vieja anterior al corte siga autorizada para el tercero; que una
#       posterior al corte no lo esté, ni para el tercero ni para reconcile; y que una
#       supresión posterior con la clave nueva la regularice (erase lo avisa; reconcile
#       --json da regularized_by). Lo llaman la compuerta y el CI.
#
#   NUCLEO_BIN=<binario ya compilado> ./scripts/tercero-supresion.sh
#       el modo completo con ese binario, sin compilar (y entonces sin go).
#
#   ./scripts/tercero-supresion.sh comprueba RECIBO_BLOQUE RECIBO_EVENTO POLITICA
#       solo la comprobación del tercero, sobre recibos que ya existen. Lo llama
#       ensayo-actualizacion.sh con los de un despliegue que viene de un release anterior.
#       Elige la clave por el índice del evento (PROTOCOL §5.1): la erasureKey, o una de
#       retiredErasureKeys cuyo corte sea ≥ ese índice; basta con que verifique una.
#
# La red (H9 de la revisión del 2026-10-14). «comprueba» no necesita ni Núcleo ni red. El
# modo completo no abre más conexión que la del testigo en 127.0.0.1, pero compila con go,
# que en una máquina sin los módulos en la caché los bajaría de GOPROXY: por eso compila
# con GOPROXY=off y GOFLAGS=-mod=readonly, y si faltan módulos sale con 1 diciendo la
# orden que los baja (`go mod download`, que SÍ usa red y se ejecuta aparte, a la vista;
# el job del CI lo hace en un paso propio antes de llamar a este script). Con NUCLEO_BIN
# no compila y no hace falta ni la caché.
#
# Necesita: python3, sha256sum, openssl y xxd; en el modo completo, además `script` de
# util-linux (simula la consola donde la custodia teclea sus tarjetas) y go con los
# módulos en caché, o NUCLEO_BIN. Sale con 0 si todo cuadra y con 1 si no.
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
# Las claves candidatas, por el índice del evento (PROTOCOL §5.1, «A third party»): la
# erasureKey, sea cual sea el índice, y cada clave retirada cuyo corte sea ≥ ese índice.
# Cada una con la frase que dice cuál es.
candidatas = []
if "erasureKey" in p:
    candidatas.append((p["erasureKey"], "la erasureKey de la política"))
for kr, corte in sorted(p.get("retiredErasureKeys", {}).items()):
    if e["index"] <= corte:
        candidatas.append((kr, f"la clave retirada {kr[:16]}… (corte {corte} ≥ índice {e['index']})"))
for n, v in (("ORIGIN", p["origin"]), ("H", b["payload_hash"]), ("K", k), ("SIG", sig),
             ("BI", b["index"]), ("EI", e["index"]), ("EPH", e["payload_hash"]),
             ("CLAVES", " ".join(c for c, _ in candidatas)),
             ("NOMBRES", "\n".join(nm for _, nm in candidatas))):
    print(f"{n}={shlex.quote(str(v))}")
EOF
	local ORIGIN H K SIG BI EI EPH CLAVES NOMBRES
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
	printf %s "$SIG" | xxd -r -p >"$d/sig.bin"
	# Basta con que verifique una de las candidatas (PROTOCOL §5.1).
	local clave i=0 con=""
	for clave in $CLAVES; do
		i=$((i + 1))
		(printf '302a300506032b6570032100' && printf %s "$clave") | xxd -r -p |
			openssl pkey -pubin -inform DER -out "$d/erasure.pem"
		if openssl pkeyutl -verify -rawin -pubin -inkey "$d/erasure.pem" -in "$d/digest.bin" -sigfile "$d/sig.bin" >/dev/null 2>&1; then
			con="$(printf '%b\n' "$NOMBRES" | sed -n "${i}p")"
			break
		fi
	done
	if [ -n "$con" ]; then
		printf '   ✔ la firma de la autorización verifica con openssl y %s\n' "$con"
	elif [ -z "$CLAVES" ]; then
		printf '   ✘ la firma de la autorización no verifica: la política no tiene ninguna clave que autorice el índice %s\n' "$EI"
		mal=1
	else
		printf '   ✘ la firma de la autorización no verifica con openssl con ninguna clave que la política admite para el índice %s\n' "$EI"
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

necesita=(python3 sha256sum openssl xxd script)
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

# suprime BLOQUE POLITICA TARJETAS: suprime como se hace. erase sin autorización da la
# orden para la custodia, la custodia la ejecuta tal cual y teclea sus tarjetas en una
# consola —`script` la simula; la salida no se enseña, porque la consola repite lo
# tecleado—, y erase suprime con esa autorización. Deja el índice del evento en $EV_ULT, y
# la salida (--json) y el stderr de ese último erase en $T/erase.out y $T/erase.err.
suprime() {
	local bloque="$1" pol="$2" tarjetas="$3" orden aut
	"$N" --dir "$E" erase --block "$bloque" --policy-file "$pol" "${P[@]}" --assume-confirmed >/dev/null 2>"$T/erase.err" || true
	orden="$(grep -o 'nucleo erasure-key authorize .*' "$T/erase.err" || true)"
	[ -n "$orden" ] || {
		echo "✘ erase del bloque $bloque sin autorización no dio la orden para la custodia:" >&2
		cat "$T/erase.err" >&2
		exit 1
	}
	script -qec "$(printf '%q --json %s' "$N" "${orden#nucleo }")" /dev/null <"$tarjetas" >"$T/aut.out" 2>&1 || true
	aut="$(grep -o 'nucleo-erasure-auth@v1:[0-9]*:[0-9a-f]\{128\}' "$T/aut.out" | head -1 || true)"
	[ -n "$aut" ] || {
		echo "✘ erasure-key authorize no dio la autorización para el bloque $bloque" >&2
		exit 1
	}
	if ! "$N" --dir "$E" --json erase --block "$bloque" --policy-file "$pol" --authorization "$aut" "${P[@]}" \
		--assume-confirmed >"$T/erase.out" 2>"$T/erase.err"; then
		echo "✘ falló erase del bloque $bloque con la autorización:" >&2
		tail -n 20 "$T/erase.err" >&2
		exit 1
	fi
	EV_ULT="$(campo "['index']" <"$T/erase.out")"
}
# recibos BLOQUE EVENTO POLITICA SUFIJO: sincroniza y emite los recibos del bloque y del
# evento, en $T/recibo-bloque-SUFIJO.txt y $T/recibo-evento-SUFIJO.txt.
recibos() {
	corre "$N" --dir "$E" sync --witness "$URL" --policy-file "$3" "${P[@]}"
	corre "$N" --dir "$E" receipt --block "$1" --recipient "Auditoría" --out "$T/recibo-bloque-$4.txt" --policy-file "$3" "${P[@]}"
	corre "$N" --dir "$E" receipt --block "$2" --recipient "Auditoría" --out "$T/recibo-evento-$4.txt" --policy-file "$3" "${P[@]}"
}

suprime 0 "$T/politica.json" "$T/tarjetas"
EV="$EV_ULT"
recibos 0 "$EV" "$T/politica.json" 0
printf '   ledger nuevo con el HEAD (%s): bloque 0 suprimido con autorización, evento en el bloque %s\n' \
	"$(cd "$RAIZ" && git log --oneline -1 | cut -c1-7)" "$EV"

# Lo que hace el tercero, sin Núcleo.
mal=0
comprueba "$T/recibo-bloque-0.txt" "$T/recibo-evento-0.txt" "$T/politica.json" || mal=1
# Y que muerde: con la erasureKey de otra clave, la firma no verifica.
if comprueba "$T/recibo-bloque-0.txt" "$T/recibo-evento-0.txt" "$T/politica-otra.json" >"$T/otra.out"; then
	printf '   ✘ con la erasureKey de OTRA clave, la comprobación también pasa: no muerde\n'
	mal=1
elif grep -q '✘ la firma de la autorización no verifica' "$T/otra.out"; then
	printf '   ✔ y con la erasureKey de otra clave, la firma no verifica: la comprobación muerde\n'
else
	printf '   ✘ con la erasureKey de otra clave falla, pero no por la firma:\n'
	sed 's/^/     /' "$T/otra.out"
	mal=1
fi

# ---------------------------------------------------------------------------------
# La rotación de la clave de supresión (ADR-033), como la cuenta docs/OPERACION.md §3: la
# clave vieja pasa a retiredErasureKeys con el corte que imprime sync, y la política nueva
# lleva una erasureKey nueva.
echo "   rotación de la clave de supresión (ADR-033):"
corre "$N" --dir "$E" --json sync --witness "$URL" --policy-file "$T/politica.json" "${P[@]}"
cp "$T/ult.out" "$T/sync-rotacion.json"
corre "$N" --json erasure-key init --assume-confirmed
cp "$T/ult.out" "$T/nueva.json"
CORTE="$(python3 - "$T" <<'EOF'
import json, sys
T = sys.argv[1]
s = json.load(open(T + "/sync-rotacion.json"))
vieja = json.load(open(T + "/clave.json"))["erasure_key"]
k = json.load(open(T + "/nueva.json"))
p = s["policy"]
# El fragmento que imprime sync, tal cual: la clave vieja con su corte.
p["retiredErasureKeys"] = s["erasure_rotation"]["retiredErasureKeys"]
p["erasureKey"] = k["erasure_key"]
json.dump(p, open(T + "/politica-rotada.json", "w"))
open(T + "/tarjetas-nueva", "w").write("\n".join(k["shares"][:2]) + "\n\n")
print(p["retiredErasureKeys"].get(vieja, "ninguno"))
EOF
)"
if [ "$CORTE" = "$EV" ]; then
	printf '   ✔ sync da el fragmento de retiredErasureKeys: la clave vieja, con corte %s (su evento)\n' "$CORTE"
else
	printf '   ✘ el corte de la clave vieja en el fragmento de sync es %s, y su evento es el %s\n' "$CORTE" "$EV"
	mal=1
fi
# La política nueva se comprueba antes de repartirla: abre este ledger con atestación.
"$N" --dir "$E" --json status --policy-file "$T/politica-rotada.json" >"$T/st-rotada.json" 2>/dev/null || true
if [ "$(campo "['attestation']" <"$T/st-rotada.json" 2>/dev/null || true)" = verified ]; then
	printf '   ✔ la política rotada abre el ledger con la atestación verificada\n'
else
	printf '   ✘ la política rotada no abre el ledger con la atestación verificada\n'
	mal=1
fi

# 1. La supresión de la clave vieja ANTERIOR al corte sigue autorizada para el tercero.
if comprueba "$T/recibo-bloque-0.txt" "$T/recibo-evento-0.txt" "$T/politica-rotada.json" >"$T/antes.out" &&
	grep -q 'verifica con openssl y la clave retirada' "$T/antes.out"; then
	printf '   ✔ la supresión de la clave vieja anterior al corte (evento %s) sigue autorizada para el tercero, con la política rotada\n' "$EV"
else
	printf '   ✘ con la política rotada, el tercero ya no da por autorizada la supresión del evento %s:\n' "$EV"
	sed 's/^/     /' "$T/antes.out"
	mal=1
fi

# 2. Una supresión de la clave vieja POSTERIOR al corte: alguien con la política vieja y
# las tarjetas viejas suprime el bloque 1. Para el tercero y para reconcile, con la
# política rotada, no está autorizada.
suprime 1 "$T/politica.json" "$T/tarjetas"
EV2="$EV_ULT"
recibos 1 "$EV2" "$T/politica-rotada.json" 1
if comprueba "$T/recibo-bloque-1.txt" "$T/recibo-evento-1.txt" "$T/politica-rotada.json" >"$T/despues.out"; then
	printf '   ✘ la supresión de la clave vieja posterior al corte (evento %s) pasa por autorizada para el tercero:\n' "$EV2"
	sed 's/^/     /' "$T/despues.out"
	mal=1
elif grep -q '✘ la firma de la autorización no verifica' "$T/despues.out"; then
	printf '   ✔ la supresión de la clave vieja posterior al corte (evento %s > %s) no está autorizada para el tercero\n' "$EV2" "$CORTE"
else
	printf '   ✘ la supresión posterior al corte falla para el tercero, pero no por la firma:\n'
	sed 's/^/     /' "$T/despues.out"
	mal=1
fi
: >"$T/vivo.jsonl"
codigo=0
"$N" --dir "$E" --json reconcile --source "$T/vivo.jsonl" --policy-file "$T/politica-rotada.json" >"$T/rec1.json" 2>/dev/null || codigo=$?
if [ "$codigo" = 2 ] && python3 - "$T/rec1.json" "$EV2" <<'EOF'; then
import json, sys
r = json.load(open(sys.argv[1]))
ev = int(sys.argv[2])
assert any(f["status"] == "supresión no autorizada" and f["index"] == ev for f in r["findings"]), r["findings"]
assert r["regularized"] == [], r["regularized"]
EOF
	printf '   ✔ y reconcile, con la política rotada, la señala como supresión no autorizada (código 2)\n'
else
	printf '   ✘ reconcile con la política rotada no señala la supresión del evento %s como no autorizada (código %s)\n' "$EV2" "$codigo"
	mal=1
fi

# 3. Una supresión posterior con la clave nueva la regulariza: erase lo avisa antes de
# sellar, y reconcile la lista en regularized con regularized_by.
suprime 1 "$T/politica-rotada.json" "$T/tarjetas-nueva"
EV3="$EV_ULT"
if grep -q "REGULARIZA la supresión no autorizada del evento $EV2" "$T/erase.err" &&
	[ "$(campo ".get('regularizes', [{}])[0].get('index')" <"$T/erase.out")" = "$EV2" ]; then
	printf '   ✔ erase con la clave nueva avisa de que regulariza el evento %s, y lo dice en regularizes\n' "$EV2"
else
	printf '   ✘ erase con la clave nueva no avisa de que regulariza el evento %s\n' "$EV2"
	sed 's/^/     /' "$T/erase.err"
	mal=1
fi
recibos 1 "$EV3" "$T/politica-rotada.json" 3
if comprueba "$T/recibo-bloque-1.txt" "$T/recibo-evento-3.txt" "$T/politica-rotada.json" >"$T/nueva.out" &&
	grep -q 'verifica con openssl y la erasureKey' "$T/nueva.out"; then
	printf '   ✔ la supresión con la clave nueva (evento %s) está autorizada para el tercero\n' "$EV3"
else
	printf '   ✘ la supresión con la clave nueva (evento %s) no está autorizada para el tercero:\n' "$EV3"
	sed 's/^/     /' "$T/nueva.out"
	mal=1
fi
codigo=0
"$N" --dir "$E" --json reconcile --source "$T/vivo.jsonl" --policy-file "$T/politica-rotada.json" >"$T/rec2.json" 2>/dev/null || codigo=$?
if [ "$codigo" = 0 ] && python3 - "$T/rec2.json" "$EV" "$EV2" "$EV3" <<'EOF'; then
import json, sys
r = json.load(open(sys.argv[1]))
ev, ev2, ev3 = (int(x) for x in sys.argv[2:])
assert r["findings"] == [], r["findings"]
assert [(g["index"], g["regularized_by"]) for g in r["regularized"]] == [(ev2, ev3)], r["regularized"]
por = {x["index"]: (x["erased_by"], x["authorized_by"]) for x in r["erased"]}
assert por == {0: (ev, "retiredErasureKeys"), 1: (ev3, "erasureKey")}, por
EOF
	printf '   ✔ reconcile: el evento %s, regularizado por el %s (regularized_by); el bloque 0, por la clave retirada; código 0\n' "$EV2" "$EV3"
else
	printf '   ✘ reconcile tras regularizar no da regularized_by %s para el evento %s (código %s)\n' "$EV3" "$EV2" "$codigo"
	sed 's/^/     /' "$T/rec2.json" | head -40
	mal=1
fi

if [ "$mal" = 0 ]; then
	echo "✔ el tercero comprueba la supresión con sha256sum y openssl, también tras rotar la clave"
else
	echo "✘ la comprobación del tercero falló"
	exit 1
fi
