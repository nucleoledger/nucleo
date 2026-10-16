#!/usr/bin/env bash
# ensayo-actualizacion.sh — el ensayo de actualización desde un release publicado.
#
# Descarga el binario PUBLICADO de una versión anterior, comprueba que es el que se firmó
# y crea con él un despliegue de verdad: ledger, testigo, política y un recibo. Después
# compila el HEAD y comprueba que ese despliegue sigue funcionando: lo abre con la misma
# política, sella y sincroniza contra la misma memoria del testigo; añade la clave de
# supresión a la política, suprime con autorización un bloque sellado por la versión
# vieja y reconcilia; verifica los recibos con el SDK publicado y con el del HEAD; y
# comprueba la supresión como un tercero, con sha256sum y openssl (PROTOCOL §5.1), con
# scripts/tercero-supresion.sh.
#
# Es el paso del ritual de RELEASING «repetir el ensayo contra el HEAD final antes de
# etiquetar». No entra en scripts/compuerta.sh porque necesita red: descarga el release
# de GitHub y el SDK de npm.
#
#   ./scripts/ensayo-actualizacion.sh                 # desde v0.3.1-alpha
#   ./scripts/ensayo-actualizacion.sh v0.3.1-alpha
#   NUCLEO_ENSAYO_SDK=0.3.0-alpha.0 ./scripts/ensayo-actualizacion.sh   # el SDK de npm que
#                                                     # acompañaba a esa versión
#
# Necesita: curl, sha256sum, go, node y npm, python3, openssl, xxd, `script` de
# util-linux (simula la consola donde la custodia teclea sus tarjetas) y cosign, que
# verifica la firma de checksums.txt: sin ella, el sha256 solo dice que el binario es el
# que nombra un checksums.txt bajado del mismo sitio, no que sea el que se firmó. Linux,
# amd64 o arm64.
#
# SIN cosign, el ensayo sale con 2 ANTES de descargar ni extraer nada. La única forma de
# seguir sin él es NUCLEO_ENSAYO_SIN_FIRMA=1, y entonces el final no dice «ENSAYO EN
# VERDE» a secas sino «ENSAYO EN VERDE — SIN FIRMA VERIFICADA»: un ensayo así no vale
# para el ritual de RELEASING.
#
# El orden del paso 1 (H8): checksums.txt y su firma → cosign verify-blob → el tarball →
# su línea exacta y sha256sum -c contra el manifiesto ya autenticado → tar.
#
# NUCLEO_ENSAYO_SOLO_PASO1=1 termina con 0 al acabar el paso 1, sin ejecutar nada de lo
# descargado: lo usa scripts/test-ensayo-orden.sh, que comprueba ese orden sin red.
#
# Sale con 0 si todo cuadra, con 1 si falla alguna comprobación y con 2 si no se puede
# comprobar, o no cuadra, que el binario descargado es el que se firmó: en ese caso no se
# ejecuta nada de lo descargado.
set -euo pipefail

VERSION="${1:-v0.3.1-alpha}"
SDK_VIEJO="${NUCLEO_ENSAYO_SDK:-0.3.0-alpha.0}"
RAIZ="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPO=https://github.com/nucleoledger/nucleo

T="$(mktemp -d)"
PIDS=()
# limpia para los testigos que se hayan levantado y borra el directorio, también si el
# script muere a medias: un testigo huérfano deja el puerto ocupado y la base abierta, y
# el ensayo mutuo ya lo enseñó una vez.
limpia() {
	for p in "${PIDS[@]:-}"; do [ -n "$p" ] && kill "$p" 2>/dev/null || true; done
	wait 2>/dev/null || true
	rm -rf "$T"
}
trap limpia EXIT
trap 'exit 130' INT TERM

# El binario nuevo es de producción: sin ganchos, como lo usaría un operador.
for v in NUCLEO_TEST_SEED NUCLEO_TEST_CLOCK NUCLEO_TEST_PASSPHRASE NUCLEO_TEST_DIE_AT NUCLEO_TEST_PAUSE_AT NUCLEO_TEST_CARDS; do
	unset "$v"
done

fallos=0
ok() { printf '   ✔ %s\n' "$1"; }
mal() {
	printf '   ✘ %s\n' "$1"
	fallos=$((fallos + 1))
}
titulo() { printf '\n── %s\n' "$1"; }
# exige <nombre> <código esperado> <orden…>: ejecuta y compara el código de salida. La
# salida queda en $T/ult.out y $T/ult.err para quien la necesite después.
exige() {
	local nombre="$1" quiero="$2" codigo=0
	shift 2
	"$@" >"$T/ult.out" 2>"$T/ult.err" || codigo=$?
	if [ "$codigo" = "$quiero" ]; then
		ok "$nombre (código $codigo)"
	else
		mal "$nombre: código $codigo, esperado $quiero"
		tail -n 5 "$T/ult.err" "$T/ult.out" | sed 's/^/        /'
	fi
}
campo() { python3 -c "import json,sys; print(json.load(sys.stdin)$1)"; }

for orden in curl sha256sum go node npm python3 openssl xxd script; do
	command -v "$orden" >/dev/null || {
		echo "falta \`$orden\`: el ensayo lo necesita (ver la cabecera del script)" >&2
		exit 1
	}
done
# La firma, antes de descargar nada (H4 de la revisión del 2026-10-11: sin cosign, el
# ensayo avisaba y ejecutaba igual el binario descargado).
SIN_FIRMA=0
if ! command -v cosign >/dev/null; then
	if [ "${NUCLEO_ENSAYO_SIN_FIRMA:-}" != 1 ]; then
		echo "✘ falta \`cosign\`: sin él no se comprueba que el binario de $VERSION sea el que se" >&2
		echo "  firmó, y no se descarga ni se ejecuta nada. La versión que usa el release está en" >&2
		echo "  .github/workflows/release.yml (cosign-release). Para ensayar SIN verificar la firma," >&2
		echo "  y que el resultado lo diga: NUCLEO_ENSAYO_SIN_FIRMA=1 $0${*:+ $*}" >&2
		exit 2
	fi
	SIN_FIRMA=1
fi
case "$(uname -s)/$(uname -m)" in
Linux/x86_64) PLAT=linux_amd64 ;;
Linux/aarch64 | Linux/arm64) PLAT=linux_arm64 ;;
*)
	echo "el ensayo corre en Linux amd64 o arm64; esto es $(uname -s)/$(uname -m)" >&2
	exit 1
	;;
esac

# ---------------------------------------------------------------------------------
titulo "1. El binario publicado de $VERSION, comprobado antes de ejecutarlo"
VER="${VERSION#v}"
ARCHIVO="nucleo_${VER}_${PLAT}.tar.gz"
BASE="$REPO/releases/download/$VERSION"
mkdir -p "$T/descarga" "$T/viejo"
# El orden es la garantía (H8 de la revisión del 2026-10-14): primero checksums.txt y su
# firma; cosign autentica el manifiesto; SOLO entonces se baja el tarball y se contrasta
# con un manifiesto ya autenticado. Antes, sha256sum usaba un checksums.txt sin
# autenticar. scripts/test-ensayo-orden.sh fija este orden sin red.
(cd "$T/descarga" && curl -fsSLO "$BASE/checksums.txt")
if [ "$SIN_FIRMA" = 0 ]; then
	# La identidad EXACTA: el workflow release.yml sobre el tag de esta versión
	# (docs/RELEASING.md, «Verificación en un solo comando»).
	ID="$REPO/.github/workflows/release.yml@refs/tags/$VERSION"
	ISSUER=https://token.actions.githubusercontent.com
	if (cd "$T/descarga" && curl -fsLO "$BASE/checksums.txt.sigstore.json"); then
		firma=(--bundle "$T/descarga/checksums.txt.sigstore.json")
	else
		(cd "$T/descarga" && curl -fsSLO "$BASE/checksums.txt.sig" && curl -fsSLO "$BASE/checksums.txt.pem")
		firma=(--signature "$T/descarga/checksums.txt.sig" --certificate "$T/descarga/checksums.txt.pem")
	fi
	if ! cosign verify-blob "$T/descarga/checksums.txt" "${firma[@]}" \
		--certificate-identity "$ID" --certificate-oidc-issuer "$ISSUER" >"$T/cosign.log" 2>&1; then
		echo "✘ la firma de checksums.txt no verifica con la identidad $ID: no se descarga ni se ejecuta nada más" >&2
		cat "$T/cosign.log" >&2
		exit 2
	fi
	ok "firma de checksums.txt verificada con cosign (release.yml@refs/tags/$VERSION)"
else
	printf '   ⚠ NUCLEO_ENSAYO_SIN_FIRMA=1 y sin cosign: la FIRMA de checksums.txt NO se ha\n'
	printf '     verificado, solo el sha256 contra un checksums.txt del mismo sitio\n'
fi
# La línea del archivo, exacta: sin ella, sha256sum --ignore-missing daría por bueno un
# checksums.txt que no lo nombra. Se mira antes de bajar el tarball: si no lo nombra, no
# hay nada que bajar.
if ! grep -q "  $ARCHIVO\$" "$T/descarga/checksums.txt"; then
	echo "✘ checksums.txt de $VERSION no nombra $ARCHIVO: no se descarga ni se ejecuta nada" >&2
	exit 2
fi
(cd "$T/descarga" && curl -fsSLO "$BASE/$ARCHIVO")
if ! (cd "$T/descarga" && grep "  $ARCHIVO\$" checksums.txt | sha256sum -c --quiet -); then
	echo "✘ el sha256 de $ARCHIVO no es el de checksums.txt: no se ejecuta nada" >&2
	exit 2
fi
ok "sha256 de $ARCHIVO igual al de checksums.txt"
tar -xzf "$T/descarga/$ARCHIVO" -C "$T/viejo"
VIEJO="$T/viejo/nucleo"
printf '   binario publicado: %s  (%s)\n' "$(sha256sum "$VIEJO" | cut -c1-16)…" "$VERSION"
if [ "${NUCLEO_ENSAYO_SOLO_PASO1:-}" = 1 ]; then
	echo "NUCLEO_ENSAYO_SOLO_PASO1=1: termina tras el paso 1, sin ejecutar lo descargado"
	exit 0
fi

titulo "2. El HEAD, y los dos SDK"
NUEVO="$T/nuevo"
(cd "$RAIZ" && go build -o "$NUEVO" ./cmd/nucleo)
printf '   HEAD: %s\n' "$(cd "$RAIZ" && git log --oneline -1)"
mkdir -p "$T/npm"
(cd "$T/npm" && npm init -y >/dev/null && npm install --no-audit --no-fund "@nucleoledger/verify@$SDK_VIEJO" >/dev/null 2>&1)
SDK_PUBLICADO="$T/npm/node_modules/@nucleoledger/verify/dist/index.js"
[ -f "$SDK_PUBLICADO" ] || {
	echo "no se pudo instalar @nucleoledger/verify@$SDK_VIEJO de npm" >&2
	exit 1
}
if (cd "$T/npm" && npm audit signatures 2>&1 | grep -q "verified attestation"); then
	ok "@nucleoledger/verify@$SDK_VIEJO de npm, con su atestación"
else
	mal "@nucleoledger/verify@$SDK_VIEJO sin atestación verificada"
fi
# El SDK del HEAD se compila FUERA del repositorio, para no tocar su dist/.
(cd "$RAIZ/sdk/ts" && { [ -d node_modules ] || npm ci --no-audit --no-fund >/dev/null; } && npx tsc -p tsconfig.json --outDir "$T/sdk-head")
SDK_HEAD="$T/sdk-head/index.js"
SDK_HEAD_VER="$(campo "['version']" <"$RAIZ/sdk/ts/package.json")"
cat >"$T/verifica.mjs" <<'EOF'
// node verifica.mjs <index.js del SDK> <recibo> <política>: 0 válido, 2 inválido, 3 política rechazada.
import { readFileSync } from "node:fs";
import { pathToFileURL } from "node:url";
const [sdk, recibo, politica] = process.argv.slice(2);
const m = await import(pathToFileURL(sdk).href);
let pol;
try {
  pol = m.parsePolicyText(readFileSync(politica, "utf8"));
} catch (e) {
  console.log(`política rechazada: ${e.message}`);
  process.exit(3);
}
const r = await m.verifyReceipt(readFileSync(recibo, "utf8"), pol);
console.log(r.valid ? "válido" : `inválido: ${JSON.stringify(r.reasons)}`);
process.exit(r.valid ? 0 : 2);
EOF

# levanta <binario>: arranca el testigo en ESTE shell —en un $(...) se perdería el PID y
# el trap no lo pararía— sobre la misma memoria cada vez, y deja su URL en $URL.
levanta() {
	: >"$T/testigo/log"
	"$1" witness serve --addr 127.0.0.1:0 --db "$T/testigo/t.db" --name testigo.ensayo/w1 \
		--log-origin "$O" --log-key "$LOGPUB" >"$T/testigo/log" 2>&1 &
	PIDS+=("$!")
	PID_TESTIGO=$!
	URL=""
	for _ in $(seq 1 100); do
		if grep -q "escuchando en" "$T/testigo/log"; then
			URL="$(grep -o 'http://[^ ]*' "$T/testigo/log" | head -1)"
			return
		fi
		sleep 0.1
	done
	echo "el testigo no arrancó:" >&2
	cat "$T/testigo/log" >&2
	exit 1
}
para() {
	kill "$PID_TESTIGO" 2>/dev/null || true
	wait "$PID_TESTIGO" 2>/dev/null || true
}

E="$T/emp"
mkdir -p "$E" "$T/testigo"
printf 'passphrase del ensayo, larga de verdad\n' >"$T/pass"
chmod 600 "$T/pass"
P=(--passphrase-file "$T/pass")
O=ensayo.example/empresa
TEN=1790012345001
nuevo_doc() { printf '{"%s":"%s","nonce":"%s"}' "$1" "$2" "$(openssl rand -hex 16)" >"$T/$3.json"; }

# ---------------------------------------------------------------------------------
titulo "3. Un despliegue hecho con $VERSION"
exige "init" 0 "$VIEJO" --dir "$E" init --origin "$O" "${P[@]}" --assume-confirmed
nuevo_doc venta 001 d0
nuevo_doc venta 002 d1
exige "seal del bloque 0" 0 "$VIEJO" --dir "$E" seal --tenant "$TEN" --type sri.factura.v1 --payload "$T/d0.json" "${P[@]}"
exige "seal del bloque 1" 0 "$VIEJO" --dir "$E" seal --tenant "$TEN" --type sri.factura.v1 --payload "$T/d1.json" "${P[@]}"
LOGPUB="$("$VIEJO" --dir "$E" --json status 2>/dev/null | campo "['log_pubkey']")"
WKEY="$("$VIEJO" witness key --db "$T/testigo/t.db")"
levanta "$VIEJO"
exige "sync con el testigo de $VERSION" 0 "$VIEJO" --dir "$E" --json sync --witness "$URL" \
	--witness-name testigo.ensayo/w1 --witness-key "$WKEY" "${P[@]}"
python3 -c 'import json,sys; print(json.dumps(json.load(sys.stdin)["policy"]))' <"$T/ult.out" >"$T/politica-vieja.json"
exige "recibo del bloque 0 emitido por $VERSION" 0 "$VIEJO" --dir "$E" receipt --block 0 \
	--recipient "María Pérez" --out "$T/recibo-viejo.txt" --policy-file "$T/politica-vieja.json" "${P[@]}"
para

# ---------------------------------------------------------------------------------
titulo "4. El HEAD sobre el mismo despliegue"
"$NUEVO" --dir "$E" --json status --policy-file "$T/politica-vieja.json" >"$T/st.json" 2>/dev/null || true
if [ "$(campo "['attestation']" <"$T/st.json")" = verified ]; then
	ok "status con la política de $VERSION: attestation verified"
else
	mal "status con la política de $VERSION no da verified"
fi
exige "verify --full" 0 "$NUEVO" --dir "$E" verify --full
nuevo_doc venta 003 d2
exige "seal con el HEAD" 0 "$NUEVO" --dir "$E" seal --tenant "$TEN" --type sri.factura.v1 --payload "$T/d2.json" "${P[@]}"
levanta "$NUEVO"
exige "sync contra la MISMA memoria del testigo, ahora servida por el HEAD" 0 \
	"$NUEVO" --dir "$E" sync --witness "$URL" --policy-file "$T/politica-vieja.json" "${P[@]}"

# ---------------------------------------------------------------------------------
titulo "5. La política nueva, con la clave de supresión (ADR-032)"
"$NUEVO" --json erasure-key init --assume-confirmed >"$T/clave.json" 2>/dev/null
python3 - "$T" <<'EOF'
import json, sys
T = sys.argv[1]
k = json.load(open(T + "/clave.json"))
p = json.load(open(T + "/politica-vieja.json"))
p["erasureKey"] = k["erasure_key"]
json.dump(p, open(T + "/politica.json", "w"))
# Dos tarjetas de supresión y la línea vacía con que se termina de teclearlas.
open(T + "/tarjetas", "w").write("\n".join(k["shares"][:2]) + "\n\n")
EOF
"$NUEVO" --dir "$E" --json status --policy-file "$T/politica.json" >"$T/st2.json" 2>/dev/null || true
if [ "$(campo "['attestation']" <"$T/st2.json")" = verified ]; then
	ok "status con la política nueva: attestation verified"
else
	mal "status con la política nueva no da verified"
fi
exige "recibo del bloque 0 emitido por el HEAD" 0 "$NUEVO" --dir "$E" receipt --block 0 \
	--recipient "María Pérez" --out "$T/recibo-nuevo.txt" --policy-file "$T/politica.json" "${P[@]}"

# ---------------------------------------------------------------------------------
titulo "6. Suprimir con autorización un bloque sellado por $VERSION"
exige "erase sin autorización no borra nada" 1 "$NUEVO" --dir "$E" erase --block 0 \
	--policy-file "$T/politica.json" "${P[@]}" --assume-confirmed
ORDEN="$(grep -o 'nucleo erasure-key authorize .*' "$T/ult.err" || true)"
if [ -n "$ORDEN" ]; then ok "y dice la orden para la custodia"; else mal "erase no dio la orden para la custodia"; fi
# La custodia ejecuta ESA orden, tal cual, y teclea sus tarjetas en una consola: `script`
# la simula. La salida no se enseña: la consola repite lo tecleado, y son tarjetas.
script -qec "$(printf '%q --json %s' "$NUEVO" "${ORDEN#nucleo }")" /dev/null <"$T/tarjetas" >"$T/aut.out" 2>&1 || true
AUT="$(grep -o 'nucleo-erasure-auth@v1:[0-9]*:[0-9a-f]\{128\}' "$T/aut.out" | head -1 || true)"
if [ -n "$AUT" ]; then
	ok "la custodia autoriza con esa orden y dos tarjetas de supresión"
else
	mal "erasure-key authorize no dio la autorización"
fi
exige "erase con la autorización" 0 "$NUEVO" --dir "$E" erase --block 0 \
	--policy-file "$T/politica.json" --authorization "$AUT" "${P[@]}" --assume-confirmed
exige "sync tras suprimir" 0 "$NUEVO" --dir "$E" sync --witness "$URL" --policy-file "$T/politica.json" "${P[@]}"
python3 - "$T" <<'EOF' >"$T/vivo.jsonl"
import base64, json, sys
T = sys.argv[1]
for i, n in ((1, "d1"), (2, "d2")):
    print(json.dumps({"index": i, "payload_b64": base64.b64encode(open(f"{T}/{n}.json", "rb").read()).decode()}))
EOF
exige "reconcile con la política nueva: el bloque 0, suprimido" 0 \
	"$NUEVO" --dir "$E" reconcile --source "$T/vivo.jsonl" --policy-file "$T/politica.json"
exige "reconcile con la política sin erasureKey: faltante y supresión no autorizada" 2 \
	"$NUEVO" --dir "$E" reconcile --source "$T/vivo.jsonl" --policy-file "$T/politica-vieja.json"
EV=$(($("$NUEVO" --dir "$E" --json status 2>/dev/null | campo "['tree_size']") - 1))
exige "recibo del bloque 0 tras suprimir" 0 "$NUEVO" --dir "$E" receipt --block 0 \
	--recipient "María Pérez" --out "$T/recibo-tras.txt" --policy-file "$T/politica.json" "${P[@]}"
exige "recibo del evento de supresión (bloque $EV)" 0 "$NUEVO" --dir "$E" receipt --block "$EV" \
	--recipient "Auditoría" --out "$T/recibo-evento.txt" --policy-file "$T/politica.json" "${P[@]}"
para

# ---------------------------------------------------------------------------------
titulo "7. Los recibos, con el SDK publicado y con el del HEAD"
for r in recibo-viejo recibo-nuevo recibo-tras recibo-evento; do
	exige "$r con @nucleoledger/verify@$SDK_VIEJO (npm) y la política de $VERSION" 0 \
		node "$T/verifica.mjs" "$SDK_PUBLICADO" "$T/$r.txt" "$T/politica-vieja.json"
	exige "$r con $SDK_HEAD_VER (HEAD) y la política nueva" 0 \
		node "$T/verifica.mjs" "$SDK_HEAD" "$T/$r.txt" "$T/politica.json"
done
exige "@nucleoledger/verify@$SDK_VIEJO rechaza la política con erasureKey (lo que dicen las notas)" 3 \
	node "$T/verifica.mjs" "$SDK_PUBLICADO" "$T/recibo-nuevo.txt" "$T/politica.json"

# ---------------------------------------------------------------------------------
titulo "8. Un tercero comprueba la supresión con sha256sum y openssl (PROTOCOL §5.1)"
# La receta es scripts/tercero-supresion.sh, la misma que corren la compuerta y el CI
# sobre un ledger recién creado; aquí, sobre los recibos de un despliegue que viene de
# $VERSION.
"$RAIZ/scripts/tercero-supresion.sh" comprueba "$T/recibo-tras.txt" "$T/recibo-evento.txt" "$T/politica.json" ||
	mal "la comprobación del tercero falló (scripts/tercero-supresion.sh)"

echo
if [ "$fallos" -eq 0 ] && [ "$SIN_FIRMA" = 1 ]; then
	echo "✔ ENSAYO EN VERDE — SIN FIRMA VERIFICADA: $VERSION → HEAD"
	echo "  (sin cosign, NUCLEO_ENSAYO_SIN_FIRMA=1: no vale para el ritual de RELEASING)"
elif [ "$fallos" -eq 0 ]; then
	echo "✔ ENSAYO EN VERDE: $VERSION → HEAD"
else
	echo "✘ ENSAYO EN ROJO: $fallos comprobaciones fallaron"
	exit 1
fi
