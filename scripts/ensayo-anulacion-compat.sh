#!/usr/bin/env bash
# ensayo-anulacion-compat.sh — la compatibilidad de una anulación con v0.5.0-alpha (ADR-035,
# decisión 9; «Los vectores», punto 5).
#
# Crea con el HEAD un ledger con una anulación —dos facturas, `nucleo void --block 1`, un
# testigo en 127.0.0.1— y comprueba lo que promete ADR-035 para quien se quede en la versión
# publicada:
#
#   - el binario PUBLICADO de v0.5.0-alpha (checksums.txt verificado con cosign antes de
#     bajar el tarball) reconcilia ese ledger y da el evento de anulación por «faltante», con
#     código 2: falla cerrado, con un nombre equivocado. El HEAD, en cambio, lo da en voided
#     con código 0;
#   - los recibos de la factura y de la anulación dan valid: true con
#     @nucleoledger/verify@0.5.0-alpha.0 de npm y con el SDK de PHP del tag v0.5.0-alpha.
#
# Es un paso del ritual de RELEASING antes de etiquetar la versión que lleve la anulación. No
# entra en scripts/compuerta.sh porque necesita red: el release de GitHub y el SDK de npm.
#
#   ./scripts/ensayo-anulacion-compat.sh
#
# Necesita: curl, sha256sum, cosign, go, node y npm, python3, openssl, git y PHP con
# ext-sodium —en $NUCLEO_PHP, que puede llevar argumentos y ser un php.exe desde WSL, como en
# la compuerta, o `php` en el PATH—. Linux, amd64 o arm64. Sin cosign sale con 2 antes de
# descargar nada: este ensayo no tiene modo sin firma.
#
# Sale con 0 si todo cuadra, con 1 si falla alguna comprobación y con 2 si no se puede
# comprobar que el binario descargado es el que se firmó (y entonces no se ejecuta).
set -euo pipefail

VERSION=v0.5.0-alpha
SDK=0.5.0-alpha.0
RAIZ="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPO=https://github.com/nucleoledger/nucleo

T="$(mktemp -d)"
PID_TESTIGO=""
limpia() {
	[ -n "$PID_TESTIGO" ] && kill "$PID_TESTIGO" 2>/dev/null || true
	wait 2>/dev/null || true
	rm -rf "$T"
}
trap limpia EXIT
trap 'exit 130' INT TERM

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
campo() { python3 -c "import json,sys; print(json.load(sys.stdin)$1)"; }
corre() {
	if ! "$@" >"$T/ult.out" 2>"$T/ult.err"; then
		echo "✘ falló: $*" >&2
		tail -n 20 "$T/ult.err" "$T/ult.out" >&2
		exit 1
	fi
}

for orden in curl sha256sum go node npm python3 openssl git; do
	command -v "$orden" >/dev/null || {
		echo "falta \`$orden\`: el ensayo lo necesita (ver la cabecera del script)" >&2
		exit 1
	}
done
command -v cosign >/dev/null || {
	echo "✘ falta \`cosign\`: sin él no se comprueba que el binario de $VERSION sea el que se firmó," >&2
	echo "  y no se descarga ni se ejecuta nada. La versión que usa el release está en" >&2
	echo "  .github/workflows/release.yml (cosign-release)." >&2
	exit 2
}
# PHP, como en la compuerta: $NUCLEO_PHP (con argumentos; un .exe desde WSL lee rutas de
# Windows) o `php`.
PHP_CMD="${NUCLEO_PHP:-}"
if [ -z "$PHP_CMD" ] && command -v php >/dev/null; then
	PHP_CMD=php
fi
[ -n "$PHP_CMD" ] || {
	echo "no hay PHP: ni \$NUCLEO_PHP ni \`php\` en el PATH. Define NUCLEO_PHP con la orden que" >&2
	echo "lo ejecuta, con ext-sodium, p. ej. NUCLEO_PHP=\"/ruta/php -d extension=sodium\"." >&2
	exit 1
}
read -r -a PHP_ARGV <<<"$PHP_CMD"
ruta_php() {
	if [[ "${PHP_ARGV[0]}" == *.exe ]] && command -v wslpath >/dev/null; then wslpath -w "$1"; else echo "$1"; fi
}
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
# El orden de ensayo-actualizacion.sh (H8): checksums.txt y su firma → cosign → el tarball →
# su línea exacta y sha256sum -c contra el manifiesto ya autenticado → tar.
ARCHIVO="nucleo_${VERSION#v}_${PLAT}.tar.gz"
BASE="$REPO/releases/download/$VERSION"
mkdir -p "$T/descarga" "$T/viejo"
(cd "$T/descarga" && curl -fsSLO "$BASE/checksums.txt" && curl -fsSLO "$BASE/checksums.txt.sigstore.json")
if ! cosign verify-blob "$T/descarga/checksums.txt" --bundle "$T/descarga/checksums.txt.sigstore.json" \
	--certificate-identity "$REPO/.github/workflows/release.yml@refs/tags/$VERSION" \
	--certificate-oidc-issuer https://token.actions.githubusercontent.com >"$T/cosign.log" 2>&1; then
	echo "✘ la firma de checksums.txt no verifica con la identidad de $VERSION: no se ejecuta nada" >&2
	cat "$T/cosign.log" >&2
	exit 2
fi
ok "firma de checksums.txt verificada con cosign (release.yml@refs/tags/$VERSION)"
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
printf '   %s\n' "$("$VIEJO" version)"

# ---------------------------------------------------------------------------------
titulo "2. Un ledger con una anulación, hecho con el HEAD"
N="$T/nuevo"
(cd "$RAIZ" && go build -o "$N" ./cmd/nucleo)
printf '   HEAD: %s\n' "$(cd "$RAIZ" && git log --oneline -1)"
E="$T/emp"
O=ensayo.example/anulacion
printf 'passphrase del ensayo, larga de verdad\n' >"$T/pass"
chmod 600 "$T/pass"
P=(--passphrase-file "$T/pass")
corre "$N" --dir "$E" init --origin "$O" "${P[@]}" --assume-confirmed --kdf-profile constrained
: >"$T/vivo.jsonl"
for i in 0 1; do
	printf '{"factura":"00%s","nonce":"%s"}' "$i" "$(openssl rand -hex 16)" >"$T/f$i.json"
	corre "$N" --dir "$E" seal --tenant 1790012345001 --type sri.factura.v1 --payload "$T/f$i.json" "${P[@]}"
	printf '{"index":%s,"payload_b64":"%s"}\n' "$i" "$(base64 -w0 "$T/f$i.json")" >>"$T/vivo.jsonl"
done
mkdir -p "$T/testigo"
LOGPUB="$("$N" --dir "$E" --json status 2>/dev/null | campo "['log_pubkey']")"
WKEY="$("$N" witness key --db "$T/testigo/t.db")"
"$N" witness serve --addr 127.0.0.1:0 --db "$T/testigo/t.db" --name ensayo.example/w1 \
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
corre "$N" --dir "$E" --json sync --witness "$URL" --witness-name ensayo.example/w1 --witness-key "$WKEY" "${P[@]}"
python3 -c "import json,sys; json.dump(json.load(open(sys.argv[1]))['policy'], open(sys.argv[2], 'w'))" \
	"$T/ult.out" "$T/politica.json"
corre "$N" --dir "$E" --json void --block 1 --policy-file "$T/politica.json" "${P[@]}"
EV="$(campo "['index']" <"$T/ult.out")"
corre "$N" --dir "$E" sync --witness "$URL" --policy-file "$T/politica.json" "${P[@]}"
corre "$N" --dir "$E" receipt --block 1 --recipient "Auditoría" --out "$T/recibo-factura.txt" --policy-file "$T/politica.json" "${P[@]}"
corre "$N" --dir "$E" receipt --block "$EV" --recipient "Auditoría" --out "$T/recibo-anulacion.txt" --policy-file "$T/politica.json" "${P[@]}"
ok "la factura del bloque 1, anulada en el bloque $EV; los dos recibos emitidos"

# ---------------------------------------------------------------------------------
titulo "3. reconcile con el binario publicado de $VERSION: el evento, faltante (falla cerrado)"
codigo=0
"$VIEJO" --dir "$E" --json reconcile --source "$T/vivo.jsonl" --policy-file "$T/politica.json" \
	>"$T/rec-viejo.json" 2>"$T/rec-viejo.err" || codigo=$?
if [ "$codigo" = 2 ] && python3 - "$T/rec-viejo.json" "$EV" <<'EOF'; then
import json, sys
r = json.load(open(sys.argv[1]))
ev = int(sys.argv[2])
assert [(f["status"], f["index"]) for f in r["findings"]] == [("faltante", ev)], r["findings"]
assert "voided" not in r, "v0.5.0-alpha no conoce voided"
EOF
	ok "$VERSION da el bloque $EV (nucleo.void.v1) por faltante, código 2, y no sabe de voided"
	printf '      su hallazgo: %s\n' "$(python3 -c "import json,sys; f=json.load(open(sys.argv[1]))['findings'][0]; print(f['status'], f['index'], f['type'])" "$T/rec-viejo.json")"
else
	mal "$VERSION no da el evento por faltante con código 2 (código $codigo)"
	sed 's/^/        /' "$T/rec-viejo.json" "$T/rec-viejo.err" | head -40
fi
codigo=0
"$N" --dir "$E" --json reconcile --source "$T/vivo.jsonl" --policy-file "$T/politica.json" >"$T/rec-nuevo.json" 2>/dev/null || codigo=$?
if [ "$codigo" = 0 ] && python3 - "$T/rec-nuevo.json" "$EV" <<'EOF'; then
import json, sys
r = json.load(open(sys.argv[1]))
assert r["findings"] == [], r["findings"]
assert [(v["index"], v["voided_by"]) for v in r["voided"]] == [(1, int(sys.argv[2]))], r["voided"]
EOF
	ok "y el HEAD la da en voided (la factura 1, por el bloque $EV), código 0"
else
	mal "el HEAD no da la anulación en voided con código 0 (código $codigo)"
	sed 's/^/        /' "$T/rec-nuevo.json" | head -40
fi

# ---------------------------------------------------------------------------------
titulo "4. Los recibos, con los SDK de $VERSION: válidos, sin cambios"
mkdir -p "$T/npm"
(cd "$T/npm" && npm init -y >/dev/null && npm install --no-audit --no-fund "@nucleoledger/verify@$SDK" >/dev/null 2>&1)
SDK_TS="$T/npm/node_modules/@nucleoledger/verify/dist/index.js"
[ -f "$SDK_TS" ] || {
	echo "no se pudo instalar @nucleoledger/verify@$SDK de npm" >&2
	exit 1
}
if (cd "$T/npm" && npm audit signatures 2>&1 | grep -q "verified attestation"); then
	ok "@nucleoledger/verify@$SDK de npm, con su atestación"
else
	mal "@nucleoledger/verify@$SDK sin atestación verificada"
fi
cat >"$T/verifica.mjs" <<'EOF'
import { readFileSync } from "node:fs";
import { pathToFileURL } from "node:url";
const [sdk, recibo, politica] = process.argv.slice(2);
const m = await import(pathToFileURL(sdk).href);
const r = await m.verifyReceipt(readFileSync(recibo, "utf8"), m.parsePolicyText(readFileSync(politica, "utf8")));
console.log(JSON.stringify({ valid: r.valid, logMLDSA: r.logMLDSA, reasons: r.reasons }));
process.exit(r.valid ? 0 : 2);
EOF
mkdir -p "$T/php-tag"
(cd "$RAIZ" && git archive "$VERSION" sdk/php) | tar -x -C "$T/php-tag"
cat >"$T/verifica.php" <<'EOF'
<?php
// php verifica.php <sdk/php del tag> <recibo> <política>: 0 válido, 2 inválido.
require $argv[1] . '/autoload.php';
try {
    $r = \Nucleo\Verifier::verify(file_get_contents($argv[2]), file_get_contents($argv[3]));
} catch (\Throwable $e) {
    echo json_encode(['valid' => false, 'error' => $e->getMessage()]), "\n";
    exit(2);
}
echo json_encode(['valid' => $r->valid, 'logMLDSA' => $r->logMLDSA]), "\n";
exit($r->valid ? 0 : 2);
EOF
for r in factura anulacion; do
	if node "$T/verifica.mjs" "$SDK_TS" "$T/recibo-$r.txt" "$T/politica.json" >"$T/ts.out" 2>&1; then
		ok "recibo de la $r con @nucleoledger/verify@$SDK: $(cat "$T/ts.out")"
	else
		mal "recibo de la $r con @nucleoledger/verify@$SDK: $(cat "$T/ts.out")"
	fi
	if "${PHP_ARGV[@]}" "$(ruta_php "$T/verifica.php")" "$(ruta_php "$T/php-tag/sdk/php")" \
		"$(ruta_php "$T/recibo-$r.txt")" "$(ruta_php "$T/politica.json")" >"$T/php.out" 2>&1; then
		ok "recibo de la $r con el SDK de PHP de $VERSION: $(cat "$T/php.out")"
	else
		mal "recibo de la $r con el SDK de PHP de $VERSION: $(cat "$T/php.out")"
	fi
done

echo
if [ "$fallos" -eq 0 ]; then
	echo "✔ ENSAYO DE COMPATIBILIDAD DE LA ANULACIÓN EN VERDE"
else
	echo "✘ $fallos comprobaciones fallaron"
	exit 1
fi
