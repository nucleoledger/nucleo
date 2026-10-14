#!/usr/bin/env bash
# valida-kit-testigo.sh — comprueba los ficheros de deploy/witness/ como los usaría un
# operador. Lo ejecuta el CI (job kit-testigo) y se puede ejecutar en local.
#
#   1. La unidad de systemd, con `systemd-analyze verify`. Ojo: verify sale con 0
#      aunque una directiva esté mal escrita —dice «Failed to parse …, ignoring» y
#      sigue—; solo falla si falta el ejecutable. Así que aquí falla TAMBIÉN si
#      aparece cualquier aviso sobre esta unidad.
#      Si /usr/local/bin/nucleo existe (el CI lo instala con sudo), se valida el
#      fichero tal cual; si no, una copia con ExecStart apuntando al binario recién
#      compilado, y se dice.
#   2. El Caddyfile, con `caddy validate`. Si no hay caddy en el PATH, descarga la
#      versión fijada abajo y comprueba su sha512 contra el checksums del release.
#   3. La configuración de ejemplo del testigo: la arranca de verdad con
#      `witness serve` y comprueba que sirve lo que dice.
set -euo pipefail

CADDY_VERSION="2.11.7"

RAIZ="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
KIT="$RAIZ/deploy/witness"
T="$(mktemp -d)"
PID=""
trap '[ -n "$PID" ] && kill "$PID" 2>/dev/null; rm -rf "$T"' EXIT
falla() {
	echo "valida-kit-testigo: $*" >&2
	exit 1
}

N="$T/nucleo"
(cd "$RAIZ" && go build -o "$N" ./cmd/nucleo)

echo "== 1. la unidad de systemd"
command -v systemd-analyze >/dev/null || falla "no hay systemd-analyze en esta máquina"
UNIDAD="$KIT/nucleo-testigo.service"
if [ -x /usr/local/bin/nucleo ]; then
	A_VALIDAR="$UNIDAD"
	echo "   se valida el fichero tal cual (/usr/local/bin/nucleo existe)"
else
	A_VALIDAR="$T/nucleo-testigo.service"
	sed "s#/usr/local/bin/nucleo#$N#" "$UNIDAD" >"$A_VALIDAR"
	echo "   /usr/local/bin/nucleo no existe aquí: se valida una copia con ExecStart=$N"
fi
set +e
SALIDA="$(systemd-analyze verify "$A_VALIDAR" 2>&1)"
CODIGO=$?
set -e
AVISOS="$(printf '%s\n' "$SALIDA" | grep -F "nucleo-testigo.service" || true)"
if [ "$CODIGO" -ne 0 ] || [ -n "$AVISOS" ]; then
	printf '%s\n' "$SALIDA" >&2
	falla "systemd-analyze verify no da la unidad por buena (código $CODIGO)"
fi
echo "   ✔ systemd-analyze verify, sin errores ni avisos sobre la unidad"

echo "== 2. el Caddyfile"
if command -v caddy >/dev/null; then
	CADDY="$(command -v caddy)"
else
	case "$(uname -s)/$(uname -m)" in
	Linux/x86_64) PLAT=linux_amd64 ;;
	Linux/aarch64) PLAT=linux_arm64 ;;
	Darwin/x86_64) PLAT=mac_amd64 ;;
	Darwin/arm64) PLAT=mac_arm64 ;;
	*) falla "plataforma $(uname -s)/$(uname -m) no prevista para descargar caddy" ;;
	esac
	DIR="${XDG_CACHE_HOME:-$HOME/.cache}/nucleo/caddy-$CADDY_VERSION-$PLAT"
	CADDY="$DIR/caddy"
	if [ ! -x "$CADDY" ]; then
		BASE="https://github.com/caddyserver/caddy/releases/download/v$CADDY_VERSION"
		TAR="caddy_${CADDY_VERSION}_$PLAT.tar.gz"
		curl -fsSL -o "$T/$TAR" "$BASE/$TAR" || falla "no se pudo descargar $BASE/$TAR"
		curl -fsSL -o "$T/sums" "$BASE/caddy_${CADDY_VERSION}_checksums.txt" || falla "no se pudo descargar el checksums de caddy"
		ESPERADO="$(awk -v f="$TAR" '$2 == f {print $1}' "$T/sums")"
		[ -n "$ESPERADO" ] || falla "$TAR no está en el checksums de caddy"
		if command -v sha512sum >/dev/null; then
			OBTENIDO="$(sha512sum "$T/$TAR" | awk '{print $1}')"
		else
			OBTENIDO="$(shasum -a 512 "$T/$TAR" | awk '{print $1}')"
		fi
		[ "$ESPERADO" = "$OBTENIDO" ] || falla "el sha512 de $TAR no coincide con el del release"
		mkdir -p "$DIR"
		tar -C "$DIR" -xzf "$T/$TAR" caddy
	fi
fi
echo "   $("$CADDY" version | awk '{print "caddy", $1}')"
"$CADDY" validate --config "$KIT/Caddyfile" --adapter caddyfile >"$T/caddy.out" 2>&1 ||
	{ cat "$T/caddy.out" >&2; falla "caddy validate no acepta el Caddyfile"; }
grep -q "Valid configuration" "$T/caddy.out" || { cat "$T/caddy.out" >&2; falla "caddy validate no dijo «Valid configuration»"; }
echo "   ✔ caddy validate: Valid configuration"

echo "== 3. la configuración de ejemplo del testigo"
cp "$KIT/testigo.json.ejemplo" "$T/testigo.json"
chmod 600 "$T/testigo.json"
"$N" witness serve --addr 127.0.0.1:0 --db "$T/t.db" --config "$T/testigo.json" >"$T/serve.log" 2>&1 &
PID=$!
for _ in $(seq 1 50); do grep -q "escuchando en" "$T/serve.log" 2>/dev/null && break; sleep 0.1; done
sleep 0.3
if ! { grep -q "logs servidos (2)" "$T/serve.log" && grep -q "logs retirados (1)" "$T/serve.log"; }; then
	cat "$T/serve.log" >&2
	falla "el ejemplo no arranca como dice"
fi
echo "   ✔ witness serve --config arranca con el ejemplo: 2 logs servidos, 1 retirado"

echo "✔ deploy/witness/ es válido"
