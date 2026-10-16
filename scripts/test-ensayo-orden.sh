#!/usr/bin/env bash
# test-ensayo-orden.sh — el orden del paso 1 de ensayo-actualizacion.sh, sin red.
#
# El ensayo descarga un release y solo puede ejecutarlo si antes ha autenticado lo que
# bajó. Que eso pase depende del ORDEN de unas pocas órdenes, y un orden no se ve en una
# salida en verde: H8 de la revisión del 2026-10-14 encontró sha256sum usando un
# checksums.txt aún sin autenticar, y H4 (2026-10-11) no tenía test automatizado. Aquí se
# corre el ensayo con NUCLEO_ENSAYO_SOLO_PASO1=1 y un PATH de mentira: curl, cosign,
# sha256sum y tar son shims que no tocan la red y anotan en un log, en orden, a quién se
# llama y con qué. Se comprueba:
#
#   a) con cosign: cosign verify-blob va ANTES de bajar el tarball y de sha256sum;
#   b) cosign que falla: salida 2, y ni se baja el tarball ni se llama a tar;
#   c) sin cosign y sin NUCLEO_ENSAYO_SIN_FIRMA: salida 2 y ni una llamada a curl (H4);
#   d) sin cosign y con NUCLEO_ENSAYO_SIN_FIRMA=1: sigue, en el mismo orden, y avisa.
#
# Lo corren scripts/compuerta.sh y el job `scripts` del CI. Sale con 0 si todo cuadra y
# con 1 si no.
set -euo pipefail

RAIZ="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENSAYO="$RAIZ/scripts/ensayo-actualizacion.sh"
T="$(mktemp -d)"
trap 'rm -rf "$T"' EXIT

fallos=0
ok() { printf '   ✔ %s\n' "$1"; }
mal() {
	printf '   ✘ %s\n' "$1"
	fallos=$((fallos + 1))
}

# El PATH del ensayo: solo este directorio. Las herramientas de verdad que necesita hasta
# el final del paso 1 entran como enlaces; las que exige pero no llega a usar (go, node…)
# como órdenes que fallan si alguien las llama; y las cuatro observadas, como shims.
SHIMS="$T/bin"
mkdir -p "$SHIMS"
for h in bash env dirname mktemp rm mkdir grep cat cut uname; do
	ln -s "$(command -v "$h")" "$SHIMS/$h"
done
for h in go node npm python3 openssl xxd script; do
	printf '#!%s\necho "%s no debería llamarse en el paso 1" >&2\nexit 99\n' "$(command -v bash)" "$h" >"$SHIMS/$h"
	chmod +x "$SHIMS/$h"
done
# curl -…O URL: anota el nombre y deja un fichero con ese nombre. El checksums.txt de
# mentira nombra los tarballs de las dos plataformas que acepta el ensayo.
cat >"$SHIMS/curl" <<'EOF'
#!/usr/bin/env bash
url="${*: -1}"
f="${url##*/}"
echo "curl $f" >>"$ORDEN_LOG"
case "$f" in
checksums.txt)
	for p in linux_amd64 linux_arm64; do
		printf '%064d  nucleo_0.3.1-alpha_%s.tar.gz\n' 0 "$p"
	done >"$f"
	;;
*) echo "contenido de $f" >"$f" ;;
esac
EOF
cat >"$SHIMS/cosign" <<'EOF'
#!/usr/bin/env bash
echo "cosign $1" >>"$ORDEN_LOG"
[ "${COSIGN_FALLA:-}" != 1 ] || { echo "error: la firma no verifica" >&2; exit 1; }
EOF
cat >"$SHIMS/sha256sum" <<'EOF'
#!/usr/bin/env bash
echo "sha256sum $*" >>"$ORDEN_LOG"
[ "${1:-}" = -c ] || printf '%064d  %s\n' 0 "${1:--}"
EOF
cat >"$SHIMS/tar" <<'EOF'
#!/usr/bin/env bash
echo "tar $1" >>"$ORDEN_LOG"
EOF
chmod +x "$SHIMS/curl" "$SHIMS/cosign" "$SHIMS/sha256sum" "$SHIMS/tar"

# corre <caso> [VAR=valor…]: el ensayo con el PATH de shims; deja el log de órdenes en
# $T/<caso>.orden, la salida en $T/<caso>.out y el código en $codigo.
corre() {
	local caso="$1"
	shift
	: >"$T/$caso.orden"
	codigo=0
	env -i HOME="$T" PATH="$SHIMS" ORDEN_LOG="$T/$caso.orden" NUCLEO_ENSAYO_SOLO_PASO1=1 "$@" \
		"$SHIMS/bash" "$ENSAYO" >"$T/$caso.out" 2>&1 || codigo=$?
}
# linea <caso> <patrón>: número de la primera línea del log que casa, o 0 si ninguna.
linea() {
	local n
	n="$(grep -n -m1 -E "$2" "$T/$1.orden" | cut -d: -f1 || true)"
	echo "${n:-0}"
}
ensena() { sed 's/^/        /' "$T/$1.orden" "$T/$1.out"; }

echo "── a) con cosign: verify-blob antes del tarball y de sha256sum"
corre a
cos="$(linea a '^cosign verify-blob')"
tgz="$(linea a '^curl nucleo_.*\.tar\.gz$')"
sha="$(linea a '^sha256sum -c')"
if [ "$codigo" = 0 ] && [ "$cos" -gt 0 ] && [ "$tgz" -gt "$cos" ] && [ "$sha" -gt "$tgz" ] &&
	[ "$(linea a '^tar ')" -gt "$sha" ]; then
	ok "checksums.txt → cosign verify-blob (línea $cos) → tarball ($tgz) → sha256sum -c ($sha) → tar"
else
	mal "orden o código inesperado (código $codigo; cosign $cos, tarball $tgz, sha256sum $sha)"
	ensena a
fi

echo "── b) cosign que falla"
corre b COSIGN_FALLA=1
if [ "$codigo" = 2 ] && [ "$(linea b '^cosign verify-blob')" -gt 0 ] &&
	[ "$(linea b '^curl nucleo_.*\.tar\.gz$')" = 0 ] && [ "$(linea b '^tar ')" = 0 ]; then
	ok "salida 2, sin bajar el tarball y sin tar"
else
	mal "cosign falló: código $codigo, o se bajó el tarball o se llamó a tar"
	ensena b
fi

echo "── c) sin cosign y sin NUCLEO_ENSAYO_SIN_FIRMA (H4)"
rm "$SHIMS/cosign"
corre c
if [ "$codigo" = 2 ] && [ "$(linea c '^curl ')" = 0 ] && grep -q "falta \`cosign\`" "$T/c.out"; then
	ok "salida 2 y ni una llamada a curl"
else
	mal "sin cosign, código $codigo o hubo descargas"
	ensena c
fi

echo "── d) sin cosign y con NUCLEO_ENSAYO_SIN_FIRMA=1"
corre d NUCLEO_ENSAYO_SIN_FIRMA=1
tgz="$(linea d '^curl nucleo_.*\.tar\.gz$')"
sha="$(linea d '^sha256sum -c')"
if [ "$codigo" = 0 ] && [ "$(linea d '^curl checksums\.txt$')" = 1 ] && [ "$tgz" -gt 1 ] &&
	[ "$sha" -gt "$tgz" ] && [ "$(linea d '^tar ')" -gt "$sha" ] &&
	grep -q "la FIRMA de checksums.txt NO se ha" "$T/d.out"; then
	ok "sigue en el mismo orden, sin el paso de cosign, y avisa de que la firma no se verificó"
else
	mal "con NUCLEO_ENSAYO_SIN_FIRMA=1, código $codigo, orden o aviso inesperados"
	ensena d
fi

echo
if [ "$fallos" -eq 0 ]; then
	echo "✔ el ensayo autentica checksums.txt antes de usarlo, y sin cosign no descarga nada"
else
	echo "✘ $fallos comprobaciones del orden del ensayo fallaron"
	exit 1
fi
