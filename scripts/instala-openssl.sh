#!/usr/bin/env bash
# instala-openssl.sh — OpenSSL 3.5.9, la implementación INDEPENDIENTE de ML-DSA-44 con la
# que se generan y se comprueban los vectores (ADR-034, decisión 7; ADR-024, enmienda del
# 2026-10-24). Es una herramienta de desarrollo, como cosign o shellcheck: no la usa el
# producto ni el binario, y no toca el OpenSSL del sistema.
#
#   ./scripts/instala-openssl.sh            # en ~/.local/opt/openssl-3.5.9
#   ./scripts/instala-openssl.sh PREFIJO    # en otro sitio (el CI)
#
# Antes de compilar nada comprueba las dos cosas que dicen de dónde viene el tarball: su
# sha256, fijado aquí, y su firma PGP, que tiene que ser de la clave de firma de OpenSSL
# cuya huella también se fija aquí. La huella se tomó de dos fuentes independientes el
# 2026-10-24 (Sprint 29) y coincidían: la página de descargas de openssl.org
# (https://openssl-library.org/source/) y doc/fingerprints.txt del repositorio de GitHub en
# el tag openssl-3.5.9. Firma una subclave de esa clave, certificada por ella; gpg da en
# VALIDSIG la huella de la PRIMARIA, que es la que se compara.
#
# Se compila sin bibliotecas compartidas (no-shared): un openssl 3.5 enlazado contra el
# libcrypto 3.0 del sistema no arranca, y LD_LIBRARY_PATH sería una condición más que
# cumplir en cada llamada.
#
# Necesita curl, gpg, perl, make y un compilador de C. Usa la red; tarda un par de minutos.
# Si ya está instalado, en esa versión, no hace nada.
set -euo pipefail

VERSION=3.5.9
SHA256=603f5602e2eef00d77fbd429d34dcd5822bb301757a1bc9cdb24c670f1eb859a
HUELLA=B146647E45A7B33947AB226B2A2C87D161692D40
TARBALL="openssl-$VERSION.tar.gz"
URL="https://github.com/openssl/openssl/releases/download/openssl-$VERSION/$TARBALL"
CLAVES="https://openssl-library.org/source/pubkeys.asc"

PREFIJO="${1:-$HOME/.local/opt/openssl-$VERSION}"

if [ -x "$PREFIJO/bin/openssl" ] && "$PREFIJO/bin/openssl" version | grep -q "^OpenSSL $VERSION "; then
	echo "ya instalado: $("$PREFIJO/bin/openssl" version) en $PREFIJO"
	exit 0
fi

for orden in curl gpg perl make cc sha256sum; do
	command -v "$orden" >/dev/null || {
		echo "falta $orden, y hace falta para descargar, comprobar y compilar OpenSSL $VERSION" >&2
		exit 1
	}
done

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

echo "descargando $TARBALL y su firma"
curl -fsSLo "$TMP/$TARBALL" "$URL"
curl -fsSLo "$TMP/$TARBALL.asc" "$URL.asc"
echo "$SHA256  $TMP/$TARBALL" | sha256sum -c -

# Un GNUPGHOME propio y vacío: ni se fía de lo que haya en el llavero del usuario ni le
# añade nada.
export GNUPGHOME="$TMP/gnupg"
mkdir -m 700 "$GNUPGHOME"
curl -fsSLo "$TMP/pubkeys.asc" "$CLAVES"
gpg --batch --quiet --import "$TMP/pubkeys.asc" 2>/dev/null
estado="$(gpg --batch --status-fd 1 --verify "$TMP/$TARBALL.asc" "$TMP/$TARBALL" 2>/dev/null || true)"
primaria="$(printf '%s\n' "$estado" | awk '$2 == "VALIDSIG" {print $NF}')"
if [ "$primaria" != "$HUELLA" ]; then
	echo "la firma PGP de $TARBALL no es de la clave de OpenSSL $HUELLA (dice: ${primaria:-ninguna firma válida})" >&2
	exit 1
fi
echo "firma PGP válida, de la clave $HUELLA"

tar -xzf "$TMP/$TARBALL" -C "$TMP"
(
	cd "$TMP/openssl-$VERSION"
	./Configure --prefix="$PREFIJO" --libdir=lib no-shared no-docs >"$TMP/configure.log" 2>&1 ||
		{ tail -n 40 "$TMP/configure.log" >&2; exit 1; }
	make -j"$(nproc 2>/dev/null || echo 2)" >"$TMP/make.log" 2>&1 ||
		{ tail -n 40 "$TMP/make.log" >&2; exit 1; }
	make install_sw >"$TMP/install.log" 2>&1 ||
		{ tail -n 40 "$TMP/install.log" >&2; exit 1; }
)
"$PREFIJO/bin/openssl" version | grep -q "^OpenSSL $VERSION " || {
	echo "instalado, pero $PREFIJO/bin/openssl no dice ser $VERSION" >&2
	exit 1
}
"$PREFIJO/bin/openssl" list -signature-algorithms | grep -q ML-DSA-44 || {
	echo "instalado, pero sin ML-DSA-44" >&2
	exit 1
}
echo "instalado: $("$PREFIJO/bin/openssl" version) en $PREFIJO"
