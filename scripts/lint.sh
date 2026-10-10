#!/usr/bin/env bash
# lint.sh — el lint de la compuerta, el MISMO que corre el CI.
#
# El 2026-10-09 el job lint del CI falló (run 38002811302) y la compuerta local había
# dicho «0 issues». Mismo número de golangci-lint, v2.13.2, pero distinto Go: el CI usa
# `go-version: 'stable'`, que ya era 1.27.2, y en local había 1.27.1. Con 1.27.2, esa
# versión de golangci-lint no sabe leer los datos de exportación del compilador. Un
# «lint en verde» que depende de qué Go hay instalado en la máquina no dice nada.
#
# Este script quita las dos fuentes de diferencia:
#
#   · la versión de golangci-lint la LEE de .github/workflows/ci.yml y descarga ese
#     binario oficial, comprobando su sha256 contra el checksums.txt del release;
#   · el Go lo toma también del job lint de ci.yml: desde el Sprint 15 es
#     `go-version-file: go.mod`, y entonces usa la directiva `toolchain` de go.mod con
#     GOTOOLCHAIN, que es lo que instala setup-go. (Si algún día volviera a decir
#     'stable', preguntaría a go.dev cuál es hoy; sin red, fallaría.)
#
# Y hace las dos pasadas del CI: sin tags y con -tags testhooks.
#
#   ./scripts/lint.sh
#
set -euo pipefail

RAIZ="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CI="${NUCLEO_LINT_CI_YML:-$RAIZ/.github/workflows/ci.yml}"

falla() {
	echo "lint.sh: $*" >&2
	exit 1
}

# El job lint de ci.yml, desde «lint:» hasta el siguiente job.
JOB="$(awk '/^  lint:$/ {dentro=1; next} dentro && /^  [a-z][a-z-]*:$/ {exit} dentro' "$CI")"
[ -n "$JOB" ] || falla "no encuentro el job lint en $CI"

VERSION="$(printf '%s\n' "$JOB" | awk '/golangci-lint-action@/ {accion=1} accion && /version:/ {print $2; exit}')"
[[ "$VERSION" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || falla "la versión de golangci-lint en $CI no se entiende: «$VERSION»"

GOFILE="$(printf '%s\n' "$JOB" | awk '/go-version-file:/ {gsub(/[\x27"]/, "", $2); print $2; exit}')"
GOCI="$(printf '%s\n' "$JOB" | awk '/go-version:/ {gsub(/[\x27"]/, "", $2); print $2; exit}')"
if [ -n "$GOFILE" ]; then
	# Lo que lee setup-go de un go.mod: la directiva toolchain si está; si no, la go.
	[ -f "$RAIZ/$GOFILE" ] || falla "el job lint lee el Go de $GOFILE y no existe"
	GOTC="$(awk '$1 == "toolchain" {print $2; exit}' "$RAIZ/$GOFILE")"
	[ -n "$GOTC" ] || GOTC="go$(awk '$1 == "go" {print $2; exit}' "$RAIZ/$GOFILE")"
elif [ -z "$GOCI" ]; then
	falla "no encuentro go-version ni go-version-file en el job lint de $CI"
elif [ "$GOCI" = "stable" ]; then
	GOTC="$(curl -fsSL 'https://go.dev/dl/?mode=json' |
		python3 -c 'import json,sys; print(next(x["version"] for x in json.load(sys.stdin) if x["stable"]))')" ||
		falla "ci.yml usa Go 'stable' y no he podido preguntar a go.dev cuál es: sin eso, el lint de aquí no es el del CI"
else
	GOTC="go${GOCI#go}"
fi

case "$(uname -s)" in
Linux) SO=linux ;;
Darwin) SO=darwin ;;
*) falla "sistema $(uname -s) no soportado por este script; en Windows, usa WSL" ;;
esac
case "$(uname -m)" in
x86_64 | amd64) ARQ=amd64 ;;
aarch64 | arm64) ARQ=arm64 ;;
*) falla "arquitectura $(uname -m) no soportada" ;;
esac

V="${VERSION#v}"
DIR="${XDG_CACHE_HOME:-$HOME/.cache}/nucleo/golangci-lint-$V-$SO-$ARQ"
BIN="$DIR/golangci-lint"
if [ ! -x "$BIN" ]; then
	TMP="$(mktemp -d)"
	trap 'rm -rf "$TMP"' EXIT
	BASE="https://github.com/golangci/golangci-lint/releases/download/$VERSION"
	TAR="golangci-lint-$V-$SO-$ARQ.tar.gz"
	echo "lint.sh: descargando golangci-lint $VERSION ($SO/$ARQ)…" >&2
	curl -fsSL -o "$TMP/$TAR" "$BASE/$TAR" || falla "no se pudo descargar $BASE/$TAR"
	curl -fsSL -o "$TMP/checksums.txt" "$BASE/golangci-lint-$V-checksums.txt" || falla "no se pudo descargar el checksums.txt"
	ESPERADO="$(awk -v f="$TAR" '$2 == f {print $1}' "$TMP/checksums.txt")"
	[ -n "$ESPERADO" ] || falla "$TAR no está en el checksums.txt del release"
	if command -v sha256sum >/dev/null; then
		OBTENIDO="$(sha256sum "$TMP/$TAR" | awk '{print $1}')"
	else
		OBTENIDO="$(shasum -a 256 "$TMP/$TAR" | awk '{print $1}')"
	fi
	[ "$ESPERADO" = "$OBTENIDO" ] || falla "el sha256 de $TAR no coincide con el del release: $OBTENIDO ≠ $ESPERADO"
	tar -C "$TMP" -xzf "$TMP/$TAR"
	mkdir -p "$DIR"
	mv "$TMP/golangci-lint-$V-$SO-$ARQ/golangci-lint" "$BIN"
fi

# Lo que se va a usar, comprobado y dicho, antes de usarlo.
"$BIN" version 2>&1 | grep -q "version $V " || falla "$BIN no es la versión $V"
cd "$RAIZ"
export GOTOOLCHAIN="$GOTC"
GOVER="$(go env GOVERSION)" || falla "no se pudo obtener $GOTC (GOTOOLCHAIN)"
[ "$GOVER" = "$GOTC" ] || falla "se pidió $GOTC y go dice $GOVER"
echo "lint.sh: golangci-lint $VERSION con $GOVER — lo que fija el job lint de ci.yml" >&2

echo "== golangci-lint run ./..." >&2
"$BIN" run ./...
echo "== golangci-lint run --build-tags testhooks ./..." >&2
"$BIN" run --build-tags testhooks ./...
echo "lint.sh: ✔ las dos pasadas, sin issues" >&2
