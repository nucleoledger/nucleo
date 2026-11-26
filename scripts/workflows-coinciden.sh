#!/usr/bin/env bash
# workflows-coinciden.sh — release.yml y release-snapshot.yml construyen con lo mismo.
#
# release-snapshot.yml existe para probar, sin tag, lo que release.yml hará el día del
# tag: la misma goreleaser-action, fijada por el mismo SHA, y la misma versión EXACTA de
# goreleaser. Si uno se actualiza y el otro no, el snapshot prueba otra cosa y su verde
# no dice nada del próximo release. Este script lo impide: falla si difieren, o si en
# alguno falta la acción o la versión (o la versión flota: `~>`, `latest`, sin `v` y
# tres números).
#
# Lo corren la compuerta y el job `workflows` de ci.yml. Sin red y sin dependencias.
#
#   ./scripts/workflows-coinciden.sh                  # sobre .github/workflows/
#   ./scripts/workflows-coinciden.sh REL.yml SNAP.yml # sobre otros dos ficheros (lo usa su autoprueba)
set -euo pipefail

RAIZ="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REL="${1:-$RAIZ/.github/workflows/release.yml}"
SNAP="${2:-$RAIZ/.github/workflows/release-snapshot.yml}"

# accion <fichero>: la línea `uses: goreleaser/goreleaser-action@…`, sin sangría.
accion() { grep -oE 'uses: goreleaser/goreleaser-action@[^ ]+( # [^ ]+)?' "$1" | head -1 || true; }
# version <fichero>: el `version:` del bloque `with:` que sigue a la acción.
version() {
	awk '/uses: goreleaser\/goreleaser-action@/ {dentro = 1; next}
	     dentro && /^ *- / {exit}
	     dentro && $1 == "version:" {v = $0; sub(/^ *version: */, "", v); gsub(/["\047]/, "", v); print v; exit}' "$1"
}

fallos=0
for f in "$REL" "$SNAP"; do
	[ -f "$f" ] || {
		echo "✘ no existe $f" >&2
		exit 1
	}
	a="$(accion "$f")"
	v="$(version "$f")"
	if ! [[ "$a" =~ @[0-9a-f]{40}\ \#\ v[0-9] ]]; then
		echo "✘ $(basename "$f"): goreleaser-action no está fijada por SHA con su # vX.Y.Z («${a:-falta}»)" >&2
		fallos=$((fallos + 1))
	fi
	if ! [[ "$v" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
		echo "✘ $(basename "$f"): la versión de goreleaser no es exacta («${v:-falta}»)" >&2
		fallos=$((fallos + 1))
	fi
done
[ "$fallos" = 0 ] || exit 1

if [ "$(accion "$REL")" != "$(accion "$SNAP")" ]; then
	echo "✘ goreleaser-action difiere:" >&2
	echo "    $(basename "$REL"):  $(accion "$REL")" >&2
	echo "    $(basename "$SNAP"): $(accion "$SNAP")" >&2
	exit 1
fi
if [ "$(version "$REL")" != "$(version "$SNAP")" ]; then
	echo "✘ la versión de goreleaser difiere: $(version "$REL") en $(basename "$REL"), $(version "$SNAP") en $(basename "$SNAP")" >&2
	exit 1
fi
echo "✔ release.yml y release-snapshot.yml: $(accion "$REL" | sed 's/^uses: //') y goreleaser $(version "$REL")"
