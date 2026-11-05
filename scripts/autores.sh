#!/usr/bin/env bash
# autores.sh — las identidades del historial son exactamente las cuatro que explica AUTHORS.
#
# AUTHORS no enumera commits: da una regla (los de dependabot[bot] son actualizaciones de
# dependencias, sus merges los hace el autor desde la web de GitHub, todo lo demás es del
# autor con sus dos identidades). Una regla no caduca, pero puede dejar de ser verdad sin
# que nadie lo note: le pasó a la versión anterior del fichero, que decía «todos menos
# uno» cuando ya eran seis. Este paso lo nota.
#
#   ./scripts/autores.sh       # mira `git log` del repositorio
#   ORDEN | ./scripts/autores.sh -   # mira las identidades que llegan por stdin, una por
#                                    # línea («Nombre <correo>»); sirve para probar el paso
#
# Va en la compuerta y NO en el CI: el CI clona sin historia (fetch-depth 1) y vería una
# sola identidad. Con un clon superficial, este script falla y dice cómo completarlo.
set -euo pipefail

cd "$(dirname "$0")/.."

# Las cuatro identidades de AUTHORS, con el correo que registra git. Si AUTHORS cambia la
# regla, esta lista cambia en el mismo commit.
ESPERADAS=(
	"Sergio Iván Ullaguari Alvarado <security@nucleoledger.com>"
	"Sergio U <cheobmx13@gmail.com>"
	"dependabot[bot] <49699333+dependabot[bot]@users.noreply.github.com>"
	"Sergio Ullaguari <53920477+cheo13@users.noreply.github.com>"
)

if [ "${1:-}" = "-" ]; then
	identidades="$(cat)"
else
	if [ "$(git rev-parse --is-shallow-repository)" = "true" ]; then
		echo "el clon es superficial: sin el historial completo no se puede comprobar AUTHORS."
		echo "Complétalo con:"
		echo "  git fetch --unshallow"
		exit 1
	fi
	identidades="$(git log --format='%an <%ae>')"
fi

esperada() {
	local e
	for e in "${ESPERADAS[@]}"; do
		[ "$e" = "$1" ] && return 0
	done
	return 1
}

mal=0
vistas=()
while IFS= read -r id; do
	[ -n "$id" ] || continue
	ya=0
	for v in "${vistas[@]+"${vistas[@]}"}"; do
		[ "$v" = "$id" ] && ya=1 && break
	done
	[ "$ya" = 1 ] && continue
	vistas+=("$id")
	if ! esperada "$id"; then
		n="$(printf '%s\n' "$identidades" | grep -cxF -- "$id")"
		echo "identidad que AUTHORS no explica: «$id» ($n commits)."
		mal=1
	fi
done <<<"$identidades"

for e in "${ESPERADAS[@]}"; do
	if ! printf '%s\n' "$identidades" | grep -qxF -- "$e"; then
		echo "falta en el historial una identidad que AUTHORS explica: «$e»."
		echo "Un historial append-only no pierde autores: o el clon está incompleto, o la lista de"
		echo "este script no es la de AUTHORS."
		mal=1
	fi
done

if [ "$mal" = 1 ]; then
	echo
	echo "Qué hacer, según el caso:"
	echo "  - si el commit es tuyo y salió con otra identidad y aún no lo has subido, rehazlo con"
	echo "    la de siempre: git config user.name / user.email, y git commit --amend --reset-author"
	echo "    si es el último, o git rebase -i para uno anterior;"
	echo "  - si la identidad es legítima (otro bot, otra persona), AUTHORS tiene que explicarla:"
	echo "    escribe la regla en AUTHORS y añade la identidad a ESPERADAS en scripts/autores.sh,"
	echo "    en el mismo commit."
	exit 1
fi
echo "las ${#ESPERADAS[@]} identidades del historial son las de AUTHORS"
