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

# Las cuatro identidades de AUTHORS, como el sha256 de «Nombre <correo>» tal cual lo registra
# git (sin salto de línea final), cada una con una etiqueta para el mensaje. Van en hash y no
# en claro porque AUTHORS evita a propósito escribir la dirección personal de la segunda, y
# este script no tiene por qué publicarla. Cuando una identidad sobra, el error la nombra
# igual: sale del `git log` local, no de aquí. Para calcular el hash de una nueva:
#   printf '%s' 'Nombre <correo>' | sha256sum
# Si AUTHORS cambia la regla, esta lista cambia en el mismo commit.
ESPERADAS=(
	"6425732e64d025c6aa83b56a4c80c5edb4cc8dfa1df81d1829f89c67a407f509 el autor, con la identidad de AUTHORS"
	"1445e68998972fd91a47289ed83284e791534d4bdbd9146dac52ac42fff86718 el autor antes del 2026-10-02 («Sergio U», correo personal)"
	"eba34ad04fb96d1226911b5a7bce820126f1cbd9da09a187ccf16bcf6990d893 dependabot[bot]"
	"fae06183a1adc5b6d04f45adc6125acba616269ca668affe6b75c987044ae23f los merges desde la web de GitHub («Sergio Ullaguari», no-reply)"
)

huella() {
	printf '%s' "$1" | sha256sum | cut -d' ' -f1
}

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
	local e h
	h="$(huella "$1")"
	for e in "${ESPERADAS[@]}"; do
		[ "${e%% *}" = "$h" ] && return 0
	done
	return 1
}

mal=0
vistas=()
huellas_vistas=""
while IFS= read -r id; do
	[ -n "$id" ] || continue
	ya=0
	for v in "${vistas[@]+"${vistas[@]}"}"; do
		[ "$v" = "$id" ] && ya=1 && break
	done
	[ "$ya" = 1 ] && continue
	vistas+=("$id")
	huellas_vistas+="$(huella "$id")"$'\n'
	if ! esperada "$id"; then
		n="$(printf '%s\n' "$identidades" | grep -cxF -- "$id")"
		echo "identidad que AUTHORS no explica: «$id» ($n commits)."
		mal=1
	fi
done <<<"$identidades"

for e in "${ESPERADAS[@]}"; do
	if ! printf '%s' "$huellas_vistas" | grep -qxF -- "${e%% *}"; then
		echo "falta en el historial una identidad que AUTHORS explica: ${e#* } (sha256 ${e%% *})."
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
	echo "    escribe la regla en AUTHORS y añade el sha256 de la identidad a ESPERADAS en"
	echo "    scripts/autores.sh, en el mismo commit: printf '%s' 'Nombre <correo>' | sha256sum"
	exit 1
fi
echo "las ${#ESPERADAS[@]} identidades del historial son las de AUTHORS"
