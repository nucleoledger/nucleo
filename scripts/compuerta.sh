#!/usr/bin/env bash
# compuerta.sh — la compuerta completa, con una sola orden.
#
# Hasta el Sprint 17 la compuerta era una lista de catorce órdenes en CLAUDE.md, y cada
# cierre la copiaba a mano: la suite de PHP con su NUCLEO_BIN, el diferencial con su
# -count=1 —sin él, la caché de go test no escribe el catálogo y el diferencial muere con
# un ENOENT que parece un veredicto—, el ejemplo con su comprobación de que setup no
# imprime la passphrase. Una lista que se copia a mano se copia mal. El Taskfile.yml del
# Sprint 1 no lo resolvía: cubría cuatro de los catorce pasos y nadie lo usaba.
#
#   ./scripts/compuerta.sh
#
# Corre TODOS los pasos aunque alguno falle, para que una ejecución diga todo lo que está
# roto y no solo lo primero; enseña la cola de la salida de cada paso que falla, y
# termina con 1 si falló cualquiera. Es lo mismo que comprueba el CI, salvo el fuzz
# exploratorio y el arranque del servidor del ejemplo (que necesita el puerto 3000).
#
# Necesita Go, Node, Python 3 y PHP con ext-sodium. PHP se busca en $NUCLEO_PHP —puede
# llevar argumentos, p. ej. NUCLEO_PHP="/ruta/php -d extension=sodium"— o como `php` en el
# PATH. Si es un php.exe de Windows llamado desde WSL, el binario que ejecuta se compila
# para Windows y las rutas se traducen con wslpath. Sin PHP, los pasos de PHP FALLAN: la
# afirmación de los tres verificadores no se da por comprobada con dos.
set -uo pipefail

RAIZ="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$RAIZ"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

FALLOS=()
INICIO=$SECONDS

# paso NOMBRE ORDEN... ejecuta la orden con su salida en un fichero; si falla, la enseña.
paso() {
	local nombre="$1"
	shift
	local t0=$SECONDS
	printf '━━ %s\n' "$nombre"
	if "$@" >"$TMP/salida" 2>&1; then
		printf '   ✔ %d s\n' $((SECONDS - t0))
	else
		printf '   ✘ FALLÓ (%d s). Las últimas líneas:\n' $((SECONDS - t0))
		tail -n 40 "$TMP/salida" | sed 's/^/   │ /'
		FALLOS+=("$nombre")
	fi
}

formato() {
	local mal
	mal="$(gofmt -l .)"
	[ -z "$mal" ] || {
		echo "sin gofmt:"
		echo "$mal"
		return 1
	}
}

# npm_listo DIR instala las dependencias de DIR desde su lockfile si aún no están.
npm_listo() {
	[ -d "$1/node_modules" ] || (cd "$1" && npm ci --no-audit --no-fund)
}

sdk_ts() {
	npm_listo sdk/ts && (cd sdk/ts && npm run typecheck && npm test)
}

# --- PHP --------------------------------------------------------------------------

PHP_CMD="${NUCLEO_PHP:-}"
if [ -z "$PHP_CMD" ] && command -v php >/dev/null; then
	PHP_CMD=php
fi
read -r -a PHP_ARGV <<<"$PHP_CMD"
PHP_WSL=false
if [ "${#PHP_ARGV[@]}" -gt 0 ] && [[ "${PHP_ARGV[0]}" == *.exe ]] && command -v wslpath >/dev/null; then
	PHP_WSL=true
fi

# ruta_php traduce una ruta a la forma que entiende el PHP que se va a ejecutar.
ruta_php() {
	if $PHP_WSL; then wslpath -w "$1"; else echo "$1"; fi
}

hay_php() {
	[ "${#PHP_ARGV[@]}" -gt 0 ] && return 0
	echo "no hay PHP: ni \$NUCLEO_PHP ni \`php\` en el PATH."
	echo "Instala PHP con ext-sodium (CONTRIBUTING.md, «The PHP verifier») o define"
	echo "NUCLEO_PHP con la orden que lo ejecuta, p. ej. NUCLEO_PHP=\"/ruta/php -d extension=sodium\"."
	return 1
}

php_listo() {
	hay_php && "${PHP_ARGV[@]}" "$(ruta_php scripts/ci-php-listo.php)"
}

# El binario que ejecuta la suite de PHP: para Windows si PHP es un .exe desde WSL.
binario_para_php() {
	if $PHP_WSL; then
		GOOS=windows GOARCH=amd64 go build -o "$TMP/php/nucleo.exe" ./cmd/nucleo && wslpath -w "$TMP/php/nucleo.exe"
	else
		go build -o "$TMP/php/nucleo$(go env GOEXE)" ./cmd/nucleo && echo "$TMP/php/nucleo$(go env GOEXE)"
	fi
}

suite_php() {
	hay_php || return 1
	local bin
	bin="$(binario_para_php)" || return 1
	NUCLEO_BIN="$bin" WSLENV="${WSLENV:+$WSLENV:}NUCLEO_BIN" \
		"${PHP_ARGV[@]}" "$(ruta_php sdk/php/test/run.php)"
}

diferencial() {
	hay_php || return 1
	# -count=1: sin él, go test puede contestar desde la caché y no escribir el catálogo.
	NUCLEO_DIFERENCIAL_OUT="$TMP/catalogo.json" \
		go test -count=1 ./internal/receipt -run '^TestDiferencialGeneraCatalogo$' || return 1
	npm_listo sdk/ts || return 1
	(cd sdk/ts && NUCLEO_DIFERENCIAL_EXIGE_PHP=1 NUCLEO_PHP="$PHP_CMD" node scripts/diferencial.mjs "$TMP/catalogo.json")
}

# --- el ejemplo -------------------------------------------------------------------

# Lo mismo que el job `ejemplo` del CI, menos el servidor y `npm audit signatures`.
ejemplo() {
	go build -o "$TMP/ejemplo/nucleo$(go env GOEXE)" ./cmd/nucleo || return 1
	npm_listo examples/erp-node || return 1
	(
		cd examples/erp-node || exit 1
		export NUCLEO_BIN="$TMP/ejemplo/nucleo$(go env GOEXE)"
		rm -rf datos
		npm run setup 2>&1 | tee "$TMP/setup.log" || exit 1
		# setup imprime las RUTAS de la passphrase y de las tarjetas, nunca su contenido.
		if grep -qF -f datos/passphrase.txt "$TMP/setup.log"; then
			echo "la salida de setup contiene la passphrase"
			exit 1
		fi
		if grep -qF -f datos/tarjetas-DE-JUGUETE.txt "$TMP/setup.log"; then
			echo "la salida de setup contiene una tarjeta de respaldo"
			exit 1
		fi
		npm run demo || exit 1
		# El cron promete su código de salida: 3 sin testigo, 0 en la pasada semanal.
		node bin/cron.js sync
		codigo=$?
		if [ "$codigo" != "3" ]; then
			echo "sync sin testigo salió con $codigo, y tenía que ser 3"
			exit 1
		fi
		node bin/cron.js semanal
	)
}

mermaid() {
	npm_listo tools/mermaid && (cd tools/mermaid && npm run valida)
}

# Un testigo que un script levantó y no paró sigue escuchando después de la compuerta.
sin_testigos_huerfanos() {
	if pgrep -fa '^/tmp/tmp.*nucleo witness serve'; then
		echo "quedan procesos de testigo de una ejecución anterior (arriba): un script no los paró"
		return 1
	fi
}

# Un script sin el bit de ejecución en el índice sale de un clon en Linux o macOS como
# «Permission denied» (H7 de la revisión del 2026-10-11: le pasó a esta misma compuerta).
# En /mnt/c git no ve los permisos —core.filemode=false—, así que el bit no se pierde al
# editar sino al AÑADIR el fichero, y nada lo avisa: se mira el índice, no el disco.
bit_de_ejecucion() {
	local f modo mal=0
	for f in scripts/*.sh; do
		modo="$(git ls-files -s -- "$f" | cut -d' ' -f1)"
		if [ -z "$modo" ]; then
			echo "$f no está en el índice de git. Regístralo con el bit de ejecución:"
			echo "  git add $f && git update-index --chmod=+x $f"
			mal=1
		elif [ "$modo" != "100755" ]; then
			echo "$f está en el índice como $modo, sin el bit de ejecución. Pónselo con:"
			echo "  git update-index --chmod=+x $f"
			mal=1
		fi
	done
	return $mal
}

paso "bit de ejecución de scripts/*.sh" bit_de_ejecucion
paso "gofmt" formato
paso "go vet" go vet ./...
paso "go vet -tags testhooks" go vet -tags testhooks ./...
paso "lint (scripts/lint.sh)" ./scripts/lint.sh
# El mismo -timeout que el CI (ci.yml, job test): un presupuesto, no los 10 min por omisión.
paso "go test -race" go test ./... -race -count=1 -timeout 15m
paso "go test -race -tags testhooks" go test -tags testhooks ./... -race -count=1 -timeout 15m
paso "SDK de TypeScript" sdk_ts
paso "vectores de recibo (generar.py --check)" python3 testdata/vectors/receipt/generar.py --check
paso "PHP con ext-sodium" php_listo
paso "suite de PHP, con el binario" suite_php
paso "diferencial de los TRES verificadores" diferencial
paso "criterio de éxito (demo-criterio-exito.sh)" ./scripts/demo-criterio-exito.sh
paso "testigo mutuo (ensayo-testigo-mutuo.sh)" ./scripts/ensayo-testigo-mutuo.sh
paso "kit del testigo (valida-kit-testigo.sh)" ./scripts/valida-kit-testigo.sh
paso "el tercero comprueba una supresión (tercero-supresion.sh)" ./scripts/tercero-supresion.sh
paso "ejemplo erp-node" ejemplo
paso "Mermaid de ARQUITECTURA" mermaid
paso "sin testigos huérfanos" sin_testigos_huerfanos

echo
if [ "${#FALLOS[@]}" -gt 0 ]; then
	printf '✘ COMPUERTA EN ROJO (%d s): %d pasos fallaron\n' $((SECONDS - INICIO)) "${#FALLOS[@]}"
	printf '   · %s\n' "${FALLOS[@]}"
	exit 1
fi
printf '✔ COMPUERTA EN VERDE (%d s): todos los pasos\n' $((SECONDS - INICIO))
