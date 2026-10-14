#!/usr/bin/env bash
# ensayo-testigo-mutuo.sh — dos instalaciones que se atestiguan entre sí, de verdad.
#
# A y B son dos empresas, cada una con su ledger y con un testigo propio. El testigo
# de A atiende el log de B, y el de B el de A: dos procesos `nucleo witness serve`,
# dos memorias, dos claves (ADR-030). El ensayo comprueba, con el binario de
# producción y sin ganchos de prueba:
#
#   1. que cada uno sincroniza con el testigo del OTRO y queda atestiguado;
#   2. que la política de cada uno acepta al testigo del otro —y no al propio—;
#   3. que si A restaura un respaldo viejo de su ledger, el testigo de B lo detecta
#      como rollback (código 2) y queda constancia en el ledger de A;
#   4. que B no se entera de nada de eso: sigue sellando y sincronizando.
#
# Lo que esto NO garantiza está en docs/OPERACION.md §1, «Testigo mutuo»: dos
# empresas de acuerdo para mentir juntas siguen pudiendo.
#
#   ./scripts/ensayo-testigo-mutuo.sh            # compila el binario en un temporal
#   NUCLEO_BIN=ruta ./scripts/ensayo-testigo-mutuo.sh
set -euo pipefail

RAIZ="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
T="$(mktemp -d)"
PIDS=()
limpia() {
	for p in "${PIDS[@]:-}"; do [ -n "$p" ] && kill "$p" 2>/dev/null || true; done
	wait 2>/dev/null || true
	rm -rf "$T"
}
trap limpia EXIT

# Un binario de producción: sin ganchos, como lo usaría un operador.
for v in NUCLEO_TEST_SEED NUCLEO_TEST_CLOCK NUCLEO_TEST_PASSPHRASE NUCLEO_TEST_DIE_AT NUCLEO_TEST_PAUSE_AT NUCLEO_TEST_CARDS; do
	unset "$v"
done
if [ -n "${NUCLEO_BIN:-}" ]; then
	N="$NUCLEO_BIN"
else
	N="$T/nucleo"
	(cd "$RAIZ" && go build -o "$N" ./cmd/nucleo)
fi

fallos=0
ok() { printf '   ✔ %s\n' "$1"; }
mal() {
	printf '   ✘ %s\n' "$1"
	fallos=$((fallos + 1))
}
titulo() { printf '\n── %s\n' "$1"; }
campo() { python3 -c "import json,sys; print(json.load(sys.stdin)$1)"; }

# levanta <dir> <config>: arranca el testigo en ESTE shell —no en un $(...), que es un
# subshell y perdería el PID: el trap no lo pararía y quedaría huérfano— y guarda su
# PID en PIDS. Después, url_de <dir> espera a que diga dónde escucha.
levanta() {
	"$N" witness serve --addr 127.0.0.1:0 --db "$1/testigo.db" --config "$2" >"$1/testigo.log" 2>&1 &
	PIDS+=("$!")
}
url_de() {
	for _ in $(seq 1 100); do
		if grep -q "escuchando en" "$1/testigo.log" 2>/dev/null; then
			grep -o 'http://[^ ]*' "$1/testigo.log" | head -1
			return
		fi
		sleep 0.1
	done
	echo "el testigo de $1 no arrancó:" >&2
	cat "$1/testigo.log" >&2
	exit 1
}

titulo "Dos instalaciones, cada una con su ledger y su testigo"
for X in a b; do
	mkdir -p "$T/$X"
	printf 'passphrase de %s\n' "$X" >"$T/$X/pass"
	chmod 600 "$T/$X/pass"
	"$N" --dir "$T/$X/ledger" --json init --origin "empresa-$X.ec/facturacion" \
		--passphrase-file "$T/$X/pass" --assume-confirmed >/dev/null
	echo "{\"factura\": \"$X-1\"}" >"$T/$X/f1.json"
	"$N" --dir "$T/$X/ledger" seal --tenant 1790012345001 --type sri.factura.v1 \
		--payload "$T/$X/f1.json" --passphrase-file "$T/$X/pass" >/dev/null 2>&1
done
LOG_A=$("$N" --dir "$T/a/ledger" --json status | campo "['log_pubkey']")
LOG_B=$("$N" --dir "$T/b/ledger" --json status | campo "['log_pubkey']")
KEY_A=$("$N" --json witness key --db "$T/a/testigo.db" | campo "['public_key']")
KEY_B=$("$N" --json witness key --db "$T/b/testigo.db" | campo "['public_key']")
ok "A y B: ledger con un bloque, y la clave de cada testigo"

# El testigo de A atiende el log de B; el de B, el de A.
printf '{"name": "testigo.empresa-a.ec", "logs": {"empresa-b.ec/facturacion": "%s"}}\n' "$LOG_B" >"$T/a/testigo.json"
printf '{"name": "testigo.empresa-b.ec", "logs": {"empresa-a.ec/facturacion": "%s"}}\n' "$LOG_A" >"$T/b/testigo.json"
levanta "$T/a" "$T/a/testigo.json"
levanta "$T/b" "$T/b/testigo.json"
URL_A=$(url_de "$T/a")
URL_B=$(url_de "$T/b")
ok "el testigo de A ($URL_A) atiende el log de B; el de B ($URL_B), el de A"

titulo "Cada uno sincroniza con el testigo del OTRO"
"$N" --dir "$T/a/ledger" --json sync --witness "$URL_B" --witness-name testigo.empresa-b.ec \
	--witness-key "$KEY_B" --passphrase-file "$T/a/pass" | campo "['policy']" | tr "'" '"' >"$T/a/politica.json"
"$N" --dir "$T/b/ledger" --json sync --witness "$URL_A" --witness-name testigo.empresa-a.ec \
	--witness-key "$KEY_A" --passphrase-file "$T/b/pass" | campo "['policy']" | tr "'" '"' >"$T/b/politica.json"
chmod 644 "$T/a/politica.json" "$T/b/politica.json"
for X in a b; do
	at=$("$N" --dir "$T/$X/ledger" --json status --policy-file "$T/$X/politica.json" | campo "['attestation']")
	if [ "$at" = "verified" ]; then ok "$X atestiguado bajo su política ($at)"; else mal "$X: attestation=$at"; fi
done

titulo "La política de cada uno acepta al testigo del otro, y no al propio"
if grep -q testigo.empresa-b.ec "$T/a/politica.json" && ! grep -q testigo.empresa-a.ec "$T/a/politica.json"; then
	ok "la de A nombra al testigo de B"
else
	mal "la política de A no es la esperada"
fi
if grep -q testigo.empresa-a.ec "$T/b/politica.json" && ! grep -q testigo.empresa-b.ec "$T/b/politica.json"; then
	ok "la de B nombra al testigo de A"
else
	mal "la política de B no es la esperada"
fi
# El testigo de B no cosigna a B: su propio log no está en su configuración.
if "$N" --dir "$T/b/ledger" sync --witness "$URL_B" --witness-name testigo.empresa-b.ec \
	--witness-key "$KEY_B" --passphrase-file "$T/b/pass" >"$T/b/propio.out" 2>&1; then
	mal "el testigo de B cosignó el log de B"
else
	ok "el testigo de B no cosigna su propio log (404: no lo atiende)"
fi

titulo "A restaura un respaldo viejo: el testigo de B lo detecta"
cp -a "$T/a/ledger" "$T/a/respaldo"
for i in 2 3; do
	echo "{\"factura\": \"a-$i\"}" >"$T/a/f$i.json"
	"$N" --dir "$T/a/ledger" seal --tenant 1790012345001 --type sri.factura.v1 \
		--payload "$T/a/f$i.json" --passphrase-file "$T/a/pass" --policy-file "$T/a/politica.json" >/dev/null 2>&1
done
"$N" --dir "$T/a/ledger" sync --witness "$URL_B" --policy-file "$T/a/politica.json" --passphrase-file "$T/a/pass" >/dev/null
ok "A sella dos facturas más y el testigo de B cosigna el tamaño 3"
rm -rf "$T/a/ledger"
cp -a "$T/a/respaldo" "$T/a/ledger"
set +e
out=$("$N" --dir "$T/a/ledger" sync --witness "$URL_B" --policy-file "$T/a/politica.json" --passphrase-file "$T/a/pass" 2>&1)
code=$?
set -e
if [ "$code" = 2 ]; then ok "el sync de A tras restaurar sale con 2"; else mal "el sync de A tras restaurar salió con $code"; fi
if [[ "$out" == *"ROLLBACK LOCAL DETECTADO"* ]]; then ok "y dice ROLLBACK LOCAL DETECTADO"; else mal "no dice que es un rollback: $out"; fi
st=$("$N" --dir "$T/a/ledger" status --policy-file "$T/a/politica.json" 2>&1 || true)
if [[ "$st" == *"ROLLBACK REGISTRADO"* ]]; then
	ok "status de A sigue diciéndolo: queda constancia en su ledger"
else
	mal "status de A no lo recuerda:
$st"
fi

titulo "B no se entera de nada de eso"
echo '{"factura": "b-2"}' >"$T/b/f2.json"
"$N" --dir "$T/b/ledger" seal --tenant 1790012345001 --type sri.factura.v1 \
	--payload "$T/b/f2.json" --passphrase-file "$T/b/pass" --policy-file "$T/b/politica.json" >/dev/null 2>&1
if "$N" --dir "$T/b/ledger" sync --witness "$URL_A" --policy-file "$T/b/politica.json" --passphrase-file "$T/b/pass" >/dev/null 2>&1; then
	ok "B sella y sincroniza con el testigo de A como siempre"
else
	mal "B dejó de sincronizar"
fi

printf '\n'
if [ "$fallos" -eq 0 ]; then
	printf '✔ Testigo mutuo: cada uno atestigua al otro, y el rollback de A lo detecta el testigo de B.\n'
else
	printf '✘ %d comprobaciones fallaron\n' "$fallos"
	exit 1
fi
