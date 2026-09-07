#!/usr/bin/env bash
# demo-criterio-exito.sh — el criterio de éxito de la v1, como test ejecutable.
#
# CONCEPTO §18 dice que el producto existe si un desarrollador cualquiera, sin
# saber criptografía, integra Núcleo en menos de una hora, sella registros,
# altera uno a propósito y la reconciliación se lo detecta y se lo explica.
#
# Este script ejecuta esa demo entera y FALLA si algún paso no produce lo
# esperado. No imprime "OK" por su cuenta: comprueba.
#
#   ./scripts/demo-criterio-exito.sh          # usa un directorio temporal
#   ./scripts/demo-criterio-exito.sh /tmp/x   # o el que se le diga
set -euo pipefail

RAIZ="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TRABAJO="${1:-$(mktemp -d)}"
mkdir -p "$TRABAJO"

# Reloj y semilla fijos: esta demo es un test, y un test que cambia de salida en
# cada ejecución no se puede comparar con nada.
export NUCLEO_TEST_CLOCK="2026-09-07T10:00:00Z"
export NUCLEO_TEST_PASSPHRASE="correcta caballo bateria grapa"

fallos=0
paso=0

titulo() {
  paso=$((paso + 1))
  printf '\n\033[1m── PASO %d — %s\033[0m\n' "$paso" "$1"
}

# exige <descripción> <texto donde buscar> <lo que debe contener>
exige() {
  if [[ "$2" == *"$3"* ]]; then
    printf '   ✔ %s\n' "$1"
  else
    printf '   ✘ %s\n     esperaba encontrar: %s\n' "$1" "$3"
    fallos=$((fallos + 1))
  fi
}

# exige_no <descripción> <texto> <lo que NO debe contener>
exige_no() {
  if [[ "$2" != *"$3"* ]]; then
    printf '   ✔ %s\n' "$1"
  else
    printf '   ✘ %s\n     NO debía aparecer: %s\n' "$1" "$3"
    fallos=$((fallos + 1))
  fi
}

# exige_codigo <descripción> <esperado> <obtenido>
exige_codigo() {
  if [[ "$2" == "$3" ]]; then
    printf '   ✔ %s (código %s)\n' "$1" "$3"
  else
    printf '   ✘ %s: código %s, esperaba %s\n' "$1" "$3" "$2"
    fallos=$((fallos + 1))
  fi
}

printf '\033[1mCRITERIO DE ÉXITO DE LA v1 — CONCEPTO §18\033[0m\n'
printf 'directorio de trabajo: %s\n' "$TRABAJO"

# ---------------------------------------------------------------------------
titulo "compilar el binario"
NUCLEO="$TRABAJO/nucleo"
(cd "$RAIZ" && go build -o "$NUCLEO" ./cmd/nucleo)
printf '   binario: %s\n' "$NUCLEO"

# ---------------------------------------------------------------------------
titulo "init — vault, ledger y tarjetas de respaldo"
EMPRESA="$TRABAJO/mi-empresa"
export NUCLEO_TEST_SEED="$(printf '%064d' 7)"
salida_init="$("$NUCLEO" --dir "$EMPRESA" init \
  --origin nucleoledger.com/mi-empresa --assume-confirmed 2>/dev/null)"
exige "crea el vault y el ledger"        "$salida_init" "vault y ledger creados"
exige "entrega las tarjetas SLIP-0039"   "$salida_init" "TARJETAS DE RESPALDO"
exige "explica que hacen falta 2 de 3"   "$salida_init" "hacen falta 2 para recuperar"
exige "dice que se escriban en papel"    "$salida_init" "Escríbelas EN PAPEL"

# ---------------------------------------------------------------------------
titulo "seal — sellar una factura del SRI con el perfil de Ecuador"
CLAVE="$(python3 - <<'PY'
base = "070920260117900123450010010010000000011234567811"
s, f = 0, 2
for ch in reversed(base):
    s += int(ch) * f
    f = 2 if f == 7 else f + 1
d = 11 - (s % 11)
print(base + str(1 if d == 10 else (0 if d == 11 else d)))
PY
)"
cat > "$TRABAJO/factura.xml" <<XML
<?xml version="1.0" encoding="UTF-8"?>
<factura id="comprobante" version="1.0.0">
  <infoTributaria>
    <ambiente>1</ambiente>
    <tipoEmision>1</tipoEmision>
    <razonSocial>DISTRIBUIDORA DEL LITORAL S.A.S.</razonSocial>
    <ruc>1790012345001</ruc>
    <claveAcceso>$CLAVE</claveAcceso>
    <codDoc>01</codDoc>
    <estab>001</estab>
    <ptoEmi>001</ptoEmi>
    <secuencial>000000001</secuencial>
  </infoTributaria>
  <infoFactura>
    <fechaEmision>07/09/2026</fechaEmision>
    <identificacionComprador>1712345678</identificacionComprador>
    <razonSocialComprador>MARIA PEREZ</razonSocialComprador>
    <totalSinImpuestos>10000.00</totalSinImpuestos>
    <importeTotal>11500.00</importeTotal>
  </infoFactura>
</factura>
XML
salida_seal="$("$NUCLEO" --dir "$EMPRESA" seal \
  --profile ecuador.sri.factura --xml "$TRABAJO/factura.xml" 2>/dev/null)"
exige     "sella el comprobante"              "$salida_seal" "registro sellado"
exige     "reconoce el perfil"                "$salida_seal" "ecuador.sri.factura"
exige     "extrae el RUC de la clave"         "$salida_seal" "1790012345001"
exige     "compromete la cédula del comprador" "$salida_seal" "identificacion_comprador: hmac-sha256/v1:"
exige_no  "la cédula NO aparece en claro"     "$salida_seal" "1712345678"
exige_no  "el importe NO aparece en claro"    "$salida_seal" "11500.00"

# Una clave de acceso con el dígito verificador mal NO se sella.
sed "s/$CLAVE/${CLAVE:0:48}9/" "$TRABAJO/factura.xml" > "$TRABAJO/factura-mala.xml"
set +e
err_dv="$("$NUCLEO" --dir "$EMPRESA" seal --profile ecuador.sri.factura \
  --xml "$TRABAJO/factura-mala.xml" 2>&1 >/dev/null)"
codigo_dv=$?
set -e
exige_codigo "rechaza el dígito verificador incorrecto" 1 "$codigo_dv"
exige        "y explica por qué"              "$err_dv" "dígito verificador"

# ---------------------------------------------------------------------------
titulo "sync — pedir atestación a un testigo que está en otra carpeta"
TESTIGO="$TRABAJO/el-testigo"
mkdir -p "$TESTIGO"
# La clave del log sale de la propia CLI: nadie debería tener que consultar la
# base de datos con SQL para configurar un testigo.
LOGPUB="$("$NUCLEO" --dir "$EMPRESA" --json status | python3 -c 'import json,sys; print(json.load(sys.stdin)["log_pubkey"])')"
export NUCLEO_TEST_SEED="$(printf '%064d' 9)"
WKEY="$("$NUCLEO" witness key --db "$TESTIGO/testigo.db")"
"$NUCLEO" witness serve \
  --addr 127.0.0.1:18977 --db "$TESTIGO/testigo.db" \
  --name witness.nucleoledger.com/w1 \
  --log-origin nucleoledger.com/mi-empresa --log-key "$LOGPUB" \
  > "$TESTIGO/salida.txt" 2>&1 &
PID_TESTIGO=$!
trap 'kill "$PID_TESTIGO" 2>/dev/null || true' EXIT
for _ in $(seq 1 50); do
  grep -q "escuchando en" "$TESTIGO/salida.txt" && break
  sleep 0.2
done
exige "el testigo arranca con su propia base y su propia clave" \
      "$(cat "$TESTIGO/salida.txt")" "escuchando en"

salida_sync="$("$NUCLEO" --dir "$EMPRESA" sync \
  --witness http://127.0.0.1:18977 \
  --witness-name witness.nucleoledger.com/w1 --witness-key "$WKEY" 2>/dev/null)"
exige "obtiene atestación" "$salida_sync" "atestación obtenida"

salida_status="$("$NUCLEO" --dir "$EMPRESA" status 2>/dev/null)"
exige "y el estado pasa a atestiguado" "$salida_status" "historia atestiguada hasta 1 de 1"

# ---------------------------------------------------------------------------
titulo "receipt — emitir un recibo para el cliente"
salida_recibo="$("$NUCLEO" --dir "$EMPRESA" receipt --block 0 \
  --recipient "María Pérez (cédula 1712345678)" \
  --out "$TRABAJO/recibo.txt" \
  --witness-name witness.nucleoledger.com/w1 --witness-key "$WKEY" 2>/dev/null)"
exige "emite el recibo"                    "$salida_recibo" "nucleo.org/receipt@v1"
exige "muestra el tiempo declarado"        "$salida_recibo" "TIEMPO DECLARADO"
exige "y el demostrable, por separado"     "$salida_recibo" "(atestiguado por testigos)"
[[ -s "$TRABAJO/recibo.txt" ]] && printf '   ✔ el recibo se guardó en un fichero (%s bytes)\n' \
  "$(wc -c < "$TRABAJO/recibo.txt")" || { printf '   ✘ no se escribió el recibo\n'; fallos=$((fallos+1)); }

# ---------------------------------------------------------------------------
titulo "verificar el recibo con el verificador de TypeScript"
# La política se arma con lo que la propia CLI publica: origin y clave del log
# salen de `status --json`, y la del testigo de `witness key`.
POLITICA="$TRABAJO/politica.json"
"$NUCLEO" --dir "$EMPRESA" --json status | python3 -c '
import json, sys
st = json.load(sys.stdin)
print(json.dumps({
    "origin": st["origin"],
    "logKey": st["log_pubkey"],
    "witnesses": {"witness.nucleoledger.com/w1": sys.argv[1]},
    "quorum": 1,
}, indent=2))' "$WKEY" > "$POLITICA"

if [[ -f "$RAIZ/web/verify/nucleo-verify.js" ]] && command -v node >/dev/null 2>&1; then
  salida_ts="$(node - "$RAIZ/web/verify/nucleo-verify.js" "$TRABAJO/recibo.txt" "$POLITICA" <<'JS'
const fs = require("node:fs");
const vm = require("node:vm");
const [, , bundle, recibo, politica] = process.argv;
const sandbox = { crypto, console, TextEncoder, TextDecoder, atob, btoa };
sandbox.globalThis = sandbox;
vm.runInNewContext(fs.readFileSync(bundle, "utf8"), sandbox);
sandbox.NucleoVerify.verifyReceipt(
  fs.readFileSync(recibo, "utf8"),
  JSON.parse(fs.readFileSync(politica, "utf8")),
).then((r) => {
  console.log("valid=" + r.valid);
  console.log("declaredTime=" + r.declaredTime);
  console.log("provableTime=" + r.provableTime);
  console.log("blockIndex=" + r.blockIndex);
  if (!r.valid) console.log("reasons=" + r.reasons.join(" | "));
});
JS
)"
  exige "el recibo de Go verifica en TypeScript" "$salida_ts" "valid=true"
  exige "y trae tiempo demostrable"              "$salida_ts" "provableTime=2026-09-07"
  printf '   salida del verificador TS:\n%s\n' "$(echo "$salida_ts" | sed 's/^/     /')"
else
  printf '   ⚠ node o el bundle no están disponibles; se salta la verificación cruzada\n'
fi

# ---------------------------------------------------------------------------
titulo "alterar un registro a propósito y ver a reconcile delatarlo"
python3 - "$TRABAJO/factura.xml" > "$TRABAJO/vivo.jsonl" <<'PY'
import base64, json, sys
# El "sistema vivo" devuelve hoy la factura con el importe cambiado: alguien
# hizo un UPDATE en la base operativa y esta no guarda memoria de ello.
original = open(sys.argv[1], "rb").read().decode()
alterado = original.replace("<importeTotal>11500.00</importeTotal>",
                            "<importeTotal>1150.00</importeTotal>")
assert alterado != original, "la alteración no se aplicó"
print(json.dumps({"index": 0, "payload_b64": base64.b64encode(alterado.encode()).decode()}))
PY
set +e
salida_rec="$("$NUCLEO" --dir "$EMPRESA" reconcile --source "$TRABAJO/vivo.jsonl" 2>/dev/null)"
codigo_rec=$?
set -e
exige_codigo "reconcile devuelve el código de verificación fallida" 2 "$codigo_rec"
exige "señala el registro alterado"  "$salida_rec" "REGISTRO ALTERADO DESPUÉS DE SELLARSE"
exige "dice qué bloque es"           "$salida_rec" "bloque         : 0"
exige "y desde cuándo estaba sellado" "$salida_rec" "sellado el     : 2026-09-07"
exige "explica qué hizo y qué no"    "$salida_rec" "Núcleo no impidió estos cambios"

printf '\n%s\n' "$salida_rec" | sed 's/^/     /'

# El control negativo: sin alteración, no hay hallazgos.
python3 - "$TRABAJO/factura.xml" > "$TRABAJO/vivo-ok.jsonl" <<'PY'
import base64, json, sys
print(json.dumps({"index": 0,
                  "payload_b64": base64.b64encode(open(sys.argv[1], "rb").read()).decode()}))
PY
set +e
salida_ok="$("$NUCLEO" --dir "$EMPRESA" reconcile --source "$TRABAJO/vivo-ok.jsonl" 2>/dev/null)"
codigo_ok=$?
set -e
exige_codigo "y sin alteración no grita" 0 "$codigo_ok"
exige "lo dice con todas las letras" "$salida_ok" "el sistema vivo coincide con lo sellado"

# ---------------------------------------------------------------------------
printf '\n\033[1m── RESULTADO ──\033[0m\n'
if [[ "$fallos" -eq 0 ]]; then
  printf '\033[32m✔ El criterio de éxito de la v1 se cumple de punta a punta.\033[0m\n'
  printf '  %d pasos, todas las comprobaciones en verde.\n' "$paso"
  exit 0
fi
printf '\033[31m✘ %d comprobaciones fallaron. El criterio de éxito NO se cumple.\033[0m\n' "$fallos"
exit 1
