# Integra Núcleo en tu sistema en una hora

Esto es una guía para un desarrollador que ya tiene un sistema funcionando —una
facturación, un ERP, lo que sea— y quiere que sus registros importantes queden
sellados de forma que una alteración posterior no pueda pasar inadvertida.

**No hace falta saber criptografía.** Hacen falta una terminal y un editor.

Cada comando de esta guía se ejecutó de verdad, y las salidas que verás están
copiadas de esa ejecución. Si algo no coincide en tu máquina, no es que la guía
esté "simplificada": es que pasó otra cosa y conviene averiguar cuál.

> Las rutas de las salidas están recortadas para que se lean. Lo demás es literal.

---

## Antes de empezar

Necesitas **Go 1.27 o superior** para compilar el binario. Nada más: sin Docker,
sin base de datos que instalar, sin servidor.

```bash
git clone https://github.com/nucleoledger/nucleo
cd nucleo
go build -o nucleo ./cmd/nucleo
```

Comprueba que responde:

```bash
./nucleo help
```

---

## Paso 1 — Crear el vault y el ledger

Aquí nacen tus claves. El `--origin` es el nombre con el que tu log se identifica
ante los testigos; usa un dominio tuyo, aunque no apunte a ninguna parte.

```bash
./nucleo --dir ./mi-empresa init --origin nucleoledger.com/mi-empresa
```

Te pedirá una passphrase **dos veces y sin eco** —no verás lo que escribes—.
Después imprime esto:

```
✔ vault y ledger creados en ./mi-empresa
  origin        : nucleoledger.com/mi-empresa
  clave tenant  : 57857f0ed34d9ab44aad8f122f890075bd60ca3bd9142f787cf91b80a4854f2a
  clave del log : 9ad2d5b3d3cc90105737568e1b5850035c181004e46f967da9ba21188818f004

═══════════════════════════════════════════════════════════════
  TARJETAS DE RESPALDO DE LA CLAVE — SLIP-0039
═══════════════════════════════════════════════════════════════

  Son 3 tarjetas y hacen falta 2 para recuperar el vault.
  Con 1 no se recupera nada: no son copias, son fragmentos.

  ── TARJETA 1 de 3 ──
     elite survive academic acid antenna body
     indicate blessing morning civil rich romantic
     literary body again penalty venture talent
     patrol smell evoke class short shaft
     holy ecology hospital husband escape spider
     airline verdict kind

  ── TARJETA 2 de 3 ──
     elite survive academic agency ambition swimming
     ...

  CÓMO GUARDARLAS
  · Escríbelas EN PAPEL. No en el ordenador, no en el móvil, no
    en una foto: cualquiera de esas cosas se sincroniza sola con
    algún sitio que no controlas.
  · Guárdalas en 3 lugares DISTINTOS y con dueños distintos. Dos
    tarjetas en el mismo cajón son una sola tarjeta.
  · Quien reúna 2 tarjetas abre el vault. Repártelas pensando en
    eso, no solo en no perderlas.
```

Antes de terminar te pedirá **teclear una palabra concreta de la tarjeta 1**. No
es un trámite: es lo que obliga a copiarlas mientras están en pantalla. El error
más común es seguir adelante pensando en apuntarlas luego, y no se descubre
hasta el día en que hacen falta.

> **Automatización.** Para scripts existen `--passphrase-file` y
> `--assume-confirmed`. Úsalos con cabeza: quien pueda leer ese fichero puede
> abrir tu vault. La passphrase **nunca** se pasa por argumento, porque los
> argumentos son visibles en la lista de procesos de toda la máquina.

---

## Paso 2 — Sellar tu primer registro

Núcleo sella **los bytes exactos** de tu documento. Si es un XML del SRI con
firma XAdES, se sella tal cual: recanonicalizarlo rompería la firma.

Con el perfil de Ecuador, además valida la clave de acceso y separa lo que es
público de lo que no:

```bash
./nucleo --dir ./mi-empresa seal \
  --profile ecuador.sri.factura \
  --xml ./factura.xml
```

```
✔ registro sellado
  bloque       : 0
  hash bloque  : 9b28759f6950d64031fa8acc0dedf01bd76f3bc9401611fd980da7487dcc582a
  hash contenido: e08ab33e7b33533ce06bb329179f55c14afea63b38fcb2d993d6625362a3b839

  perfil       : ecuador.sri.factura
    clave_acceso:            0709202601179001234500110010010000000011234567816
    establecimiento:         001
    fecha_emision:           2026-09-07
    ruc_emisor:              1790012345001
    secuencial:              000000001
    tipo_comprobante:        01

  campos sensibles, registrados como COMPROMISO (nunca como hash desnudo):
    identificacion_comprador: hmac-sha256/v1:b1130f607fed8f8d1f94603…
    importe_total:           hmac-sha256/v1:dc94661f4c02b71ce759b76…
    razon_social_comprador:  hmac-sha256/v1:42e28aaf3e0817ca484fc02…

  Un hash desnudo de una cédula o un importe se invierte probando: el
  espacio de valores es diminuto. Con clave, el diccionario no sirve.

  El bloque aún no está atestiguado. Ejecuta `nucleo sync` para que
  un testigo lo vea; hasta entonces solo lo respalda esta máquina.
```

Fíjate en lo que **no** aparece: ni la cédula del comprador, ni su nombre, ni el
importe. Están comprometidos con una clave derivada de tu vault. Un hash a secas
de una cédula se invierte probando los diez mil millones de combinaciones; con
clave, ese diccionario no sirve de nada.

Si la clave de acceso tiene el dígito verificador mal, **no se sella**:

```
error: ecuador: dígito verificador incorrecto: la clave termina en 9 y el
módulo 11 de los 48 dígitos anteriores da 1
```

Y el código de salida es `1`. Mejor enterarse ahora que dejar en el ledger, para
siempre, un comprobante que el SRI no reconoce.

### Sellar desde tu código

La CLI es la integración. Cualquier lenguaje que pueda lanzar un proceso puede
usar Núcleo; con `--json` la salida es para máquinas. En Node:

```js
import { execFile } from "node:child_process";
import { promisify } from "node:util";
const run = promisify(execFile);

async function sellar(xmlPath) {
  const { stdout } = await run("./nucleo", [
    "--dir", "./mi-empresa", "--json",
    "seal", "--profile", "ecuador.sri.factura", "--xml", xmlPath,
  ], { env: { ...process.env, NUCLEO_PASSPHRASE_FILE: "/ruta/segura/pass" } });

  const r = JSON.parse(stdout);
  // Guarda esto junto a tu factura: es lo que te permitirá emitir el recibo.
  return { bloque: r.index, hashContenido: r.payload_hash };
}
```

En modo `--json` **no se imprime ni una línea de prosa**, para que puedas parsear
sin filtrar nada. Y los códigos de salida son contrato:

| código | significa |
|---:|---|
| 0 | todo correcto |
| 1 | error de uso o de entrada |
| 2 | **la verificación falló**: hay una alteración o una discrepancia |
| 3 | **la sincronización con el testigo falló** |

El 3 merece una alerta si se repite: un testigo inalcanzable de forma sostenida
es indistinguible de uno al que están impidiendo hablar.

---

## Paso 3 — Mirar el estado

```bash
./nucleo --dir ./mi-empresa status
```

```
ledger    : ./mi-empresa/nucleo.db
origin    : nucleoledger.com/mi-empresa
clave log : 9ad2d5b3d3cc90105737568e1b5850035c181004e46f967da9ba21188818f004
bloques   : 1
raíz      : e6a49cdde0e70df7cac335235e395cfd290c6c8859d2ec90c980b59d3b6de31e
estado    : ⚠ SIN ATESTIGUAR (1 bloques)
            La cadena es localmente válida, pero que esté COMPLETA no
            está garantizado: sin un checkpoint cosignado por un testigo,
            un prefijo truncado es indistinguible de la historia entera.
            Ejecuta `nucleo sync` contra un testigo.
```

Ese aviso es importante y conviene entenderlo. Tu ledger es **íntegro**: cada
bloque encadena con el anterior y las firmas cuadran. Pero íntegro no es
**completo**. Si alguien con acceso a tu servidor borrase los últimos registros,
lo que quedaría seguiría siendo una cadena impecable — solo que más corta. Nada
dentro del fichero puede desmentirlo, porque el fichero entero sería suyo.

Lo que lo desmiente es un testigo.

---

## Paso 4 — Levantar un testigo

Un testigo es un proceso aparte, con su propia base de datos y su propia clave,
que firma "he visto este log con este tamaño en este momento". Lo interesante es
que **no está en tu máquina**: en producción lo pones en otro servidor, o lo
opera un tercero.

Para la guía, otra carpeta basta.

```bash
mkdir -p ./el-testigo

# La clave del testigo. Se crea la primera vez y se conserva.
WKEY=$(./nucleo witness key --db ./el-testigo/testigo.db)

# El origin y la clave de tu log, publicados por status.
LOGPUB=$(./nucleo --dir ./mi-empresa --json status | jq -r .log_pubkey)

./nucleo witness serve \
  --addr 127.0.0.1:18988 \
  --db ./el-testigo/testigo.db \
  --name witness.nucleoledger.com/w1 \
  --log-origin nucleoledger.com/mi-empresa \
  --log-key "$LOGPUB"
```

```
testigo witness.nucleoledger.com/w1 escuchando en http://127.0.0.1:18988
  memoria    : ./el-testigo/testigo.db
  clave      : dd7e84d010aed28a416e928f50c4c09ac0f94a8f5b346548168bddb61cdb7263
  log servido: nucleoledger.com/mi-empresa

Ctrl-C para parar.
```

Déjalo corriendo y abre otra terminal.

---

## Paso 5 — Sincronizar

```bash
./nucleo --dir ./mi-empresa sync \
  --witness http://127.0.0.1:18988 \
  --witness-name witness.nucleoledger.com/w1 \
  --witness-key "$WKEY"
```

```
✔ atestación obtenida del testigo witness.nucleoledger.com/w1
  origin  : nucleoledger.com/mi-empresa
  bloques : 1
  (era el primer checkpoint de este log para ese testigo)
```

Vuelve a mirar el estado:

```
estado    : ✔ historia atestiguada hasta 1 de 1 bloques
```

Eso ya es otra cosa. Ahora existe, fuera de tu máquina, una firma de un tercero
diciendo que tu log tenía un bloque. Recortarlo dejaría una contradicción que la
próxima sincronización detecta.

**Sincroniza a menudo.** Un `sync` en el cron cada hora es razonable: lo que no
esté atestiguado solo lo respalda tu propio disco.

---

## Paso 6 — Emitir un recibo

Un recibo es lo que le entregas a la otra parte. Se verifica **sin ti**: sin tu
servidor, sin tu base de datos y sin pedirte permiso.

```bash
./nucleo --dir ./mi-empresa receipt \
  --block 0 \
  --recipient "María Pérez (cédula 1712345678)" \
  --out ./recibo.txt \
  --witness-name witness.nucleoledger.com/w1 \
  --witness-key "$WKEY"
```

```
✔ recibo escrito en ./recibo.txt (4500 bytes)

nucleo.org/receipt@v1
destinatario      : María Pérez (cédula 1712345678)
emisor (tenant)   : 1790012345001
tipo de registro  : ecuador.sri.factura.v1
hash del contenido: e08ab33e7b33533ce06bb329179f55c14afea63b38fcb2d993d6625362a3b839
bloque            : 0

TIEMPO DECLARADO  : 2026-09-07T10:00:00Z  (declarado por el sistema emisor)
TIEMPO DEMOSTRABLE: 2026-09-07T10:00:00Z  (atestiguado por testigos)
```

**Los dos tiempos son cosas distintas y el recibo nunca los confunde.**

- El **declarado** lo puso tu sistema. Sale de un reloj que tú controlas, así
  que puede mentir. Se muestra porque es útil, no porque pruebe nada.
- El **demostrable** lo firmó el testigo. Un tercero independiente afirmó haber
  visto ese árbol en ese momento, y eso sí acota cuándo existía el registro.

Si no hay testigo, el recibo lo dice con todas las letras: `SIN TIEMPO
DEMOSTRABLE`. Callarse y enseñar solo el declarado sería presentarlo como prueba.

---

## Paso 7 — Que el destinatario lo verifique

Abre `web/verify/index.html` en un navegador. **No usa la red**: puedes guardarla
junto a `nucleo-verify.js` y abrirla sin conexión dentro de diez años.

Pega el recibo y esta política, que le dices al destinatario cuáles son tus
claves:

```json
{
  "origin": "nucleoledger.com/mi-empresa",
  "logKey": "9ad2d5b3d3cc90105737568e1b5850035c181004e46f967da9ba21188818f004",
  "witnesses": {
    "witness.nucleoledger.com/w1": "dd7e84d010aed28a416e928f50c4c09ac0f94a8f5b346548168bddb61cdb7263"
  },
  "quorum": 1
}
```

Verás **✔ Recibo válido**, los dos relojes etiquetados y el bloque. Si alguien
retoca una sola letra del texto visible del recibo, verás ✘ y la razón: el
encabezado se deriva de la prueba, así que un recibo cuyo texto contradiga sus
bytes no se acepta.

El mismo verificador corre en Node, si prefieres automatizarlo:

```js
import { verifyReceipt } from "@nucleoledger/verify";
const r = await verifyReceipt(textoDelRecibo, politica);
if (!r.valid) console.error("recibo inválido:", r.reasons);
```

---

## Paso 8 — Alterar un registro y ver qué pasa

Esto es lo que Núcleo existe para hacer. Núcleo **no puede impedir** que alguien
edite tu base de datos operativa: no es suya. Lo que hace es recordar qué decía
cada registro cuando se selló.

Simula el ataque. Cambia el importe de la factura en tu sistema, de `11500.00` a
`1150.00`, y pásale a Núcleo lo que tu sistema devuelve **hoy**:

```bash
# Un fichero JSONL: una línea por registro vivo.
# {"index":N,"payload_b64":"<el contenido actual, en base64>"}
./nucleo --dir ./mi-empresa reconcile --source ./vivo.jsonl
```

```
comparados : 1
coinciden  : 0
hallazgos  : 1
ledger     : ✔ verificación exhaustiva superada

  ✘ REGISTRO ALTERADO DESPUÉS DE SELLARSE
      bloque         : 0
      emisor         : 1790012345001
      tipo           : ecuador.sri.factura.v1
      sellado el     : 2026-09-07T10:00:00Z  (tiempo declarado)
      hash sellado   : e08ab33e7b33533ce06bb329179f55c14afea63b38fcb2d993d6625362a3b839
      hash actual    : ff8b2a5bb21280de28a0182677a8c8d45598b5c6cb39892eae62e6b0f9667979

  Núcleo no impidió estos cambios: la base operativa no es suya. Lo que
  hace es recordar qué decía cada registro cuando se selló, y desde
  cuándo. La alteración deja de ser invisible.
```

Y el código de salida es **2**, así que un cron lo detecta sin leer la prosa:

```bash
./nucleo --dir ./mi-empresa reconcile --source ./vivo.jsonl --json || alertar
```

`reconcile` también avisa de lo que **falta** —registros sellados que tu sistema
ya no tiene— y de lo que **sobra** —registros vivos que nunca se sellaron—.

---

## Lo que acabas de montar

```
tu sistema  ──seal──▶  ledger local  ──sync──▶  testigo (otra máquina)
     │                      │                        │
     │                      └──receipt──▶ recibo ────┘
     │                                      │
     └────────reconcile ◀───────────────────┘
                                            ▼
                                  verificador en el navegador
```

Con eso tienes, en orden de importancia:

1. **Un registro que no se puede reescribir sin que se note.** Si alguien edita
   la base operativa, `reconcile` lo señala con nombre y fecha.
2. **Una fecha que no depende de tu palabra.** El testigo firma cuándo vio cada
   estado de tu log.
3. **Recibos que sobreviven a tu empresa.** Se verifican sin tus servidores.
4. **Un derecho de supresión que no rompe nada.** Los contenidos sensibles viven
   cifrados y borrables; borrarlos deja el ledger intacto y los recibos válidos.

---

## Lo que Núcleo NO hace

Conviene decirlo para que nadie construya sobre una expectativa falsa.

- **No impide que te alteren la base operativa.** La hace visible.
- **No prueba que el contenido sea cierto.** Prueba que ese contenido exacto
  estaba en el log en ese momento. Una factura falsa sellada sigue siendo falsa,
  solo que ahora consta desde cuándo existe.
- **No te certifica ante ninguna autoridad.** Está diseñado para alinearse con
  la LOPDP y con la normativa del SRI; alinearse no es tener un dictamen.
- **No verifica la firma XAdES de tu XML.** Eso lo hace el SRI. Núcleo sella los
  bytes tal cual, que es lo que le permite no romperla.

---

## Si algo va mal

| síntoma | qué mirar |
|---|---|
| `no hay ledger en ...` | te falta `init`, o el `--dir` no es el que crees |
| `no se pudo abrir el vault` | passphrase incorrecta; no hay forma de recuperarla salvo las tarjetas |
| `SIN ATESTIGUAR` | no has ejecutado `sync`, o el testigo no responde |
| código 3 repetido | el testigo lleva rato inalcanzable: **míralo**, no lo silencies |
| `dígito verificador incorrecto` | la clave de acceso está mal tecleada o mal generada |
| el recibo no verifica | comprueba que la política tenga el `origin` y las claves correctas |

Y si perdiste la passphrase pero tienes las tarjetas:

```bash
./nucleo --dir ./mi-empresa restore
```

Escribe dos mnemónicos y comprobará que reconstruyen la clave **de este vault**,
no solo una clave cualquiera.

---

## ¿Ha llevado menos de una hora?

Ese es el criterio con el que se mide este proyecto, y está automatizado:

```bash
./scripts/demo-criterio-exito.sh
```

Ejecuta todo lo anterior de punta a punta y falla si algún paso no produce lo que
debe. Si ese script pasa en tu máquina, tienes la integración funcionando.
