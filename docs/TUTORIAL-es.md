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
  perfil KDF    : default (64 MiB, 3 iteraciones, 4 hilo(s))

═══════════════════════════════════════════════════════════════
  TARJETAS DE RESPALDO DE LA CLAVE — SLIP-0039
═══════════════════════════════════════════════════════════════

  Son 3 tarjetas y hacen falta 2 para recuperar el vault.
  Con 1 no se recupera nada: no son copias, son fragmentos.

  ── TARJETA 1 de 3 ──
     ajar kidney academic acid acid advocate
     cover clogs license permit wildlife dance
     acrobat elegant peasant counter maiden escape
     slavery presence dough herd main cause
     firefly column ancestor stilt iris spew
     rainbow nylon secret

  ── TARJETA 2 de 3 ──
     ajar kidney academic agency amount sheriff
     ...

  CÓMO GUARDARLAS
  · Escríbelas EN PAPEL. No en el ordenador, no en el móvil, no
    en una foto: cualquiera de esas cosas se sincroniza sola con
    algún sitio que no controlas.
  · Guárdalas en 3 lugares DISTINTOS y con dueños distintos. Dos
    tarjetas en el mismo cajón son una sola tarjeta.
  · Quien reúna 2 tarjetas abre el vault. Repártelas pensando en
    eso, no solo en no perderlas.
  · Esta pantalla NO se puede volver a ver. Se pueden emitir
    tarjetas nuevas con `nucleo backup`, pero solo si aún tienes
    la passphrase.
```

Antes de terminar te pedirá **teclear una palabra concreta de la tarjeta 1**. No
es un trámite: es lo que obliga a copiarlas mientras están en pantalla. El error
más común es seguir adelante pensando en apuntarlas luego, y no se descubre
hasta el día en que hacen falta.

> **¿Hosting compartido?** Abrir el vault pide **64 MiB** de memoria, porque eso
> es lo que hace caro probar passphrases. En un plan compartido con límites de
> LVE/CageFS, eso no es "más lento": es un proceso que el hosting mata. Para ese
> caso existe `init --kdf-profile constrained`, que baja a 19 MiB, 2 iteraciones
> y 1 hilo — el mínimo que recomienda OWASP.
>
> Medido en un Ryzen 7 5700U: abrir el vault pasa de **51 ms y 67 MB** a **25 ms
> y 20 MB**. Es más débil, y conviene saber cuánto: con 8 GiB de RAM, quien robe
> tu vault pasa de unos **2.400 intentos por segundo a unos 16.700**, un factor
> **7**. Compénsalo con una passphrase más larga — cuatro palabras más valen
> mucho más que ese factor.
>
> Los parámetros quedan guardados en el vault, así que se abre con los que se
> creó aunque una versión futura suba los valores por omisión. Cambiar de perfil
> exige crear un vault nuevo.

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
  hash bloque  : e29d362566c75076f5388a1c905b2e116cc78bc338b8f2d0931746c2a67ce354
  hash contenido: c5b0e7f18d0d1829df5d6895d1fbac063c5e09af3c5276a9a43d461ef1f8754b

  perfil       : ecuador.sri.factura
    clave_acceso:            0709202601179001234500110010010000000011234567816
    establecimiento:         001
    fecha_emision:           2026-09-07
    ruc_emisor:              1790012345001
    secuencial:              000000001
    tipo_comprobante:        01

  campos sensibles, registrados como COMPROMISO (nunca como hash desnudo):
    identificacion_comprador: hmac-sha256/v1:23ea3816f74b46c584c3e17…
    importe_total:           hmac-sha256/v1:19cda343843e598eaf8cdb5…
    razon_social_comprador:  hmac-sha256/v1:4cb5a652bf76e1a66c4a5a4…

  Un hash desnudo de una cédula o un importe se invierte probando: el
  espacio de valores es diminuto. Con clave, el diccionario no sirve.

  El bloque aún no está atestiguado. Ejecuta `nucleo sync` para que
  un testigo lo vea; hasta entonces solo lo respalda esta máquina.
frescura  : ⚠ ninguna atestación verificada, ni registro de haberla tenido
```

La última línea, `frescura`, es un aviso que te acompañará hasta que sincronices
con un testigo; el Paso 3 explica qué significa.

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
ledger    : mi-empresa/nucleo.db
origin    : nucleoledger.com/mi-empresa
clave log : 9ad2d5b3d3cc90105737568e1b5850035c181004e46f967da9ba21188818f004
regla hoja: leaf/v2
clave firma: 57857f0ed34d9ab44aad8f122f890075bd60ca3bd9142f787cf91b80a4854f2a
bloques   : 1
raíz      : ffed719f554a3655156c7b8381604f15974a2cf14c3838d0e1ea11e6d9c74307
firmante  : ◐ una sola clave en toda la cadena, NO verificada contra ninguna política
            Pasa --signer-key o --policy-file para comprobar que es la tuya.
estado    : ⚠ SIN ATESTIGUAR (1 bloques)
            La cadena es localmente válida, pero que esté COMPLETA no
            está garantizado: sin un checkpoint cosignado por un testigo,
            un prefijo truncado es indistinguible de la historia entera.
            Ejecuta `nucleo sync` contra un testigo.
frescura  : ⚠ ninguna atestación verificada, ni registro de haberla tenido
```

Y por **stderr**, sin que nadie lo haya pedido:

```
AVISO: este ledger no tiene ninguna atestación verificada ni registro de haberla tenido.
       Que la cadena sea localmente válida no dice que esté completa: un
       prefijo truncado es indistinguible de la historia entera mientras
       nadie de fuera haya visto una raíz. Ejecuta `nucleo sync`.
```

Ese aviso es importante y conviene entenderlo. Tu ledger es **íntegro**: cada
bloque encadena con el anterior y las firmas cuadran. Pero íntegro no es
**completo**. Si alguien con acceso a tu servidor borrase los últimos registros,
lo que quedaría seguiría siendo una cadena impecable — solo que más corta. Nada
dentro del fichero puede desmentirlo, porque el fichero entero sería suyo.

La línea `firmante` dice algo parecido de las firmas. Núcleo comprueba **siempre**
que toda la cadena la firma una sola clave —la que ves en `clave firma`—, así que
nadie puede refirmar unos bloques sueltos con otra. Pero si alguien reescribiera la
cadena **entera** con su propia clave, sería igual de coherente. Lo que la distingue
de la tuya es que tú sabes cuál es la tuya. Por eso dice "NO verificada": todavía
no le has dicho a Núcleo qué clave esperar. Lo harás en el Paso 5, con la política.

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
  tiempo  : 2026-09-07T10:00:00Z (lo afirma el testigo, no este reloj)
  (era el primer checkpoint de este log para ese testigo)

  Tu política, lista para guardar como politica.json:

  {
    "origin": "nucleoledger.com/mi-empresa",
    "logKey": "9ad2d5b3d3cc90105737568e1b5850035c181004e46f967da9ba21188818f004",
    "signerKey": "57857f0ed34d9ab44aad8f122f890075bd60ca3bd9142f787cf91b80a4854f2a",
    "witnesses": {
      "witness.nucleoledger.com/w1": "dd7e84d010aed28a416e928f50c4c09ac0f94a8f5b346548168bddb61cdb7263"
    },
    "quorum": 1
  }

  Y el cron, con ella:

    nucleo --dir ./mi-empresa sync --witness URL --policy-file politica.json
    nucleo --dir ./mi-empresa status --policy-file politica.json

  Es lo mismo que tu contraparte necesita para verificar tus recibos:
  la misma política, el mismo fichero.
```

Eso último es **tu política**, y es la pieza más importante de esta guía. Guárdala
tal cual en `politica.json`, junto a tu ledger. (Si lo automatizas, `sync --json`
la devuelve en el campo `policy`: `jq .policy > politica.json`.)

Tiene cinco campos y cada uno responde a una pregunta:

| campo | responde a |
|---|---|
| `origin` | ¿de qué log hablamos? |
| `logKey` | ¿quién firma los checkpoints de ese log? |
| `signerKey` | ¿quién firma los **bloques**? |
| `witnesses` | ¿qué terceros cuentan, y con qué clave? |
| `quorum` | ¿cuántos de ellos tienen que haber firmado? |

**La política es lo único en lo que confías; todo lo demás se comprueba contra
ella** (ADR-017). Y es **el mismo fichero** para ti y para quien recibe tus recibos:
la CLI, el SDK de TypeScript y la página de verificación leen exactamente este
formato.

Vuelve a mirar el estado, ahora **con la política**:

```bash
./nucleo --dir ./mi-empresa status --policy-file politica.json
```

```
ledger    : mi-empresa/nucleo.db
origin    : nucleoledger.com/mi-empresa
clave log : 9ad2d5b3d3cc90105737568e1b5850035c181004e46f967da9ba21188818f004
regla hoja: leaf/v2
clave firma: 57857f0ed34d9ab44aad8f122f890075bd60ca3bd9142f787cf91b80a4854f2a
bloques   : 1
raíz      : ffed719f554a3655156c7b8381604f15974a2cf14c3838d0e1ea11e6d9c74307
firmante  : ✔ verificado contra la política
estado    : ✔ historia atestiguada hasta 1 de 1 bloques
frescura  : ✔ atestación verificada de hace 0 segundos, por witness.nucleoledger.com/w1
```

Tres ✔, y cada uno dice una cosa distinta:

- **firmante**: la cadena la firma la clave de `signerKey`, no otra.
- **estado**: un checkpoint cosignado cubre la historia, y la cosignature
  verifica contra la clave del testigo **que tú aportaste**.
- **frescura**: esa cosignature es de hace nada. La fecha es la que firmó el
  testigo, no la de tu reloj.

Sin la política, `status` no puede afirmar nada de eso, y no lo afirma:

```bash
./nucleo --dir ./mi-empresa status
```

```
ledger    : mi-empresa/nucleo.db
origin    : nucleoledger.com/mi-empresa
clave log : 9ad2d5b3d3cc90105737568e1b5850035c181004e46f967da9ba21188818f004
regla hoja: leaf/v2
clave firma: 57857f0ed34d9ab44aad8f122f890075bd60ca3bd9142f787cf91b80a4854f2a
bloques   : 1
raíz      : ffed719f554a3655156c7b8381604f15974a2cf14c3838d0e1ea11e6d9c74307
firmante  : ◐ una sola clave en toda la cadena, NO verificada contra ninguna política
            Pasa --signer-key o --policy-file para comprobar que es la tuya.
estado    : ◐ checkpoint presente hasta el bloque 1, NO verificado
            no se aportó ninguna política de testigos al abrir.
            Para comprobar que un testigo lo avala, pasa --policy-file (o
            --witness-name y --witness-key): la prueba tiene que venir de
            fuera de este fichero.
frescura  : ◐ registro local de hace 0 segundos, por witness.nucleoledger.com/w1 — NO verificado
            Lo escribió el último `sync` en este disco; abre con --policy-file
            para que la frescura salga de la cosignature verificada.
```

La razón es la que da nombre a este producto. Todo lo que hay dentro de
`nucleo.db` lo puede escribir quien tenga el fichero — incluido un checkpoint con
aspecto de cosignado, y una auditoría lo fabricó; incluido el registro de "última
atestación" del que sale la frescura, y otra auditoría lo escribió a mano con un
testigo inventado. Lo único que **no** se puede fabricar es la firma de un testigo
cuya clave no se tiene, y eso solo se comprueba con una clave que traes tú desde
fuera. Por eso "atestiguada" no es algo que el fichero pueda afirmar de sí mismo: es
algo que verificas, o no lo es.

> **¿Y las banderas sueltas?** `--witness-name` y `--witness-key` siguen
> funcionando y verifican la atestación igual. Pero sin `--signer-key` el firmante
> se queda en "◐ NO verificada", así que lo cómodo y lo completo es el fichero. No
> se mezclan: `--policy-file` junto a banderas sueltas es un error de uso, porque
> dos fuentes de verdad acaban contradiciéndose en silencio.

Ahora existe, fuera de tu máquina, una firma de un tercero diciendo que tu log tenía
un bloque. Recortarlo dejaría una contradicción que la próxima sincronización
detecta.

**Sincroniza a menudo.** Un `sync` en el cron cada hora es razonable —las dos líneas
que `sync` te imprimió son exactamente eso—: lo que no esté atestiguado solo lo
respalda tu propio disco.

**Y si el cron se rompe, Núcleo te lo dice solo.** Esa es la parte que importa,
porque un cron roto no avisa: simplemente deja de correr. Pasadas **72 horas** sin
una atestación, `status`, `seal`, `verify` y `reconcile` escriben un aviso por
**stderr** —también en modo `--json`, donde además va el campo
`freshness.stale`—. Cuatro días después de este `sync`, con la política:

```
AVISO: la última atestación es de hace 4 días (umbral: 3 días).
       witness.nucleoledger.com/w1 la firmó el 2026-09-07T10:00:00Z, cubriendo 1 bloques. Desde entonces, lo
       que respalda esta historia es solo este disco.
       Si hay un `nucleo sync` en el cron, probablemente lleva 4 días roto.
```

Y sin ella, el mismo aviso, pero diciendo de dónde sale la fecha:

```
AVISO: la última atestación es de hace 4 días (umbral: 3 días) (registro local, NO verificado).
       witness.nucleoledger.com/w1 la firmó el 2026-09-07T10:00:00Z, cubriendo 1 bloques. Desde entonces, lo
       que respalda esta historia es solo este disco.
       Si hay un `nucleo sync` en el cron, probablemente lleva 4 días roto.
```

Esa coletilla no es un adorno. Sin política, lo único que Núcleo tiene para calcular
la frescura es la nota que dejó el último `sync` en tu propio disco, y esa nota la
puede escribir cualquiera con acceso al fichero. Con política, la fecha sale de la
cosignature que se acaba de verificar y la nota ni se lee. En `--json` lo dicen
`freshness.verified` y `freshness.source`; un cron que mire `stale` sin mirar
`verified` se está fiando del disco. El contrato completo de la salida para
máquinas está en [`docs/CLI-JSON.md`](CLI-JSON.md).

Que salga por stderr no es un detalle: una línea de cron con `>> registro.log`
manda stdout al fichero y stderr al correo del administrador. Así la alarma suena
sin que nadie haya tenido que programarla. El umbral se cambia con
`--stale-after 12h`.

Ninguno de ellos **falla** por esto: el bloque se sella, la verificación pasa y
el código de salida sigue siendo 0. Integridad y frescura son preguntas distintas,
y el que falla con código 3 es `sync`, que es el que de verdad no pudo trabajar.

---

## Paso 6 — Emitir un recibo

Un recibo es lo que le entregas a la otra parte. Se verifica **sin ti**: sin tu
servidor, sin tu base de datos y sin pedirte permiso.

```bash
./nucleo --dir ./mi-empresa receipt \
  --block 0 \
  --recipient "María Pérez (cédula 1712345678)" \
  --out ./recibo.txt \
  --policy-file politica.json
```

```
✔ recibo escrito en ./recibo.txt (4962 bytes)

nucleo.org/receipt@v2
destinatario      : María Pérez (cédula 1712345678)  (firmado por el emisor)
emisor (tenant)   : 1790012345001
tipo de registro  : ecuador.sri.factura.v1
hash del contenido: c5b0e7f18d0d1829df5d6895d1fbac063c5e09af3c5276a9a43d461ef1f8754b
bloque            : 0

TIEMPO DECLARADO  : 2026-09-07T10:00:00Z  (declarado por el sistema emisor)
TIEMPO DEMOSTRABLE: 2026-09-07T10:00:00Z  (atestiguado por testigos)

ADVERTENCIA LEGAL
Este recibo es evidencia técnica de integridad y tiempo. No constituye por sí
mismo un acto público, una certificación notarial ni un pronunciamiento de
autoridad. Su valor probatorio lo determina un perito o un juez.
```

**El recibo lleva ahora la firma del bloque, y eso le da a tu cliente algo que
antes no tenía.** En la parte de máquina, después del header canónico, va una línea
con la firma Ed25519 del bloque. Sirve para dos cosas a la vez:

- Es lo que permite recomponer la hoja del árbol de Merkle. Desde la versión
  0.2-draft del protocolo la hoja es `hash ‖ firma`, no solo el hash
  (`PROTOCOL.md` §2.1, regla `leaf/v2`), de modo que una raíz cosignada por un
  testigo también clava las firmas. Antes no: alguien con acceso a tu base podía
  destrozar la columna de firmas y la apertura seguía diciendo "atestiguada".
- Y permite a quien recibe el recibo **comprobar quién lo firmó**. Antes veía
  `signer_pubkey` en el header y no tenía nada con lo que contrastarlo. Ahora lo
  contrasta con el `signerKey` de tu política, y el verificador HTML lo enseña
  como `firma del bloque: ✔ verificada contra la clave del emisor de la política`.

Son dos afirmaciones distintas y hacen falta las dos: la inclusión demuestra que el
log se comprometió con estos bytes; la firma demuestra que tu clave los firmó.

**El destinatario va FIRMADO.** El nombre lo eliges tú al emitir el recibo, y el
emisor firma el documento entero —nombre, los dos tiempos y la advertencia legal—
con la misma clave que firmó el bloque. Reescribir el nombre invalida el recibo: ya
no es una línea que cualquiera con el fichero pueda cambiar.

Lo que esa firma **no** dice, y conviene que lo sepas antes de que alguien te lo
pregunte en una reunión: no demuestra que se lo entregaras a esa persona, y nada te
impide emitir dos recibos del mismo registro para dos destinatarios distintos. Dice
quién produjo ESTE documento para ESTE destinatario con ESTE texto. Por eso la
etiqueta es `(firmado por el emisor)` y no "entregado a".

**Tu cliente necesita tu política, y eso es a propósito.** Una versión anterior de
esta guía decía que no hacía falta repartir ninguna clave, porque `signer_pubkey`
viaja dentro del header y el header entra en la hoja del árbol que el testigo
cosigna. Es verdad que la raíz clava esa clave; lo que no dice es que sea **la
tuya**. Una auditoría reescribió bloques firmándolos con su propia clave —firmas
coherentes, `signer_pubkey` apuntando a ella— y todo cuadraba. Lo único que distingue
tu clave de la de otro es que alguien de fuera sepa cuál es la tuya.

Por eso `signerKey` es obligatorio en la política con la que se verifica un recibo
(ADR-017), y un recibo cuyo `signer_pubkey` no coincida se rechaza. La buena noticia
es que no hay nada nuevo que repartir: es el mismo `politica.json` que ya usas tú,
y se entrega una vez, igual que un certificado.

> **Ojo, esto cambia el comando.** `receipt` ahora te pide la passphrase, porque la
> clave con la que firma vive cifrada en el vault. Antes solo leía. En un cron, usa
> `--passphrase-file`.

**La advertencia legal va dentro del recibo y no se puede quitar.** Está en el
texto que el verificador vuelve a componer para compararlo byte a byte: un
recibo al que le borren esas cuatro líneas deja de verificar. Es deliberado. Lo
que Núcleo demuestra es que un registro existía con unos bytes concretos en un
momento acotado por terceros; no demuestra que lo registrado sea cierto, ni
tiene el efecto de un acto público. Un papel con aspecto técnico invita a esa
lectura, y quien lo reciba merece leer el límite en el mismo papel.

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

Pega el recibo y tu `politica.json` —el que imprimió `sync`—. Es lo que le
entregas al destinatario, una vez, por un canal que no sea el propio recibo:

```json
{
  "origin": "nucleoledger.com/mi-empresa",
  "logKey": "9ad2d5b3d3cc90105737568e1b5850035c181004e46f967da9ba21188818f004",
  "signerKey": "57857f0ed34d9ab44aad8f122f890075bd60ca3bd9142f787cf91b80a4854f2a",
  "witnesses": {
    "witness.nucleoledger.com/w1": "dd7e84d010aed28a416e928f50c4c09ac0f94a8f5b346548168bddb61cdb7263"
  },
  "quorum": 1
}
```

Verás **✔ Recibo válido**, los dos relojes etiquetados y, debajo, el detalle:

```
bloque                  0
destinatario            María Pérez (cédula 1712345678)  (firmado por el emisor)
firma del recibo        ✔ verificada — el destinatario y el texto están firmados
firma del bloque        ✔ verificada contra la clave del emisor de la política
log                     nucleoledger.com/mi-empresa
testigos que verifican  witness.nucleoledger.com/w1
firmas ignoradas        nucleoledger.com/mi-empresa (claves que no conoces)
```

La última fila no es un error. `nucleoledger.com/mi-empresa` es tu propio log, que
firma su checkpoint dos veces: con Ed25519, que es la que el verificador comprueba,
y con ML-DSA-44 en una extensión que los verificadores C2SP ignoran por diseño
(ADR-007). Esa segunda firma es la que aparece como ignorada.

Si alguien retoca una sola letra del texto visible del recibo —el nombre del
destinatario incluido—, verás ✘ y la razón, y **ninguna** fila del detalle quedará
con un ✔ a secas: lo que solo es cierto localmente se marca como tal. Y si a la
política le falta `signerKey`, el verificador no adivina:

```
✘ Recibo NO válido
  la política no se pudo leer: falta signerKey: la clave del firmante de bloques tiene que venir en la política (ADR-017)
```

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
./nucleo --dir ./mi-empresa reconcile --source ./vivo.jsonl \
  --policy-file politica.json
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
      hash sellado   : c5b0e7f18d0d1829df5d6895d1fbac063c5e09af3c5276a9a43d461ef1f8754b
      hash actual    : dd0e6e3697fa2ca96e619ed42c729a750884870feee7eab20e45e7ae9165969f

  Núcleo no impidió estos cambios: la base operativa no es suya. Lo que
  hace es recordar qué decía cada registro cuando se selló, y desde
  cuándo. La alteración deja de ser invisible.

firmante  : ✔ verificado contra la política
estado    : ✔ historia atestiguada hasta 1 de 1 bloques
frescura  : ✔ atestación verificada de hace 0 segundos, por witness.nucleoledger.com/w1
```

Y el código de salida es **2**, así que un cron lo detecta sin leer la prosa:

```bash
./nucleo --dir ./mi-empresa reconcile --source ./vivo.jsonl \
  --policy-file politica.json --json || alertar
```

`reconcile` también avisa de lo que **falta** —registros sellados que tu sistema
ya no tiene— y de lo que **sobra** —registros vivos que nunca se sellaron—.

Las tres últimas líneas no sobran. Que el sistema vivo coincida con lo sellado solo
consuela si lo sellado está completo, y eso lo dicen el firmante, la atestación y la
frescura. Por eso `reconcile` las imprime, y en `--json` van con los mismos nombres
que en `status`.

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
| `falta signerKey` | la política es anterior a ADR-017: vuelve a copiar la que imprime `sync` |
| `firmante : ◐ NO verificada` | abres sin política, o con banderas sueltas sin `--signer-key`: usa `--policy-file` |
| `frescura : ◐ registro local … NO verificado` | abres sin política: la fecha sale de tu propio disco, no del testigo |
| `la clave del log de la política no coincide` | esa política es de **otro** ledger, o alguien sustituyó la clave en este: investígalo |
| `--policy-file no se combina` | pasaste el fichero y banderas sueltas a la vez: elige uno |

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
