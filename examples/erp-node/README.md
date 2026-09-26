# ERP de ejemplo, en Node.js

Un ERP mínimo pero realista —factura, sella, entrega recibos, reconcilia— para que puedas
ver en una tarde, y sin leerte el protocolo, **cómo integra un sistema propio con Núcleo**.

No reimplementa nada: el sellado invoca el binario `nucleo` y la verificación usa
`@nucleoledger/verify`. Cada pantalla enseña el comando que ejecutó y la respuesta que
recibió, porque lo que vienes a ver es eso y no el ERP.

```
examples/erp-node/
├── bin/setup.js       deja el despliegue listo: binario, ledger, política
├── bin/testigo.js     un testigo local (en producción es de un tercero)
├── bin/demo.js        el recorrido completo sin navegador. Es lo que corre el CI
├── bin/cron.js        la receta de cron: sync cada hora, verify --full los domingos
├── src/nucleo.js      EL ENVOLTORIO DEL BINARIO. Empieza por aquí
├── src/contrato.js    lector estricto de la salida --json (ADR-025)
├── src/erp.js         las facturas: qué se sella y con qué clave de idempotencia
├── src/servidor.js    las cinco pantallas, con su manejo de errores
└── src/paginas.js     el HTML, sin dependencias
```

## Arranque

Necesitas **Node ≥ 20**, **Go 1.27+** (para compilar el binario; si tienes un release
firmado, apunta `NUCLEO_BIN` a él) y nada más: ni Docker, ni base de datos, ni cuentas.

```bash
# desde la raíz del repositorio
go build -o nucleo ./cmd/nucleo

cd examples/erp-node
npm run setup     # ~30 s: instala el verificador de npm, crea el ledger y la política
npm run demo      # ~10 s: el recorrido completo, con comprobaciones
```

Y si quieres verlo en el navegador:

```bash
npm run testigo   # en otra terminal
npm start         # http://127.0.0.1:3000
```

`npm run demo` monta su propio despliegue en `datos/demo/`, así que puedes repetirlo sin
tocar el del navegador. Todo lo que crea el ejemplo vive en `datos/`, que está en
`.gitignore`: **la passphrase y las tarjetas de respaldo que genera son de juguete** y
están ahí para que esto sea reproducible, no para copiarlas a ningún sitio.

## Qué mirar en cada paso

### 1. Sellar una factura al emitirla

`src/erp.js`, método `emite`. Tres cosas que no son adorno:

- **El documento que se sella lleva un `nonce` de 16 bytes aleatorios.** Una factura es
  un documento de baja entropía —cliente, fecha, importe— y su `payload_hash` viaja en
  cada recibo. Sin entropía dentro, ese hash confirma conjeturas: se prueban importes
  hasta que uno encaja (ADR-023 §C).
- **La clave de idempotencia es el número de factura**, no un UUID nuevo por intento. Si
  el reintento no repite la clave, no sirve de nada: duplicará el registro (ADR-020 §D).
- **El orden es reservar número → sellar → marcar emitida.** Si el sellado falla, la
  factura queda pendiente con su número, y el botón *Reintentar* usa la misma clave: o
  entra, o descubre que ya estaba sellada.

En la pantalla de la factura verás el comando entero, y la respuesta con `index`,
`payload_hash` e `idempotent`.

### 2. El cron

`bin/cron.js`, y la receta que imprime la pantalla *Estado del ledger*:

```cron
0 * * * * cd /ruta/al/ejemplo && node bin/cron.js sync     >> datos/cron.log 2>&1
0 3 * * 0 cd /ruta/al/ejemplo && node bin/cron.js semanal  >> datos/cron.log 2>&1
```

- `sync` **firma** un checkpoint: necesita la passphrase por fichero. `status` no firma y
  no la necesita. Un cron que la pidiera por terminal se colgaría para siempre.
- Los avisos de frescura y de rollback salen por **stderr**, también con `--json`. En un
  cron eso va al correo, y es la única alarma que hay: no los redirijas a stdout.
- El código de salida se propaga tal cual: `0` bien, `2` integridad, `3` el testigo no
  contestó. Un cron que siempre sale `0` no se puede vigilar.

### 3. El recibo del cliente

Un recibo lleva dentro el header del bloque, la prueba de inclusión y el checkpoint
cosignado por los testigos. Con eso se verifica **sin llamar a nadie**: ni al ledger, ni
al testigo, ni a internet.

Por eso el orden correcto es **sellar → sincronizar → emitir el recibo**: no existe el
recibo de un bloque que ningún testigo ha cubierto todavía. El ERP lo hace por ti (mira
la ruta `/factura/:n/recibo` en `src/servidor.js`) en vez de enseñarte un error que no te
toca resolver.

### 4. Verificar un recibo pegado

La pantalla *Verificar un recibo* usa `@nucleoledger/verify` contra `datos/politica.json`,
en el mismo proceso y sin red. Pégale un recibo, cámbiale un carácter y vuelve a
verificar: dirá qué firma dejó de cuadrar.

**La política es lo único en lo que se confía**: el origin del log, la clave del emisor y
los testigos aceptados con su clave. Todo lo demás se comprueba contra ella. Quien recibe
un recibo tuyo necesita tu política, y eso es a propósito.

### 5. Reconciliar, y ver una alteración

Entra en una factura, pulsa *Alterar el importe* y vuelve a *Reconciliar*. El ERP exporta
lo que dice **hoy** —una línea por factura, con el índice del bloque y el contenido en
base64— y Núcleo lo compara con lo que se selló:

```
✘ HAY REGISTROS QUE NO CUADRAN
  discrepancia en el bloque 0
    sellado: bc9716a8…   hoy: 9f59128d…
```

Núcleo no puede impedir que alguien edite la base del ERP: no es suya. Lo que hace es
recordar qué decía el registro cuando se selló. Y el recibo que ya entregaste sigue
verificando: no depende del ERP.

Ese cotejo sale con **código 2**, y eso no es un fallo del programa: encontrar una
discrepancia es su trabajo. Por eso `src/nucleo.js` lee el informe en las dos ramas.

### 6. La alarma de frescura, y quién se entera

Si el testigo deja de contestar, la atestación envejece. Núcleo **sigue sellando** —un
registro que no se sella se pierde; una atestación atrasada se recupera en el siguiente
`sync`— y abre una **alarma** que guarda en el propio ledger
([ADR-028](../../docs/adr/ADR-028-alarma-de-frescura-durable.md)). No depende de stderr,
que en un hosting real no lee nadie: viaja en el JSON de cada comando.

El envoltorio llama a **`onStale`** en cada operación mientras la alarma esté abierta y
sin reconocer (`src/config.js`: en el ejemplo apunta la alarma y la enseña en el panel;
en tu ERP, ahí va tu correo o tu WhatsApp). Deja de llamarse cuando alguien la reconoce
—el botón de la pantalla de estado, o `reconoceAlarma()`— y la alarma se cierra sola con
el próximo `sync` bueno. **Configurar `onStale` es un requisito de integración**, no un
extra.

Para verla sin esperar tres días: `NUCLEO_STALE_AFTER=30s npm start` con el testigo
parado, emite una factura y espera medio minuto. La demo lo recorre en su paso 9.

## Manejo de errores

Lo que el ejemplo hace en cada caso, porque un ERP que sella y no sabe qué hacer cuando
el sellado falla no es una integración:

| Qué pasa | Qué recibe el ERP | Qué hace |
|---|---|---|
| Falta el binario, o no se puede ejecutar | `ErrorDeEntorno` | No emite nada. El arreglo está en el despliegue, no en el código |
| El sellado no contesta en el plazo | `ErrorDeEntorno` (timeout) | Deja la factura pendiente y reintenta **con la misma clave**: el registro pudo escribirse |
| El testigo no responde | `ErrorDeSincronizacion`, código 3 | Sigue sellando. No se ha perdido nada; falta el tercero que dé fe de la fecha |
| El cotejo encuentra una discrepancia | código 2 con el informe completo | Enseña el informe. No reintenta: un 2 es un incidente |
| La salida no encaja con el contrato | `ErrorDeContrato` | Se detiene. No rellena con valores por omisión: así es como una salida truncada parece un sellado correcto |
| La atestación lleva vieja más que el umbral | `alert.state: "open"` en el JSON, y `onStale` | Sigue sellando y avisa por tu canal hasta que alguien la reconoce. Con `fallaSiVieja`, no sella y lanza `ErrorDeSincronizacion` transitorio |
| Se pide el recibo de un bloque que ningún testigo cubrió | código 1 con `error_class: transient` | Sincroniza y reintenta. **No** es un error de la llamada, y el ERP lo sabe sin leer el mensaje ([ADR-027](../../docs/adr/ADR-027-clase-del-error-en-json.md)) |

Cada rama tiene su página, y las tres contestan lo mismo: qué pasó, **qué hizo el ERP con
mi factura** y qué hacer ahora.

## Decisiones, y de dónde salen

- **Vive en este repositorio**, en `examples/`, y no en uno aparte: así su CI se rompe en
  el mismo commit que rompa el contrato `--json`, el formato del recibo o un código de
  salida. Eso es el objetivo, no un efecto colateral. Está razonado en
  [ADR-026](../../docs/adr/ADR-026-ejemplo-de-integracion.md).
- **Usa el verificador publicado en npm**, `@nucleoledger/verify@0.2.0-alpha.0`, fijado
  por versión exacta y por hash en `package-lock.json`: lo mismo que instalarías en tu
  proyecto. Tiene procedencia —lo construyó `publish-npm.yml` de este repositorio— y lo
  puedes comprobar con `npm audit signatures`, que el CI también ejecuta. Hasta el 25 de
  septiembre de 2026 el ejemplo tenía que usar el SDK del repositorio, porque la versión
  publicada entonces (0.1.0-alpha.0) era anterior al recibo `@v2`; la deuda y su cierre
  están en ADR-026.
- **El envoltorio está escrito desde `docs/CLI-JSON.md`**, no traducido del de PHP: es el
  segundo consumidor independiente del contrato de ADR-025. Cuatro fricciones salieron de
  escribirlo así, y están en el informe del sprint; tres se arreglaron en el mismo.
- **La clase del error se lee, y no el texto del mensaje.** Cada objeto de error trae
  `error_class` —`usage`, `transient`, `environment` o `integrity`— y eso es lo que
  decide qué hace el ERP: reintentar, avisar a quien opera o abrir un incidente. Es
  [ADR-027](../../docs/adr/ADR-027-clase-del-error-en-json.md), y salió de que este
  ejemplo no podía distinguir "has llamado mal" de "todavía no" sin leer español.

## Si tu copia está en /mnt/c (WSL) o en un recurso compartido

Verás dos cosas, y las dos son correctas:

- un aviso de que la política tiene permisos `0777` y que el directorio **no guarda
  permisos POSIX**: ahí `chmod` contesta que sí y no cambia nada. El ejemplo funciona
  igual; para un despliegue de verdad, tenlo en un sistema de ficheros que los guarde.
- que la memoria del testigo se va a un directorio temporal: Núcleo se niega —con razón—
  a servir un testigo cuya clave privada se reporta legible por otros usuarios.

## Licencia

AGPL-3.0-or-later, como el resto del repositorio.
