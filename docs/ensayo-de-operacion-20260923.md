# Ensayo de operación — 2026-09-23

Esto no es una auditoría de código. Es un despliegue montado como lo tendría una pyme y
**operado**: sellar todos los días, sincronizar cada hora, verificar los domingos,
romperlo de las formas en que se rompen las cosas de verdad, y anotar dónde se porta mal,
confunde o asusta.

**Binario**: el de producción (`go build ./cmd/nucleo`, sin `testhooks`). La única
excepción es el escenario 7, el del reloj, que necesita mover la hora y usa el binario de
pruebas: se dice donde toca.

**Método**: el camino documentado. Se siguió `docs/TUTORIAL-es.md` —incluidos sus
comandos tal como están escritos— y las recetas que el propio programa imprime. Dos de
los hallazgos salieron precisamente de copiar lo que el programa decía que copiara.

**Compresión del tiempo**: donde hacía falta esperar días se bajó el umbral en vez de
falsear el reloj (`--stale-after 10s`), que es una bandera de producción y recorre el
mismo código. Un mes de facturación son 1.200 sellados y 720 sincronizaciones reales.

---

## Resumen

| # | escenario | veredicto |
|---|---|---|
| 1 | un mes de operación comprimido | **funciona**; crecimiento lineal y previsible, cero fallos en 1.200 sellados |
| 2 | el cron roto tres días | **funciona**; el aviso es accionable. Un ✔ de más y un plural |
| 3 | el testigo caído, lento, 404, 500, basura, a medias | **funciona** el código de salida; **el mensaje no servía** |
| 4 | restaurar un respaldo de hace una semana | **funciona** la detección; **la alarma se olvidaba** |
| 5 | disco lleno, permisos, base bloqueada, passphrase mala | **rompía**: tres averías distintas, un solo mensaje mudo |
| 6 | dos workers del ERP sellando a la vez | **rompía**: un tercio de los sellados se perdía |
| 7 | el reloj salta atrás y adelante | **rompía**: un salto dejaba el ledger sin poder sellar, sin explicarlo |
| 8 | un recibo archivado, verificado "un año después" | **funciona**, sin testigo, sin emisor y sin red |

Todo lo que rompía está arreglado en este mismo sprint, con su regresión. Lo que
funcionaba se deja escrito para que la próxima vez se sepa qué medir.

---

## 1. Un mes de operación comprimido

30 «días», 40 facturas al día, una sincronización por hora, `verify --full` los domingos.
Todo con la política puesta, que es lo que el propio `sync` recomienda para el cron.

```
día  bloques  db        seal   sync   status  verify --full  checkpoints  log_state
1    41       92 KiB    94 ms  91 ms   8 ms                  2            3
7    281      364 KiB   98 ms  104 ms  10 ms  36 ms          8            3
14   561      676 KiB   150 ms 142 ms  14 ms  76 ms          15           3
21   841      984 KiB   105 ms 115 ms  16 ms  88 ms          22           3
30   1201     1.376 KiB 113 ms 124 ms  18 ms  (117 ms el 28) 31           3
```

**Qué crece.** El fichero, y de forma lineal: **1.173 bytes por bloque**, blob cifrado
incluido. Un año de esa facturación son unos 17 MiB. Los `checkpoints` crecen con los
días y no con las sincronizaciones: **720 syncs dejaron 31 filas**, porque la tabla está
indexada por tamaño de árbol y re-sincronizar sin bloques nuevos no añade nada.
`log_state` se queda en 3 filas para siempre.

**Qué se degrada.** `verify --full` es lineal —unos 0,1 ms por bloque— y eso es
esperable: recomputa todas las firmas. Lo importante es que el resto **no** se degrada:
`seal` se mueve entre 94 y 150 ms porque lo que domina es Argon2id al abrir el vault, no
el tamaño del ledger, y `status` sube de 8 a 18 ms en 1.200 bloques.

**Ruido.** Cero. En 1.200 sellados y 720 sincronizaciones con la política puesta no salió
un solo aviso ni un solo error. Importa tanto como el rendimiento: una herramienta que
avisa cuando no pasa nada enseña a ignorar sus avisos.

**Recibo** del bloque 1.000: 5.453 bytes, emitido en 0,2 s.

---

## 2. El cron se rompe tres días y vuelve

Secuencia: sincronizar, romper el cron, seguir sellando 40 facturas al día tres días,
mirar, y volver a sincronizar.

Lo que ve el operador en cada sellado, por stderr —también con `--json`—:

```
AVISO: la última atestación es de hace 3 días (umbral: 3 días).
       witness.nucleoledger.com/w1 la firmó el …, cubriendo 1201 bloques. Desde entonces, lo
       que respalda esta historia es solo este disco.
       Si hay un `nucleo sync` en el cron, probablemente lleva 3 días roto.
```

Es accionable: dice quién, cuándo, cuántos bloques y qué mirar. Y la vuelta también:

```
✔ atestación obtenida … (extensión de 1201 a 1322, con prueba de consistencia)
```

**Lo que confundía.** `status` decía `estado: ✔ historia atestiguada hasta 1201 de 1321
bloques`. Un operador lee el ✔; los 120 bloques de esos tres días no los respaldaba nadie
más que el disco. Y en `--json`, `attested` seguía siendo `true`, que es justo el campo
que mira un monitor. → **Arreglado**: `◐` con los bloques que faltan, y `attested_head`
en el JSON. Más el plural de «hace 1 minutos».

---

## 3. El testigo no responde

Nueve formas de portarse mal: nadie escuchando, host inexistente, URL sin `http://`,
`404`, `500`, 200 con basura, la conexión cortada a la mitad, el que acepta y calla, y el
que tarda dos minutos.

**Lo que funcionaba**: las nueve terminaron con **código 3** —incidente operativo— y el
ledger quedó utilizable en todas (`status` con 0 después). El que no contesta **no cuelga
un cron**: hay un tiempo de espera de 30 s por petición, ajustable con `--timeout`.

**Lo que no servía**: el mensaje.

```
error: witness: checkpoint de "nucleoledger.com/mi-empresa": Get "http://127.0.0.1:18999/
c65397b04d875cc205ed905c64c7dddf5a29d9505d799f168825499c37b1aab1/checkpoint": dial tcp
127.0.0.1:18999: connect: connection refused
```

Un hash de 64 caracteres, la forma de un error de la biblioteca de red de Go, y ni una
palabra sobre qué mirar. Y el peor de los nueve era **el typo más común**: olvidar el
`http://` contestaba `first path segment in URL cannot contain colon` **y salía con 3**,
como si el testigo tuviera la culpa de una errata nuestra —y un cron que reintenta ante
el 3 reintentaría para siempre una URL que nunca va a funcionar—.

→ **Arreglado**: cada clase con su frase y su consejo, el detalle técnico debajo, y la
URL validada antes de tocar la red como error de uso (código 1).

---

## 4. Restaurar un respaldo de hace una semana

El escenario que la auditoría del 13-sep marcó como no cubierto. Secuencia: copiar el
fichero (lo que hace un sysadmin con rsync), seguir una semana en el ledger vivo —100
facturas y su sincronización—, perder el disco y restaurar la copia.

**Lo que funcionó, y es lo importante**: el testigo no se deja.

```
✘ ROLLBACK LOCAL DETECTADO
    en disco          : 1322 bloques
    el testigo cosignó: 1422 bloques
    faltan            : 100 bloques
[exit 2]
```

Y volver a poner el ledger bueno lo resuelve: la siguiente sincronización sale en verde
sin dejar rastro en el testigo.

**Lo que asustaba de verdad**: `status` y `verify --full` sobre el respaldo restaurado
decían

```
estado    : ✔ historia atestiguada hasta 1322 de 1322 bloques
frescura  : ✔ atestación verificada de hace 4 minutos
[exit 0]
```

El primer sitio donde mira quien acaba de restaurar decía que todo estaba bien. La única
alarma vivía en la salida de un cron que nadie lee, y el sellado seguía tan campante,
apartándose un bloque más de la historia atestiguada en cada factura.

→ **Arreglado**: la constancia se guarda en el ledger; `status` y `seal` lo dicen en cada
invocación, `verify` sale con 2 mientras conste, y solo una sincronización que vuelva a
cuadrar la borra.

---

## 5. Averías del entorno

| avería | antes | ahora |
|---|---|---|
| ledger en solo lectura | `error interno de la base de datos` | qué fichero, qué permisos, y los dos sidecar que nadie adivina |
| directorio en solo lectura | `error interno de la base de datos` | idem |
| base tomada por otro proceso | `error interno de la base de datos` | «otro proceso lo tiene tomado; el registro NO se escribió. Reintenta» |
| fichero que no es un ledger | (no probado antes) | «no es un ledger de Núcleo, o está dañado» |
| passphrase equivocada ×3 | `chacha20poly1305: message authentication failed` | «la passphrase no es la de este vault», con qué mirar y `nucleo restore` |
| fichero de passphrase sin permisos | ya era claro | igual |
| límite de tamaño de fichero (`ulimit -f`) | el proceso muere por SIGXFSZ | igual: nada que el programa pueda decir, y **el ledger queda íntegro** |

**El que dejó el despliegue inservible.** SQLite crea `nucleo.db-wal` y `nucleo.db-shm`
junto a la base y **heredan sus permisos**. Un `chmod` sobre la base deja el `-shm` en
444 aunque la base vuelva a 644, y desde ese momento cada sellado falla con «error interno
de la base de datos». La cura es `chmod 644 nucleo.db-shm` y no aparecía en ninguna
parte: tardé en encontrarla teniendo el código delante.

**Lo que aguantó**: tras el SIGXFSZ, los bloqueos y los permisos, `verify --full` pasó en
verde. La transacción única de ADR-020 §C hizo su trabajo: nada quedó a medias.

---

## 6. Dos workers del ERP sellando a la vez

Dos procesos, 30 sellados cada uno, contra el mismo ledger.

```
antes:  worker A: 21 de 30 · worker B: 20 de 30   → 19 de 60 PERDIDOS
        "la base está ocupada por otro proceso"  y  "índice fuera de secuencia"
ahora:  worker A: 30 de 30 · worker B: 30 de 30   → 60 de 60
```

**Lo que nunca se rompió**: la integridad. Ni antes ni después hubo huecos ni índices
repetidos ni blobs duplicados, y `verify --full` pasó siempre. Y la clave de idempotencia
aguanta la concurrencia: cinco pares de reintentos simultáneos con la misma clave dejaron
**un** bloque, y los nueve reintentos restantes contestaron `idempotent: true` con el
mismo índice.

La causa eran dos y están explicadas en el commit: el BUSY inmediato de SQLite en WAL
—que `busy_timeout` no reintenta— y el bloque firmado fuera de la transacción, que deja
de encadenar cuando otro proceso confirma en medio. → **Arreglado** con transacciones en
modo `immediate` y un reintento acotado.

---

## 7. El reloj salta

Único escenario con el binario de pruebas: mover la hora necesita el gancho
`NUCLEO_TEST_CLOCK`, que el binario de producción rechaza —y hace bien—. El código que se
recorre es el mismo.

**Hacia atrás** (NTP mal, una VM restaurada): el sellado se niega, y hace bien. Pero
decía `error: ledger: timestamp anterior al del bloque previo`. Exacto y mudo.

**Hacia delante**: el sellado **funciona**… y deja un bloque con fecha futura que impide
sellar hasta que el reloj la alcance. Un salto de un año dejó el ledger sin poder sellar
durante un año, explicado con el mismo mensaje mudo. Es el hallazgo más caro del ensayo:
un fallo de NTP de un minuto deja a una pyme sin poder facturar, y nada se lo advierte.

→ **Arreglado**: el reloj atrasado se explica con las dos horas, NTP y qué pasa si el raro
es el bloque; y un salto hacia delante de más de un día **avisa antes de escribir**,
cuando todavía se puede parar.

**Lo que funcionó bien**: el aviso de reloj descolocado cuando la atestación parece del
futuro («uno de los dos relojes está mal puesto… la comprobación de frescura no significa
nada») y el aviso de replay, que salta solo con el reloj adelantado porque la cosignature
parece vieja.

---

## 8. Un recibo archivado, verificado «un año después»

Se emitió el recibo del bloque 1.000, se archivó, **se apagó el testigo** y se verificó
con la política guardada, en dos verificadores independientes y sin red:

```
SDK de PHP        valid: true  | bloque 1000 | declarado …T05:14:19Z | demostrable …T05:21:08Z
bundle de la web  valid: true  | los mismos valores, los mismos testigos
```

La verificación **no mira el reloj** en ninguna implementación, así que «un año después»
no cambia nada, y eso es exactamente la respuesta correcta: un recibo no caduca, y lo que
afirma —qué se selló, cuándo lo vio un tercero, quién lo firmó— no depende de que el
emisor, el testigo o la red sigan existiendo. Es la promesa del producto y se sostiene.

---

## Hallazgos y dónde se arreglaron

| # | qué | gravedad | arreglo |
|---|---|---|---|
| 1 | tres averías distintas con un solo mensaje mudo; el `-shm` dejaba el despliegue inservible | **alta** (operación) | `9314b8a` |
| 2 | dos workers perdían un tercio de los sellados | **alta** | `5da9448` |
| 3 | un salto de reloj dejaba el ledger sin poder sellar, sin explicarlo | **alta** | `5da9448` |
| 4 | el rollback detectado se olvidaba; `status` decía ✔ | **alta** | `cf41c89` |
| 5 | los nueve fallos del testigo en jerga de Go; el typo de URL como incidente | media | `c0e96c3` |
| 6 | la passphrase equivocada en jerga de criptografía | media | `9c11a4c` |
| 7 | ✔ con la cabeza sin atestiguar, y `attested` engañoso para un monitor | media | `9c11a4c` |
| 8 | `sync` imprimía una receta de cron que falla en un cron | media | `9c11a4c` |
| 9 | «hace 1 minutos» | baja | `9c11a4c` |

## Lo que queda anotado y no se tocó

- **`ulimit -f` mata el proceso con SIGXFSZ** y ahí no hay mensaje posible: el programa no
  llega a enterarse. Un disco lleno de verdad (ENOSPC) sí devuelve error y ahora se dice
  con su nombre, pero no se pudo provocar en esta máquina sin montar un sistema de
  ficheros, así que la clase `ErrDiskFull` está probada por su código y no por una
  ejecución.
- **El aviso de sincronización sin bloques nuevos** dice lo mismo que el primero
  («✔ atestación obtenida»), sin distinguir «no había nada que hacer». Para un cron da
  igual; para quien lo ejecuta a mano, es una línea que no informa.
- **Las cifras de `age_hours` y `threshold_hours`** salen con toda la cola decimal
  (`0.0320357455975`). Es correcto y comparable; queda feo en un panel.
- **El ledger restaurado sigue sellando** con el rollback registrado. Se avisa en cada
  bloque, no se prohíbe: prohibirlo sería decidir por el operador en un caso donde puede
  tener razones. Si algún día se quiere una negativa, tendría que ser explícita y con
  bandera para saltarla.
