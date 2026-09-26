# ADR-028-alarma-de-frescura-durable

**Estado:** ACEPTADA el 2026-09-26 por el dev (Sprint 12) · **Fecha:** 2026-09-26 · **Fuentes:** política *fail-stale* del Sprint 7 (`cmd/nucleo/stale.go`), ensayo de operación del Sprint 10 (`docs/ensayo-de-operacion-20260923.md`, escenarios 2 y 3), ADR-009 y su enmienda (`log_state` mutable por diseño), ADR-025 y ADR-027 (la salida `--json` y la clase del error), `store.RollbackKey` como precedente

## El problema

Desde el Sprint 7, una atestación vieja es «un incidente que se anuncia solo»: `seal`,
`status`, `verify` y `reconcile` escriben un AVISO por **stderr**, también con `--json`,
con el argumento de que «un cron con stdout a un fichero y stderr al correo del
administrador hace sonar la alarma sin programar nada».

Ese argumento supone un cron que alguien configuró bien. En el hosting donde vive el
mercado de este producto, la línea de cron típica es

```
*/10 * * * * php /home/cuenta/erp/cron.php > /dev/null 2>&1
```

y el ERP invoca `seal` desde PHP con `proc_open`, recoge stdout para parsear el JSON y
tira stderr —o lo escribe en un log que nadie abre—. En ese despliegue, que es el normal,
la alarma **no la lee nadie**: suena en un sitio donde no hay nadie escuchando, y el día
que el testigo lleva una semana caído no se entera ni el integrador ni su cliente.

Y el remedio obvio —que `seal` falle cuando la atestación está vieja— es peor que la
enfermedad. Un registro que no se sella **se pierde**: la factura se emitió igual, y lo
que falta es la prueba de que existía a esa hora, que no se puede fabricar después. Una
atestación atrasada, en cambio, **se recupera sola** en el siguiente `sync` que salga
bien: el testigo cosigna la raíz que cubre todo lo sellado mientras tanto.

## Decisión

### A. `seal` sella SIEMPRE por defecto

La frescura nunca impide sellar sin que el integrador lo pida. Es lo que ya hacía `seal`,
y ahora es una decisión escrita y no un efecto de cómo quedó el código.

### B. `--fail-on-stale`, para quien tiene cola

`seal --fail-on-stale` **no escribe el bloque** si la atestación está vieja y sale con
código **3** (`error_class: transient`, ADR-027): quien tiene una cola de trabajos y puede
reintentar después de un `sync` prefiere no acumular historia sin atestiguar. Es opcional
y está desactivado por omisión, por lo dicho en §A.

Un reintento idempotente con una clave ya sellada contesta lo del primer sellado aunque
la atestación esté vieja: no escribe nada, así que no hay nada que rechazar.

### C. La alarma se guarda en el ledger, y dura lo que dura el problema

Cada vez que `seal`, `status`, `verify`, `reconcile` o `sync` evalúan la frescura, dejan
el resultado en `log_state` bajo `log/stale-alarm/v1`:

| campo | qué es |
|---|---|
| `stale_since` | desde cuándo está vieja: el instante de la última atestación más el umbral; si no hubo ninguna que cuente, el momento en que se observó por primera vez |
| `alert_emitted_at` | cuándo la registró Núcleo por primera vez |
| `alert_acked_at` | cuándo alguien dijo «me he enterado» con `nucleo alert ack`, o nada |
| `acked_by` | quién, si lo dijo |
| `threshold_hours`, `reason` | con qué umbral se juzgó y por qué: `age`, `never_attested` o `no_attestation_under_policy` |

El ciclo es corto y no tiene más estados que estos:

- **se abre** la primera vez que un comando observa la atestación vieja;
- **se reconoce** con `nucleo alert ack [--by NOMBRE]`, que no la cierra: dice que alguien
  se ha enterado;
- **se cierra sola** cuando un comando vuelve a observar la atestación fresca —en la
  práctica, tras un `sync` que sale bien—. El registro se borra, y el siguiente episodio
  abre una alarma nueva, sin reconocer.

`sync` evalúa la frescura también **cuando falla**, porque es justo ahí donde se produce:
el testigo no contesta y el cron no lo lee nadie.

`nucleo alert status` enseña la alarma; con `--exit-code`, sale con **3** si hay una
alarma abierta sin reconocer, para quien vigila desde un script sin parsear JSON.

### D. Toda salida `--json` lleva el objeto `alert`

`seal`, `status`, `verify`, `reconcile`, `sync` y `alert status` publican
`"alert": {"state": "none"|"open"|"acked", …}` con los campos de §C más `new` —true solo en
el comando que la abrió— y `persisted` —false si no se pudo escribir en el ledger, que es
lo único que un integrador necesita saber para no fiarse de la durabilidad—. También el
objeto de error de un `sync` que falla o de un `seal --fail-on-stale` que se niega lleva
`alert`: son los dos momentos en que más importa. Es un campo **añadido**; se lee como
opcional (ADR-025 §A, ADR-027 §C).

### E. El hook: el integrador elige el canal, Núcleo garantiza que se entera

El SDK de PHP (`Sealer`) y el envoltorio del ejemplo Node aceptan un **`onStale`** que se
llama en cada operación mientras haya una alarma **abierta y sin reconocer**, con el
objeto `alert`. Por correo, por WhatsApp o por lo que sea: esa elección es del
integrador, y el producto no la hace por él.

La garantía es **al menos una vez**: el hook se repite hasta que alguien ejecuta
`alert ack`, y ahí para. Un hook que se llamara solo la primera vez perdería el aviso el
día que el correo estuviera caído. Configurar `onStale` es un **requisito de
integración**, documentado como tal en `docs/OPERACION.md`: sin él, Núcleo registra la
alarma, pero la persona que tiene que actuar no se entera.

## Lo que NO se hace

- **La alarma no es un control de seguridad.** Vive en `log_state`, que ADR-009 declaró
  mutable: quien pueda escribir el fichero puede borrarla o reconocerla. Lo que no puede
  es hacer que mienta sobre el presente, porque se recalcula en cada comando a partir del
  veredicto de frescura —con política, el de la cosignature verificada—: si se borra
  mientras la atestación sigue vieja, el siguiente comando la vuelve a abrir. El control
  de seguridad sigue siendo la memoria del testigo y la política.
- **`stderr` no se calla.** El aviso sigue saliendo como hasta ahora: no cuesta nada y hay
  despliegues donde sí se lee. Lo que cambia es que ya no es el único sitio.
- **Núcleo no envía nada.** Ni correos ni mensajes: no tiene credenciales de nadie y no
  opera infraestructura. Registra, expone y llama al hook.
- **Reconocer no silencia el aviso de stderr ni cierra la alarma.** Solo para el hook.

## Consecuencias

- `status` pasa a escribir en `log_state`. Si no puede —un fichero de solo lectura—,
  sigue funcionando: lo dice por stderr y publica `persisted: false`.
- Los vectores válidos de `testdata/vectors/cli-json/` ganan el campo `alert` y se
  regeneran con la CLI de verdad; se añade un inválido con un estado desconocido.
- La alarma sigue el veredicto de cada comando. Con política y sin ella el veredicto
  puede diferir —sin política cuenta el registro local de `sync`—, así que un despliegue
  debe usar la política en TODOS los comandos, como ya pedía ADR-017; la guía de
  operación lo repite.
