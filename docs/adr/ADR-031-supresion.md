# ADR-031-supresion

**Estado:** PROPUESTA el 2026-10-10 (Sprint 17), implementada en el mismo sprint; pendiente de que el dev la acepte · **Fecha:** 2026-10-10 · **Fuentes:** hallazgo 1 de la lista del Sprint 16 (la supresión no tenía comando), CONCEPTO §5 (LOPDP por construcción), PROTOCOL §2 y §5 (header, `payload_cid`, AAD por tenant), ADR-020 §C (una transacción por sellado), ADR-004 (confirmación tecleada), ADR-009 y su enmienda (tablas mutables), `docs/GARANTIAS.md` L7

## El problema

El concepto promete cumplir la LOPDP **por construcción**: el dato personal vive cifrado
fuera de la cadena, la cadena guarda su hash, y borrar el dato no rompe nada. La pieza
existía —`internal/vault/erase.go#EraseBlob`, que llama a `internal/store/blobs.go#Store.DeleteBlob`—
pero **nadie la llamaba**: no había comando. Un integrador que recibía una solicitud de
supresión tenía que abrir la base con SQL, que es justo lo que el producto dice que nunca
hace falta.

Y no bastaba con añadir el comando, por cuatro cosas que la función suelta no resolvía:

1. **Borraba solo la copia cifrada.** Los compromisos de los campos sensibles del perfil
   (`commit/v1/<payload_hash>` en `vault_meta`) se quedaban.
2. **No dejaba rastro.** Tras borrar, la reconciliación ve un bloque cuyo registro ya no
   está en el sistema vivo y lo informa como **faltante**: no distingue una supresión
   legítima de un registro que alguien hizo desaparecer. Peor aún: lo que haría
   indistinguible es precisamente lo que Núcleo existe para detectar.
3. **El dato seguía en el disco.** Un `DELETE` de SQLite marca la página como libre y no
   borra sus bytes; y una copia reciente puede seguir en el WAL. El test de este ADR lo
   comprobó: sin cambiar nada, los bytes de los compromisos suprimidos se leían en el
   fichero.
4. **No se confirmaba.** Un dígito mal copiado en el índice suprime el registro de otra
   persona, sin vuelta atrás.

## Decisión

### A. Qué se borra

`nucleo erase --block N` suprime **el contenido** del bloque N:

- la copia cifrada (`blobs`, clave `payload_hash`);
- sus compromisos (`vault_meta`, `commit/v1/<payload_hash>`).

Lo que **no** se borra, ni puede borrarse sin romper la cadena: el bloque, con su
`payload_hash`, su tenant, su tipo y su tiempo declarado. Ningún verificador necesita el
contenido: la firma, la inclusión y el recibo demuestran el hash.

La copia cifrada se guarda por `payload_hash`, así que **es la de todos los bloques que
sellaron ese mismo contenido** (ADR-020 §A). Se suprime la de todos, y el comando los nombra
antes de confirmar y en su salida (`blocks`). Suprimir el contenido de un bloque y dejarlo
en otro sería no haberlo suprimido.

Un bloque sellado con `--no-encrypt` y sin perfil no tiene nada guardado: Núcleo solo tiene
su hash. El comando lo dice y no sella nada; el contenido vive solo en el sistema del
integrador, y es ahí donde se suprime.

### B. Cómo se confirma

Como `init` y `restore` (ADR-004, ADR-029 §B): el comando enseña el hash y los bloques
afectados y pide **teclear los 8 primeros caracteres del hash**. Una confirmación que no
coincide no escribe nada. En `--json` no hay a quién pedírselo, así que hay que pasar
`--assume-confirmed`; sin él, es un error de uso que lo dice. Sin consola —un cron—, el
error de lectura también lo dice.

Pide la passphrase: el evento (§C) se firma con la clave del emisor.

### C. La supresión deja un evento sellado, sin datos personales

En **la misma transacción** que borra (ADR-020 §C: o está todo o no está nada), se sella un
bloque más:

- `type`: `nucleo.erasure.v1`;
- `tenant`: el del bloque suprimido;
- contenido: `{"erased_payload_hash":"<hash>"}` en JCS (RFC 8785), y nada más;
- `payload_cid`: `none://` — el contenido del evento no se guarda, porque se reconstruye a
  partir del hash.

**No lleva el campo aleatorio** que PROTOCOL §5 exige a los payloads que construye Núcleo,
y es a propósito. Esa regla existe para que nadie confirme el contenido de un documento
adivinándolo desde su hash; aquí el contenido es el propio hash suprimido, que ya es público
en la cadena, así que adivinarlo no revela nada. Y el determinismo es lo que hace que el
evento sirva: la reconciliación y un tercero lo encuentran recalculándolo. Con un campo
aleatorio habría que guardar el contenido del evento fuera de la cadena para poder leerlo, y
la reconciliación pasaría a depender de un dato aparte que se puede perder.

No lleva datos personales: el hash suprimido ya estaba en la cadena, en el bloque N. Ni
el índice del bloque, ni un motivo, ni quién lo pidió: el motivo de una supresión puede ser
en sí un dato personal, y su registro corresponde al sistema del integrador.

El vector del contenido está calculado fuera del código, con `sha256sum`
(`internal/erasure/erasure_test.go#TestElEventoDeSupresionCoincideConElVector`).

Los tipos `nucleo.*` quedan **reservados**: `seal --type nucleo.…` es un error de uso. Un
evento sellado a mano haría pasar un registro desaparecido por uno suprimido.

Pedir otra vez la supresión de un contenido ya suprimido no sella otro evento: contesta
`already_erased: true`. Si después de suprimirlo el mismo contenido se vuelve a sellar, esa
copia nueva es un registro nuevo y se puede suprimir a su vez, con un evento nuevo.

### D. El disco

- La base se abre con `PRAGMA secure_delete=ON`: lo borrado se sobrescribe con ceros.
- Tras la transacción, `PRAGMA wal_checkpoint(TRUNCATE)` vacía el WAL
  (`internal/store/store.go#Store.PurgeWAL`). Si otro proceso lo está leyendo, no se puede
  vaciar entero: el comando lo dice (`wal_purged: false`) y repetir la orden lo vuelve a
  intentar sin sellar otro evento.

Test: `internal/store/supresion_test.go#TestLaSupresionNoDejaElContenidoEnElDisco` busca
los bytes en el fichero principal y en el WAL. Sin `secure_delete`, falla.

### E. Qué informa `reconcile`

Un bloque que el sistema vivo ya no tiene y cuyo contenido tiene un evento de supresión
**posterior** a él no es un hallazgo: sale en `erased` —con el bloque del evento y su
tiempo declarado— y la reconciliación termina con 0. Sin evento, sigue siendo `faltante` y
termina con 2.

La reconciliación no abre el vault, y no lo necesita: calcula, para cada bloque que falta,
el `payload_hash` que llevaría su evento, y lo busca entre los bloques de tipo
`nucleo.erasure.v1`. Todo sale del ledger firmado; un marcador fuera de la cadena lo podría
poner cualquiera que escriba el fichero.

Solo cuenta un evento **posterior** al bloque: uno anterior suprimió una copia anterior del
mismo contenido, y el bloque la volvió a sellar después. Los propios eventos tampoco son
«faltantes»: los sella Núcleo, no el sistema vivo.

### F. Cómo lo ven los SDK

**No cambian.** Los verificadores de TypeScript, PHP y web verifican recibos, y un recibo
no depende del contenido: el de un bloque suprimido sigue verificando, el que ya se había
entregado y uno emitido después. El evento es un bloque como cualquier otro, y su recibo
también.

Quien tenga el recibo del evento y el hash del bloque suprimido puede comprobar la
supresión sin Núcleo: reconstruye `{"erased_payload_hash":"<hash>"}`, calcula su SHA-256 y
lo compara con el `payload_hash` del recibo del evento, cuyo tipo es `nucleo.erasure.v1`.
Esa comprobación no está en los SDK; si un integrador la necesita, es una función de diez
líneas y se añade entonces.

El `Sealer` de PHP (ADR-021) no envuelve `erase`. Una supresión es una decisión de una
persona con la passphrase delante, no algo que un ERP lance por su cuenta.

### G. PROTOCOL

El formato del bloque no cambia: el evento usa los ocho campos de siempre. Lo nuevo es una
convención sobre dos de ellos —el tipo reservado y el contenido del evento—, y queda
escrita aquí. Registrarla en PROTOCOL.md, y con qué versión, lo decide el dev al aceptar
este ADR.

## Lo que NO resuelve

- **Las copias de seguridad.** Una copia del ledger hecha antes de suprimir sigue teniendo
  el contenido, cifrado. El comando lo dice; destruirlas es cosa de quien opera. Restaurar
  una copia anterior trae el contenido de vuelta **y** quita el evento: la reconciliación
  vuelve a ver el registro como no suprimido, que es lo que es.
- **El sistema vivo.** Núcleo suprime lo suyo; el registro en la base del integrador lo
  borra el integrador. Si no lo borra, la reconciliación lo da por verificado, que también
  es cierto.
- **El hash.** Sigue en la cadena. Para un contenido de baja entropía, un hash desnudo se
  puede invertir probando (L7); por eso los campos sensibles van como compromisos con
  clave, y esos sí se borran.
- **La DEK.** Todos los contenidos se cifran con la misma DEK, así que no hay borrado
  criptográfico por registro: destruir una clave por contenido exigiría otra jerarquía de
  claves (PROTOCOL §6), y no compensa mientras el contenido se pueda borrar de verdad.

## Consecuencias

- La promesa del concepto tiene comando, test y evento: `cmd/nucleo/erase_test.go#TestLaSupresionDejaLaCadenaYLosRecibos`
  comprueba que, tras suprimir, `verify --full` pasa, el recibo entregado antes verifica,
  se emiten recibos nuevos del bloque y del evento, y `reconcile` informa la supresión.
- `reconcile --json` gana el campo `erased`, siempre un array (`docs/CLI-JSON.md`).
- `internal/vault/erase.go#EraseBlob` y `Store.DeleteBlob` se quedan como estaban: los usan
  sus tests, el de integración y la prueba de concepto histórica. El comando no los usa, porque borra dentro de la transacción del evento.
