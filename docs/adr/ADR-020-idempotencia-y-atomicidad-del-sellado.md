# ADR-020-idempotencia-y-atomicidad-del-sellado

**Estado:** ACEPTADA el 2026-09-17 por el dev (Sprint 8) · **Fecha:** 2026-09-17 · **Fuentes:** [revisión externa, por un modelo, del 2026-09-13](../revision-externa-modelo-20260913.md) hallazgo H8; ADR-009 (esquema congelado), PROTOCOL.md §5 (AAD del blob) y §8 (almacenamiento), `cmd/nucleo/seal.go:119-146`, `internal/store/blobs.go:22`, `cmd/nucleo/profile.go:56`

## El hallazgo, reproducido

Binario de pruebas (reloj fijado para poder ordenar los hechos), ledger nuevo, un
documento de siete bytes. Cuatro comportamientos, todos verificados el 2026-09-17:

```
1) sellar el mismo payload dos veces, con cifrado (lo normal)
   error: store: inserción del blob 015abd7f…f862: constraint failed:
          UNIQUE constraint failed: blobs.payload_hash (1555)
   exit 1 — y en --json, esa misma frase dentro del campo "error"

2) sellar el mismo payload dos veces, con --no-encrypt
   ✔ bloque 1 — sin aviso, sin mención de que el contenido ya estaba sellado

3) el proceso falla entre el blob y el bloque
   (provocado de verdad: reloj atrasado → VerifyLink rechaza el bloque
    DESPUÉS de que el blob ya está escrito)
   error: ledger: timestamp anterior al del bloque previo
   → queda un blob sin bloque, y el reintento con el reloj bien:
   error: store: inserción del blob 0ab1a6d3…da93: UNIQUE constraint failed
   → y otra vez, y otra: ese documento NO SE PUEDE SELLAR NUNCA MÁS en este ledger

4) el mismo contenido desde otro tenant
   error: store: inserción del blob 015abd7f…f862: UNIQUE constraint failed
```

Lo que enseñan los cuatro juntos es que hoy **no hay ninguna decisión tomada**: el
comportamiento lo dicta qué tabla tiene PRIMARY KEY. Con cifrado sale un error crudo del
motor; sin cifrado, un bloque nuevo en silencio. La misma pregunta de negocio —¿re-sellar
es un error?— tiene dos respuestas opuestas según una bandera que solo debería hablar de
dónde se guarda el contenido.

El caso 3 es peor de lo que decía la auditoría. No es "queda un huérfano que bloquea el
reintento": es que **el reintento queda bloqueado para siempre**. Un ERP que reintenta
tras un timeout no recupera el sellado con un reintento posterior, ni al día siguiente.

## Decisión

### A. Re-sellar el mismo payload es un BLOQUE NUEVO legítimo

El ledger no registra documentos: registra **hechos de sellado**. "Este contenido existía
el 17 a las 12:00" y "este contenido existía el 17 a las 14:00" son dos afirmaciones
distintas, las dos verdaderas y las dos susceptibles de necesitar prueba —un contrato que
se vuelve a registrar al renovarlo, un acta que se re-sella tras una auditoría—. Nada del
protocolo dice que `payload_hash` sea único: la tabla `blocks` no lo restringe, y el
recibo prueba inclusión de un BLOQUE, no de un contenido.

Así que el caso 2 tenía razón y el caso 1 estaba mal. Pero el silencio del caso 2 también
estaba mal: un duplicado accidental es mucho más frecuente que uno deliberado, y el
sellado tiene que decirlo donde ocurre.

- El bloque se sella.
- El blob se **reutiliza**: mismo tenant y mismo `payload_hash` dan el mismo AAD
  (PROTOCOL §5), así que la fila que hay es exactamente la que se escribiría. Antes de
  reutilizarla se **descifra y se compara con el contenido en mano**; si no descifra o no
  coincide, no es un duplicado, es una manipulación de la base, y se dice así.
- La salida nombra el duplicado: `este contenido ya estaba sellado en el bloque N`, y
  `--json` lleva `duplicate_of`.

### B. El mismo contenido desde dos tenants distintos se RECHAZA, con su razón

No por purismo: porque hoy no cabe, y aceptarlo produciría un registro roto en silencio.

1. El texto cifrado está atado al tenant por el AAD (`tenant ‖ payload_hash`, PROTOCOL
   §5). El blob de T1 **no lo descifra T2**. Reutilizar la fila le daría a T2 un bloque
   cuyo contenido T2 no puede leer.
2. Los compromisos del perfil viven en `vault_meta` bajo `commit/v1/<payload_hash>` y
   `PutMeta` es un upsert. Con la clave sin tenant, los compromisos de T2 **sobrescriben**
   los de T1, calculados con otra subclave. El registro anterior queda con compromisos que
   no verifican.

La salida correcta sería una clave de blob por (tenant, payload_hash), y eso es un cambio
del esquema de ADR-009 —fichero de clientes, y este proyecto no tiene migraciones (regla
de arquitectura, no pereza)—. Mientras el esquema siga congelado, el sellado lo dice:

```
error: ese contenido ya está sellado por el tenant "T1" (bloque 0), y su copia cifrada
       está atada a ese tenant: T2 no podría descifrarla.
       Sella con --no-encrypt (solo el hash entra en el ledger) o usa un despliegue
       propio para ese tenant.
```

Queda anotado como limitación conocida, no como cosa arreglada.

### C. Blob + bloque + compromisos + clave de idempotencia, en UNA transacción

El comentario que ordenaba las escrituras ("el blob ANTES del bloque, así sobra un blob
inofensivo en vez de faltar el contenido de un bloque sellado") era el razonamiento
correcto para un mundo sin transacciones. Pero el huérfano no era inofensivo: bloqueaba el
reintento para siempre, que es el caso 3.

`store` gana `AppendRecord`, que hace todo dentro de una transacción: el blob, la
validación de encadenamiento contra el último bloque persistido, el bloque, los metadatos
del registro (compromisos) y el registro de idempotencia. O está todo, o no está nada. Los
huérfanos dejan de existir como clase, y el orden entre las escrituras deja de ser un
argumento de seguridad.

El candado de escritura del proceso sigue donde estaba, y ahora además abarca la
transacción entera: dos sellados concurrentes no pueden leer el mismo "último bloque".

### D. La clave de idempotencia la pasa el integrador

`nucleo seal --idempotency-key K`. Semántica, la de las APIs de pago, que es la que un ERP
ya conoce:

| situación | resultado |
|---|---|
| K nueva | se sella; la clave se guarda en la misma transacción |
| K conocida, **mismo** documento y tipo | **no-op**: exit 0, misma salida que el sellado original (índice, hash, perfil, compromisos), con `idempotent: true`. No se escribe nada |
| K conocida, **otro** documento o tipo | error de uso: `la clave de idempotencia "K" ya se usó para otro documento (bloque N)` |
| K conocida, pero el bloque al que apunta **no está** | error de verificación (exit 2): el registro y el bloque se escribieron juntos, así que el bloque falta porque alguien tocó el fichero |

La clave está **acotada por tenant**: dos emisores del mismo despliegue no se pisan las
claves, porque "factura-001" es un identificador natural en cualquier ERP. Vive en
`log_state`, que ADR-009 declaró mutable por diseño, bajo
`seal/idempotency/v1/<sha256(tenant ‖ 0x00 ‖ K)>`; el valor guarda el tenant y la clave en
claro para poder nombrarlos en los errores. Sin DDL nuevo: no hay cambio de esquema.

Dos cosas que el no-op NO afloja:

- se comprueba el firmante de la cadena igual que en un sellado normal. Un reintento
  contra un ledger secuestrado no puede contestar "todo en orden" (ADR-017);
- el bloque al que apunta la clave se **lee del ledger** y se compara su `payload_hash`
  con el del documento en mano. `log_state` no está firmado: quien pueda escribirlo
  intentaría hacer que un reintento diera por sellado un documento que no está.

Sin `--idempotency-key` no hay magia: se sella un bloque nuevo (decisión A). Adivinar la
intención a partir de que el contenido coincida convertiría un duplicado deliberado en un
no-op silencioso, y el ledger dejaría de tener el hecho que alguien pidió registrar.

### E. Ningún error del motor llega al usuario

`UNIQUE constraint failed: blobs.payload_hash (1555)` no es un mensaje: es un volcado. Y
en `--json` iba dentro del campo `error`, es decir, entraba en el log del integrador como
contrato.

- `store` clasifica los errores del driver por su **código de resultado** —no por el texto,
  que cambia entre versiones— y devuelve errores con tipo: `ErrDuplicateBlob`,
  `ErrConstraint`, `ErrBusy`.
- Lo que no se puede clasificar sale como "error interno de la base de datos" nombrando la
  operación, y el detalle del driver queda accesible con `errors.Unwrap` para quien
  depura, no en la primera línea del usuario.
- Un test recorre las rutas de fallo del sellado y **falla si algún mensaje de la CLI
  contiene `constraint`, `sqlite`, `SQL` o un código de resultado entre paréntesis**. Es la
  única forma de que esto no vuelva: la regla es comprobable, no una buena intención.

## Consecuencias

- Un ERP que reintenta tras un timeout con la misma clave deja de duplicar registros, y
  sin clave deja de romperse: en el peor caso duplica un bloque y se le dice.
- Un documento cuyo sellado se cortó a medias se puede volver a sellar. Antes, no.
- `seal` hace una lectura más por sellado para poder nombrar el duplicado
  (`blocks WHERE header_json LIKE '%"payload_hash":"…"%'`). Es una pasada sobre la tabla y
  se apoya en que `header_json` está guardado en forma canónica JCS, que es invariante del
  store. Medido en el ledger de referencia: por debajo del coste de la propia apertura.
- `--no-encrypt` y el cifrado se comportan igual ante un duplicado. La bandera vuelve a
  hablar solo de dónde se guarda el contenido.
- **No toca PROTOCOL.md.** Nada de esto cambia lo firmado: ni el header, ni la hoja, ni el
  recibo, ni la nota. Un verificador —Go, TypeScript o la página— no nota la diferencia, y
  los vectores compartidos siguen valiendo byte a byte.
- **No toca el esquema de ADR-009.** Ni tablas nuevas ni columnas nuevas: la idempotencia
  usa `log_state`, que ya existía y ya era mutable.

## Alternativas descartadas

- **Re-sellar es un error (mantener el caso 1, con mejor mensaje).** Convierte en error una
  operación legítima, y deja al integrador sin forma de registrar dos veces un mismo
  contenido en dos momentos. Además exige que el ERP distinga "ya lo sellé" de "quiero
  sellarlo otra vez", que es precisamente lo que la clave de idempotencia resuelve mejor.
- **Re-sellar es siempre un no-op idempotente (deduplicar por contenido).** Es la opción
  que más gente esperaría y la peor: el ledger perdería hechos reales, y peor aún, lo haría
  en silencio. Un "ya estaba" indistinguible de un "lo acabo de sellar" es exactamente el
  patrón que ADR-016 cerró en la atestación.
- **Clave de idempotencia dentro del header.** Sería parte de lo firmado y prueba de nada:
  la clave es un detalle del transporte entre el ERP y la CLI, no un hecho sobre el
  documento. Y cambiaría el formato de cable, los vectores y los tres verificadores.
- **Deducir la idempotencia de (tenant, tipo, payload_hash) sin clave.** Ver decisión D:
  no hay forma de distinguir el reintento del duplicado deliberado, y adivinar mal
  silencia un hecho.
- **Blobs con clave (tenant, payload_hash).** Es la forma correcta y no cabe sin migración.
  Anotada como limitación en B para cuando el esquema se abra.
