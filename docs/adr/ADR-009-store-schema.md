# ADR-009-store-schema

**Estado:** aceptada · **Fecha:** 2026-09-05 · **Fuentes:** PROTOCOL.md §5 y §8, ADR-001

## Contexto

El ledger necesita persistencia. PROTOCOL.md §8 fija SQLite con driver Go puro,
WAL, `synchronous=FULL`, un solo escritor y disparadores que aborten UPDATE y
DELETE sobre los bloques. Este ADR congela el esquema: hay ficheros de clientes
en juego, así que cambiarlo exigirá un ADR nuevo y una migración.

## Esquema

```sql
blocks(idx INTEGER PRIMARY KEY,
       hash TEXT UNIQUE NOT NULL CHECK(length(hash)=64),
       header_json TEXT NOT NULL,
       signature TEXT NOT NULL)

blobs(payload_hash TEXT PRIMARY KEY CHECK(length(payload_hash)=64),
      ciphertext BLOB NOT NULL,
      nonce BLOB NOT NULL,
      created_at TEXT NOT NULL)

checkpoints(tree_size INTEGER PRIMARY KEY,
            note TEXT NOT NULL)   -- nota firmada verbatim, cosignatures incluidas

vault_meta(k TEXT PRIMARY KEY, v BLOB NOT NULL)  -- salt Argon2id, DEK envuelta, params
```

`checkpoints.note` guarda la nota **verbatim**, con sus cosignatures. No se
descompone en columnas: los bytes exactos son lo firmado, y reserializar desde
campos sueltos reintroduciría el riesgo de que un cambio de formato invalide
firmas ya emitidas.

## Decisiones

**1. Append-only por disparadores.** BEFORE UPDATE y BEFORE DELETE sobre `blocks`
y `checkpoints` hacen `RAISE(ABORT, 'nucleo: ledger append-only')`. `blobs`
admite DELETE —es el borrado de datos personales de la LOPDP— pero **no** UPDATE:
sustituir un texto cifrado bajo el mismo `payload_hash` sería reescribir el
contenido sin tocar el ledger.

Los disparadores son una barandilla contra el error y el atacante perezoso, no la
frontera de seguridad: quien controle el fichero puede borrarlos con una
sentencia. Lo que hace irreversible una reescritura son los testigos que ya
cosignaron la raíz anterior. Por eso `Open` verifica la integridad en vez de
confiar en el esquema.

**2. Un solo escritor, serializado con un mutex de proceso.** `AppendBlock`
decide el índice y el `prev_hash` del bloque nuevo leyendo el último persistido.
Dos escritores concurrentes leerían el mismo "último bloque" y construirían dos
bloques con el mismo índice; el UNIQUE de `hash` rescataría algunos casos, no
todos, y el que perdiera la carrera ya habría firmado. SQLite en WAL admite un
escritor a la vez de todos modos, así que serializar en el proceso convierte un
error de datos en una espera.

**3. Los PRAGMA viajan en el DSN.** `journal_mode` es persistente en el fichero,
pero `synchronous` y `foreign_keys` son **por conexión**: ejecutarlos una sola
vez tras abrir dejaría al resto del pool sin ellos. Se pasan como `_pragma` en el
DSN para que los reciba cada conexión, y los tests los leen de vuelta.

**4. El estado Merkle se reconstruye en memoria al abrir, en O(n).** No se
persiste el árbol ni se cachean subárboles. A ~20.000 sellos/s de hashing, un
millón de bloques se recorren en segundos, de sobra para el perfil pyme que es el
objetivo.

La caché de subárboles queda **explícitamente diferida**, con esta condición
escrita: *se implementa cuando un benchmark real muestre apertura >5 s en
hardware objetivo.* `BenchmarkOpen` mide la apertura con 10^5 bloques y su cifra
se registra en el reporte del sprint; mientras esté por debajo del umbral, la
caché no se escribe.

**5. `Open` verifica antes de devolver.** Encadenamiento completo de todos los
bloques, raíz de Merkle reconstruida, y contraste con el último checkpoint
persistido. Una discrepancia devuelve un error tipado que nombra el bloque
implicado. Es lo que convierte el borrado de un disparador en un fallo visible en
vez de en una reescritura silenciosa.

## Consecuencias

- `modernc.org/sqlite` entra como dependencia, con su cierre transitivo (libc,
  memory, mathutil, bigfft y utilidades). Es el precio del SQLite sin cgo, que
  es lo que permite releases estáticos multiplataforma sin toolchain de C.
- Cambiar el esquema exige ADR nuevo y migración: a partir de aquí hay bases de
  datos reales que abrir.
