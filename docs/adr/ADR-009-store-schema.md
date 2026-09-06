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

## Enmienda 2026-09-05 — la apertura verifica desde el último checkpoint cosignado

La condición escrita en la decisión 4 **se cumplió**: `BenchmarkOpen` da 73 ms
con 10^3 bloques, 715 ms con 10^4 y **7,12 s con 10^5**, por encima del umbral
de 5 s. La condición se mantiene tal como se redactó; lo que esta enmienda
corrige es el remedio, porque la medición desmiente el supuesto que lo eligió.

`BenchmarkRootReconstruction` aísla el coste del árbol: **119 ms de los 7.120**.
Cachear subárboles arreglaría el **1,7 %** del problema. El coste real son 10^5
verificaciones Ed25519 a ~70 µs cada una, unos 7 s. La condición se escribió
suponiendo que la reconstrucción del árbol dominaba la apertura, y no domina.
La caché de subárboles queda **descartada** como remedio de la apertura: si algún
día vuelve, será por otra razón y con otra medición.

### Regla nueva

Al abrir:

1. Se reconstruye el árbol de Merkle **completo**, sobre todos los bloques.
2. La raíz reconstruida **DEBE** igualar la del último checkpoint **cosignado**
   persistido. Una discrepancia es un fallo de integridad, como hasta ahora.
3. Las firmas Ed25519 de los bloques se verifican **solo** para los bloques
   posteriores a ese checkpoint.
4. Si **no** hay ningún checkpoint cosignado persistido, la apertura verifica
   todas las firmas, como hasta ahora: sin testigo no hay atajo.
5. La verificación completa queda disponible como operación explícita
   (`VerifyFull`), para auditorías y para el arranque tras una sospecha.

**Fundamento.** Los bytes cubiertos por una raíz cosignada son los atestiguados:
un tercero independiente firmó esa raíz y conserva su propia copia, así que
reescribirlos ya no es un problema local. Y sus firmas Ed25519 ya se verificaron
al sellar —`AppendBlock` rechaza el bloque que no verifica— y al comprobarlas de
nuevo no se aprende nada que la raíz no diga ya.

### Lo que la regla nueva NO cubre, dicho sin adornos

**La firma de un bloque no está dentro de su hoja.** La hoja de Merkle es
SHA-256(JCS(header)), y la firma vive fuera del header. La raíz cosignada fija
cada byte de cada header —y con ellos el `prev_hash`, o sea el encadenamiento
entero—, pero **no** fija la columna `signature`. Quien tenga el fichero puede
corromper la firma de un bloque histórico y la apertura rápida no lo verá; lo
verá `VerifyFull`, y lo verá cualquiera que verifique un recibo de ese bloque.
Es corrupción detectable de un dato ya atestiguado, no reescritura de la historia.

Por eso el camino rápido **sí** recomputa SHA-256(JCS(header)) de cada bloque y
lo contrasta con la columna `hash`: sin esa comprobación, el árbol se
reconstruiría desde hashes que nadie ató a su contenido y el `header_json` sería
sustituible a voluntad. Es un SHA-256 por bloque, no una verificación Ed25519.

**El marcador de "cosignado" no se verifica al abrir.** El almacén no conoce las
claves de los testigos —no es su trabajo—, así que distingue una cosignature por
su forma: el blob de una firma de nota Ed25519 mide 64 bytes y el de una
`tlog-cosignature@v1` mide 72 (u64 de timestamp más 64 de firma). Quien controle
el fichero puede fabricar una línea de firma con la longitud correcta y activar
el camino rápido. Lo que gana con ello es exactamente lo del párrafo anterior: la
posibilidad de corromper firmas históricas sin que la apertura chille. No gana
reescribir historia, porque la raíz sigue teniendo que cuadrar.

Ambas cosas son el precio consciente de abrir en menos de un segundo. Quien no
quiera pagarlo llama a `VerifyFull`.
