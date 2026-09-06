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

Por eso el camino rápido **sí** comprueba la atadura entre cada header y su
hash: sin ella, el árbol se reconstruiría desde hashes que nadie ató a su
contenido y el `header_json` sería sustituible a voluntad. Es un SHA-256 por
bloque, no una verificación Ed25519. Se hace sobre los bytes almacenados, por
la razón que dice la decisión 1 de abajo.

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

### Decisiones del dev, 2026-09-06

**1. Los bytes almacenados son la forma autoritativa, y rechazar equivalentes es
lo correcto.** La comprobación de la atadura header↔hash se hace sobre el
`header_json` tal como está guardado —`SHA-256(bytes) == hash`— y no
recanonicalizando el header antes de hashearlo. Las dos detectan un header
alterado; se diferencian en qué hacen con un JSON de contenido idéntico y bytes
distintos, por ejemplo con los campos en otro orden. Recanonicalizar lo aceptaría
sin una queja, porque su forma canónica sí cuadra con el hash. Sobre los bytes
almacenados se rechaza, y ese rechazo es la conducta correcta: lo que el tenant
firmó no fue "un header con este contenido", fue **esta secuencia de bytes**, la
misma que `checkpoints.note` guarda verbatim y por el mismo motivo. Un
`header_json` que deje de ser la forma canónica JCS significa que la base ya no
contiene lo que se firmó, y eso tiene que verse aunque el contenido coincida:
normalizarlo por lo bajo convertiría en invisible una diferencia que un
verificador de otro lenguaje —el SDK de TypeScript, mañana— sí notaría. De paso
es lo que hace barato el camino rápido: 412 ms con 10⁵ bloques en lugar de 2,32 s.

**2. La firma fuera de la hoja es un límite ACEPTADO, con mitigación.** La hoja
de Merkle es SHA-256(JCS(header)) y la firma vive fuera del header, así que una
raíz cosignada no fija la columna `signature` y la apertura rápida no detecta su
corrupción. Meter la firma dentro de la hoja lo resolvería y **no se va a
hacer**: cambiaría la hoja, y con ella el formato del árbol, las pruebas de
inclusión ya emitidas y PROTOCOL.md §2. El precio de arreglarlo es mayor que el
problema, porque el problema es corrupción detectable de un dato ya atestiguado
—no reescritura de historia— y ya tiene dos maneras de salir a la luz: cualquiera
que verifique un recibo de ese bloque, y `VerifyFull`. La mitigación es que
`VerifyFull` deje de depender de que alguien sospeche: la reconciliación del
Sprint 3 lo ejecutará de forma programada, sin cambio de hoja ni de protocolo.

## Auditoría externa 2026-09-06

Revisión independiente de GPT-5.5 sobre SLIP-0039, vault y apertura. El frente
de las pruebas Merkle y de consistencia salió limpio. Tres hallazgos; este ADR
registra el que toca al almacén y deja constancia de dónde fueron los otros dos.

### ALTO — rollback local con borrado de checkpoints

**El hallazgo.** Quien controle el fichero puede borrar los disparadores, vaciar
la tabla `checkpoints` y truncar `blocks` a un prefijo. Lo que queda encadena,
sus firmas verifican y no hay checkpoint que lo contradiga: es una historia
válida, la de ayer. `Open` la acepta y hasta ahora no decía nada al respecto.

**Por qué no se arregla dentro del fichero.** No es un defecto de
implementación. Cualquier prueba que viviera en la base también sería del
atacante, así que la base no puede testificar sobre su propia integridad
histórica. Es el límite de lo que un fichero puede probar sobre sí mismo, y la
razón de que exista `internal/witness`.

**Decisión: se señala, no se bloquea.** `Open` devuelve
`OpenResult{TreeSize, Attested, AttestedSize}`. `Attested` es true solo si hay
un checkpoint cosignado persistido **y** la raíz reconstruida cuadra con él. Sin
checkpoints la apertura funciona —negarse sería negarse a abrir cualquier ledger
recién creado, que es un caso legítimo— pero queda marcada NO ATESTIGUADA, y el
estado viaja en el valor de retorno para que ningún llamante lo omita por
descuido. `cmd/nucleo-poc2` lo imprime.

**Mitigación, tarea del Sprint 3.** La detección definitiva está fuera del
fichero: al sincronizar, preguntar al testigo cuál fue el último checkpoint que
cosignó de nuestro origin y compararlo con lo que hay en disco. El testigo
recuerda un árbol de 5 y en la base hay 3: ahí se acaba el disimulo. Anotado en
TODO.md.

### Los otros dos hallazgos

- **MEDIO, AAD ambiguo** (`internal/vault`, PROTOCOL §5): el AAD es
  `tenant ‖ payload_hash` sin separador, y sin validación el par ("A", "B…")
  produce los mismos bytes que ("AB", "…"). Corregido exigiendo un
  `payload_hash` de 64 caracteres hex en minúscula: con el sufijo de longitud
  fija la lectura es única. El formato de PROTOCOL §5 no cambia.
- **BAJO, contrato de `RestoreKEK`**: registrado en el addendum de ADR-010.

