# ADR-011-witness-http

**Estado:** aceptada · **Fecha:** 2026-09-06 · **Fuentes:** `c2sp.org/tlog-witness`, PROTOCOL.md §3, ADR-001, ADR-009 (auditoría externa)

## Versión del spec implementada

El wire format no se reconstruye de memoria ni de tutoriales: se descargó el
texto canónico del repositorio C2SP y se implementa contra él.

| dato | valor |
|---|---|
| documento | `tlog-witness.md` del repositorio [C2SP/C2SP](https://github.com/C2SP/C2SP) |
| commit del fichero | `c559ede261d1346b798c0d19d1e8bf7faa8eef39` |
| fecha del commit | 2026-07-29T18:07:37Z |
| sha256 del fichero | `83f9ce84cdcfe2bda283a7f9bd09b2a22c0a3a0d02f33bf227c0a5ed99481bf6` |

Cuando el spec cambie, ese sha256 dejará de coincidir y habrá que releerlo
entero antes de tocar nada. Es el mismo criterio que se usó con los vectores de
SLIP-0039: la referencia es el documento canónico, con su versión anotada, no la
memoria de quien escribe el código.

## Qué se implementa

**`POST <submission prefix>/add-checkpoint`**, completo.

Cuerpo de la petición: línea `old <tamaño>`, cero o más líneas de prueba de
consistencia en base64 (máximo 63), línea vacía, y el checkpoint verbatim. Cada
línea termina en U+000A.

Códigos de respuesta, tal como los fija el spec:

| código | causa |
|---|---|
| 200 | todo correcto; el cuerpo son líneas de firma de nota con las cosignatures |
| 400 | `old` mayor que el tamaño del checkpoint, o petición mal formada |
| 403 | ninguna firma de una clave de confianza para ese origin, o una firma cuyo nombre y key ID coinciden con una clave conocida pero no verifica |
| 404 | origin desconocido |
| 409 | `old` no coincide con el último tamaño cosignado; el cuerpo es ese tamaño en decimal más `\n`, con `Content-Type: text/x.tlog.size` |
| 422 | checkpoint de tamaño 0 sin la raíz del árbol vacío, prueba no vacía con `old` 0, prueba que no verifica, o `old` igual al tamaño con raíces distintas |

**`GET <monitoring prefix>/<origin hash>/checkpoint`**, completo. El origin hash
es el SHA-256 del origin en hexadecimal minúsculo. Devuelve la nota verbatim del
último checkpoint cosignado, con la firma del log y la cosignature del testigo;
404 si nunca cosignó para ese log.

Ese endpoint no es un extra: es **la mitigación del hallazgo ALTO de la
auditoría externa** registrado en ADR-009. Es la única forma de que el log
descubra que su fichero local fue truncado, porque la memoria que lo desmiente
vive fuera de su disco.

## Atomicidad

El spec dedica un bloque entero a una condición de carrera concreta: si el
testigo comprueba el tamaño anterior y persiste el checkpoint nuevo en dos pasos
separados, dos peticiones simultáneas pueden dejarlo avalando una historia más
corta que otra que ya avaló.

La comprobación de consistencia, la firma y la persistencia ocurren dentro de
**una sola transacción** de SQLite (`BEGIN IMMEDIATE`). Si la firma falla, la
transacción se deshace y el testigo no queda comprometido con nada. El estado
persistido es la tabla `witness_logs(origin TEXT PRIMARY KEY, note TEXT)`, con la
nota **verbatim**: los bytes exactos son lo firmado, y reserializar desde campos
sueltos reintroduciría el riesgo que ADR-009 ya descartó para `checkpoints`.

## Desviaciones conscientes

**Las cosignatures son Ed25519 (`tlog-cosignature@v1`, byte de algoritmo 0x04),
no ML-DSA-44.** El spec dice *"Witnesses SHOULD use ML-DSA-44 cosignatures"*, y
esto es una desviación de un SHOULD, no de un MUST. El motivo es de alcance: en
este sprint ML-DSA-44 entra como segunda firma del **log** (ADR-007), y las
cosignatures ML-DSA de testigos quedan explícitamente diferidas. Cuando entren,
el key ID usará el byte 0x06 que PROTOCOL.md §3 ya tiene reservado.

**`sign-subtree` no se implementa.** El spec lo declara OPTIONAL y Núcleo no
tiene hoy ningún uso para subárboles cosignados.

## Puntos ambiguos marcados en el código

Marcados con `// SPEC-CHECK` allí donde el spec no fija el detalle:

1. **`Content-Type` de la respuesta 200.** El spec fija el de la respuesta 409
   (`text/x.tlog.size`) y no dice nada del resto. Se emite
   `text/plain; charset=utf-8`.
2. **Cuerpo de las respuestas de error distintas de 409.** No está especificado.
   Se emite una línea de texto en claro para que un operador humano pueda leer
   el motivo; ningún cliente debe parsearla.
3. **Orden de comprobación entre el origin desconocido (404) y la firma
   inválida (403).** El spec describe ambas sin fijar el orden. Se resuelve
   primero el origin, porque para elegir la clave con la que verificar hay que
   saber de qué log se habla.

## Consecuencia sobre el código existente

`Witness.Cosign` verificaba la firma **antes** de leer el cuerpo de la nota. El
protocolo obliga a invertirlo: hay que leer el origin —sin verificar— para
elegir la clave con la que verificar y para poder devolver 404. No debilita
nada: el origin sin verificar solo se usa para **seleccionar** la clave, y
después se exige que la nota esté firmada por esa clave. Un origin falso
selecciona una clave que no firmó nada, y la verificación falla.

---

## Addendum 2026-09-06 — auditoría externa del testigo HTTP

Segunda revisión independiente de GPT-5.5, esta vez sobre el testigo HTTP. Dos
hallazgos ALTOS, dos MEDIOS, uno BAJO y tres frentes limpios.

### El principio que ordena todas las correcciones

**La única verdad autenticada es una cosignature verificada.** Ningún camino
puede declarar éxito, ni marcar nada como atestiguado, apoyándose en tamaños o
notas sin verificar. Los dos ALTOS eran la misma omisión mirada desde dos sitios:
el código trataba como prueba cosas que solo tenían la forma de una prueba.

### ALTO — el cliente no verificaba las cosignatures

El cliente se quedaba con las líneas de firma que le devolviera el servidor y las
daba por atestación. Una respuesta 200 impecable con una cosignature bien formada
**de otra clave** pasaba por buena.

Cláusula: *«The client MUST ignore any cosignatures from unknown keys. To parse
the response, the client MAY concatenate it to the checkpoint, and use a note
verification function configured with the witness keys it trusts. If that call
succeeds, it can move the valid signatures to its own view of the checkpoint.»*

`NewClient` exige ahora nombre y clave del testigo —sin clave no hay nada que
configurar, luego un cliente sin clave no puede cumplir el protocolo— y
`AddCheckpoint` devuelve la nota cosignada **ya verificada** en lugar de líneas
sueltas, para que nadie tenga que ensamblar bytes sin comprobar. El endpoint de
monitorización recibe el mismo trato, lo que cierra de paso el hallazgo BAJO.

### ALTO — el replay de una nota vieja y genuina silenciaba el rollback

`SyncWithWitness` tenía un atajo: si el testigo parecía estar al día, devolvía
éxito con la nota que él sirviera. Bastaba con reproducir la cosignature que el
testigo emitió cuando el árbol era más pequeño para que un ledger truncado
cuadrase consigo mismo. **La nota es auténtica y su firma verifica**; lo que no
hace es decir nada del estado de hoy.

Por eso el arreglo no fue verificar más, sino **no cortocircuitar nunca**. Cada
sincronización pide una cosignature del árbol actual, incluso cuando parece que
no hay nada nuevo, y solo devuelve éxito si la obtiene y esa cosignature cubre el
origin, el tamaño y la raíz locales.

El rollback se detecta por dos vías, ambas apoyadas en información verificada:
una nota de monitorización **verificada** con más historia de la que hay en
disco, o un 409 **corroborado** porque nuestro intento de extender contra el
estado real falló. El tamaño que viaja en el 409 no está autenticado y por sí
solo no probaría nada.

### MEDIO — 422 y 409: corrección de la implementación, no del ADR

Una prueba de consistencia que no verificaba devolvía **409** y el spec exige
**422**: *«If the proof is not empty when the old size is zero, or if a Merkle
Consistency Proof doesn't verify, the witness MUST respond with a "422
Unprocessable Entity" HTTP status code.»*

**Nota de corrección:** la tabla de códigos de este ADR, más arriba, ya decía
422 para ese caso y sigue siendo correcta tal como está escrita. Lo que se
desviaba era la implementación, de su propio ADR. Se corrige el código y la tabla
no se toca.

El 409 queda para su única causa —que el tamaño anterior declarado no sea el
último cosignado—, que es lo que justifica su cuerpo: ese tamaño, para que un log
honesto que perdió el hilo reintente. En los demás rechazos el tamaño declarado
era correcto y devolverlo no ayudaría a nadie.

Se revisó también el otro caso que el spec resuelve en 422 —`old` igual al tamaño
con raíces distintas— y ya estaba bien.

### MEDIO — el tiempo demostrable se calculaba por la forma del blob

Registrado en detalle en ADR-002 y en el paquete; en resumen: cualquier cosa de
72 bytes al final de la nota se convertía en una fecha con aspecto de
atestiguada. Ahora el tiempo demostrable exige la política de testigos y cuenta
solo cosignatures verificadas bajo ella.

### Frentes limpios, verificados

- **Atomicidad.** La comprobación del tamaño anterior, la firma y la
  persistencia siguen dentro de una sola transacción con `_txlock=immediate`.
- **Primer checkpoint.** `old = 0` con prueba vacía y, si el tamaño es 0, con la
  raíz del árbol vacío.
- **Recibo retocado.** `Parse` sigue re-derivando el encabezado y exigiendo
  igualdad byte a byte.

### Límite residual, documentado

Un adversario que controle el camino **puede impedir la detección, no fabricar
atestación**. Puede tirar la conexión, servir notas caducadas o provocar alarmas
falsas: todo eso es **disponibilidad**, y es ruidoso —una sincronización que no
termina en éxito se ve—. Lo que no puede es producir una cosignature válida de
una clave que no tiene, y por tanto no puede hacer que un ledger truncado pase
por atestiguado. La **integridad** aguanta; la disponibilidad no está garantizada
y no puede estarlo desde este lado.

El propio spec deja el canal sin resolver: *«There is no authentication of
requests beyond the validation of the signature on the checkpoint»*, y permite
delegar el prefijo de monitorización a una CDN con retrasos de hasta una hora.
Es decir, **una nota vieja y genuina es un resultado legítimo del protocolo**, no
una anomalía: por eso la frescura tiene que venir de `add-checkpoint` y no de lo
que sirva el canal de monitorización.

La consecuencia operativa es que una sincronización que falla repetidamente debe
tratarse como incidente, no como ruido. Hoy eso queda en manos de quien la
invoca; una alerta por sincronización sin éxito prolongada es trabajo pendiente.

