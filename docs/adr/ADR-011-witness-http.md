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
