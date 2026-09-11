# ADR-014-hoja-y-firma

**Estado:** PROPUESTA, pendiente de decisión del dev · **Fecha:** 2026-09-10 · **Fuentes:** revisión externa 2026-09-10 (hallazgo 4), ADR-009 y su enmienda, ADR-006, PROTOCOL.md §1-§2, RFC 6962 §2.1, `internal/ledger/merkle.go`, `internal/store/integrity.go`

La revisión externa marcó como defecto de diseño —no como nota al pie— que la
firma del bloque quede fuera de la hoja de Merkle: *"un auditor externo te lo va a
marcar HIGH hasta que el leaf sea H(header ‖ sig) o equivalente; `verify --full` no
es mitigación si nadie lo corre"*. Este ADR analiza el cambio. **No implementa
nada.**

## Cómo está hoy, exactamente

```
block.hash      = SHA-256( JCS(header) )                    (32 bytes)
block.signature = Ed25519( block.hash )                     (64 bytes, columna aparte)
leaf_data       = block.hash                                ← la hoja es SOLO el hash
leaf_hash       = SHA-256( 0x00 ‖ leaf_data )               (RFC 6962 §2.1)
```

`Hash` y `Signature` viven fuera del header a propósito, para que lo firmado sea
inequívoco (comentario en `internal/ledger/block.go`). La consecuencia no buscada
es que **la raíz cosignada no dice nada sobre la columna `signature`**.

Un dato que conviene tener delante, porque afina el hallazgo: el recibo **no
lleva la firma del bloque**. Lleva el header canónico y la prueba. Así que hoy
quien recibe un recibo no es que tenga una ruta lenta para comprobar la firma del
bloque: **no tiene ninguna**. Ve `signer_pubkey` en el header y nada con lo que
contrastarlo.

## Qué protege de más, con precisión

Lo que el cambio cierra:

1. **El punto ciego de la apertura rápida.** Tras la enmienda de ADR-009, abrir
   verifica los bytes almacenados del header contra su hash y, por debajo del
   último checkpoint cosignado, se salta las verificaciones Ed25519 (412 ms contra
   8,04 s en 10⁵ bloques). Hoy, alguien con escritura en la base puede **borrar o
   ensuciar las firmas** y la apertura sigue diciendo "historia atestiguada": la
   raíz no las cubre. Con la firma en la hoja, la misma comprobación que ya se
   hace al abrir detecta ese destrozo. `verify --full` deja de ser la única ruta,
   que es el texto literal del hallazgo.
2. **El recibo puede llevar la firma y ser comprobable por el destinatario.** Si
   la hoja incluye la firma, el recibo tiene que transportarla para que la
   contraparte recomponga la hoja — y con ella gana la capacidad de verificar la
   firma del bloque, que hoy no tiene.

Lo que **no** cierra, y no conviene insinuar que sí:

- Un adversario con la clave del tenant. Tampoco hoy: cambiar el header cambia su
  hash, cambia la hoja y cambia la raíz. `signer_pubkey` va dentro del header, así
  que una firma válida tiene que ser de la clave fijada por la raíz. El cambio no
  mueve esa frontera.
- Mentiras en origen. El log demuestra qué se registró, no que sea cierto.

En una frase: el cambio convierte *"corrupción de firmas detectable solo por una
auditoría que nadie ejecuta"* en *"detectable por la comprobación que ya se hace
al abrir"*. Es una mejora real y estrecha. Merece hacerse por lo que cuesta, no
porque hoy haya un agujero por el que se falsifique nada.

## Qué forma darle a la hoja

Dos candidatas:

| forma | leaf_data | notas |
|---|---|---|
| **A** | `block.hash ‖ block.signature` (32+64 = 96 bytes, crudos) | sin hash extra; la hoja es auto-describible y se puede partir |
| **B** | `SHA-256( block.hash ‖ block.signature )` (32 bytes) | mantiene el tamaño de hoja actual |

Las dos son seguras: ambos campos son de **longitud fija**, así que la
concatenación no es ambigua —la lección del AAD de ADR-009, aplicada aquí a
tiempo—. La diferencia es de especificación, no de fuerza.

**Recomendación: A.** Una regla menos que escribir en PROTOCOL.md, y un verificador
que por error alimente solo el hash obtiene una hoja distinta y **falla
ruidosamente** en vez de coincidir por casualidad. El tamaño de las pruebas de
inclusión no cambia en ninguna de las dos: la prueba son hashes de nodo.

**Condición de estabilidad.** Esto solo funciona si la firma es determinista: la
misma clave sobre el mismo mensaje tiene que dar los mismos bytes, o la hoja
cambiaría al re-firmar. Ed25519 lo es por RFC 8032, y lo medí en vez de citarlo:
1000 firmas del mismo mensaje con la misma clave, idénticas. **Si algún día la
firma de bloque pasa a ML-DSA-44, tiene que usar la variante determinista** —ya
existe `SignDeterministic` en `internal/checkpoint/mldsa.go`— o este diseño se
rompe en silencio. Eso hay que escribirlo en PROTOCOL.md junto a la regla de la
hoja, no en un ADR que nadie relee.

## Qué rompe, medido

El brief decía "TODOS los vectores". No es exacto, y la diferencia importa:

- **Los vectores oficiales RFC 6962 SOBREVIVEN.** `testdata/vectors/merkle/rfc6962/`
  prueba el algoritmo del árbol con datos de hoja arbitrarios (`leaves_hex`: `""`,
  `"00"`, `"10"`, …). Cambiar lo que *nosotros* metemos en una hoja no toca el
  algoritmo. `internal/ledger/merkle.go` no se modifica.
- **Sí rompen:** los 3 vectores de recibo, `internal/store` (`LeafHashes`, `Root`,
  la reconstrucción en `integrity.go`), `internal/logsync/adapter.go`,
  `internal/receipt`, `internal/proof`, y en TypeScript `merkle.ts` (el `leafData`
  que recibe `verifyInclusion`) y `receipt.ts`. Más los tests de
  `internal/integration`, `internal/ledger/bench_test.go` y `sdk/ts/test`.
- **PROTOCOL.md §1-§2** y el formato del recibo, que crece ~129 bytes (la firma en
  hex): de 4740 a ~4869, un 2,7 %.
- **El magic del recibo.** Si el recibo pasa a llevar la firma, un verificador
  viejo no sabe recomponer la hoja nueva: aquí sí hay que bumpear a
  `nucleo.org/receipt@v2`. No es opcional como en ADR-015.
- **Todas las raíces existentes.** Cada hoja cambia, así que cambia cada raíz, y
  con ella todo checkpoint firmado y toda cosignature de testigo ya emitida.

## El coste, hoy y después

**Hoy: prácticamente cero.** Cero usuarios, cero recibos en manos de terceros,
alpha publicada hace un día. Lo que hay que regenerar son tres vectores y los
logs de desarrollo.

**Después: alto, pero no infinito.** Conviene no dramatizar, porque hay una salida
ya diseñada: **ADR-006 ya define segmentos por periodo**, con pruebas de
consistencia RFC 9162 §2.1.4 entre los checkpoints de cierre. Una migración futura
podría cerrar el segmento vigente con su raíz vieja y abrir el siguiente con la
regla nueva, dejando la historia anterior verificable con la regla anterior. Es
caro —dos reglas de hoja conviviendo, dos caminos en cada verificador, para
siempre— pero es posible.

Eso sí: la versión de la regla de hoja tendría que ser **explícita** en algún sitio
que el verificador lea (el `origin` del segmento, o una línea de extensión del
checkpoint). Hoy no lo es, y sin eso la migración por segmentos no es
implementable: un verificador no tendría forma de saber qué regla aplicar.

## Recomendación

**Hacerlo, y hacerlo ahora**, con cuatro condiciones:

1. **Forma A**, `leaf_data = hash ‖ signature`, con los dos campos crudos y de
   longitud fija.
2. **La regla de hoja pasa a ser versionada y explícita**, para que la próxima vez
   exista la salida por segmentos que hoy no existe. Esto es casi más valioso que
   el cambio en sí: es lo que evita que dentro de un año volvamos a estar ante un
   "ahora o nunca".
3. **Una sola rotura de formato.** Si ADR-015 (destinatario firmado) se acepta, va
   en la misma migración. Dos roturas en dos sprints son el doble de versiones de
   verificador conviviendo, y cada una cuesta lo mismo que esta.
4. **Vectores primero**, calculados fuera del código: la hoja nueva, la raíz nueva
   y un recibo completo, con `sha256sum` y python, antes de tocar una línea de
   producción. Regla anti-circularidad del proyecto, que aquí es justo donde más
   duele equivocarse.

Si el dev dice **no**, la consecuencia hay que asumirla por escrito: `verify --full`
pasa a ser obligatorio y programado —no una opción de auditoría—, porque es la
única ruta que cubre la columna `signature`, y el README debe decir que la
apertura rápida no la cubre. Hoy lo dice a medias.

## Plan de ejecución, si el dev dice sí

1. PROTOCOL.md: regla de hoja nueva, versionada y explícita, más la condición de
   determinismo de la firma. Bump de `receipt@v1` → `@v2`.
2. Vectores nuevos calculados FUERA: `leaf_data`, `leaf_hash`, raíz de un árbol de
   8 bloques, y un recibo completo. Con su script de generación independiente.
3. `internal/ledger`: una función `LeafData(block)` —el único sitio donde se decide
   qué es una hoja— para que no quede repartida por tres paquetes como ahora.
4. `internal/store`: `LeafHashes` lee también `signature`; medir de nuevo la
   apertura (espero unos pocos ms más: una concatenación y un SHA-256 por bloque
   sobre los 412 ms actuales en 10⁵, pero **medirlo**).
5. `internal/receipt` + `internal/proof`: la firma viaja, el texto legible no
   cambia.
6. `sdk/ts`: `leafData` nuevo y los cuatro casos de vector. Los vectores
   compartidos son lo que garantiza que las dos implementaciones se encuentren; ya
   cazaron este mismo tipo de desajuste una vez.
7. `web/verify` y tutorial, con salidas reales.
8. CHANGELOG con una nota de incompatibilidad explícita: los recibos emitidos
   antes del cambio no verifican con el verificador nuevo, y al revés.
