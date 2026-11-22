# ADR-035-anulacion-de-facturas

**Estado:** PROPUESTA el 2026-11-22 (Sprint 36), sin código y pendiente de aceptación del dev ·
**Fecha:** 2026-11-22 · **Fuentes:**
- la investigación de la norma, [`docs/investigacion/sri-anulacion-2026-11.md`](../investigacion/sri-anulacion-2026-11.md)
  (NAC-DGERCGC25-00000014 y -00000017, Ficha técnica offline v2.34);
- `docs/GARANTIAS.md` L18 y el TODO «Después de la 0.5»;
- PROTOCOL 0.8-draft §1, §5 y §5.1;
- ADR-023 (enumeración y entropía);
- ADR-031, ADR-032 y ADR-033 (cómo se diseñó la supresión);
- `profiles/ecuador/` (`TipoFactura`, `ParseFactura`, `ClaveAcceso`), `cmd/nucleo/profile.go`,
  `cmd/nucleo/seal.go` y `internal/reconcile`.

## El problema

Una factura del SRI se **anula**. La anulación no borra la factura: el SRI la marca «ANULADO»,
y el emisor tiene que conservarla siete años (RCV art. 50). Y hoy Núcleo no tiene forma de
decirlo. El README y L18 lo admiten: «la supresión no es la anulación de una factura».

Lo que un integrador tiene hoy a mano, y por qué no sirve:

- **Suprimir** (`erase`, ADR-031/032) borra el contenido. Es lo contrario de lo que pide el
  SRI, que manda conservar la factura anulada y dejar verificable su emisión. Además exige la
  clave de supresión, que custodia una persona y no un ERP.
- **Borrar la factura de la base** la deja como `faltante` en la siguiente reconciliación, que
  sale con 2. Es correcto: Núcleo no tiene manera de distinguir una factura anulada de una que
  alguien hizo desaparecer.
- **Cambiar la factura en la base** para marcarla anulada (un campo `estado`) da una
  `discrepancia` con lo sellado, y otra vez código 2.
- **Sellar un JSON propio** («anulé la factura N») funciona, pero es una convención privada: la
  reconciliación no lo entiende, ningún tercero sabe leerlo y nada impide sellar dos.

Lo que falta es un **evento de anulación**: un bloque que diga «el emisor declara anulada la
emisión del bloque N», con la emisión intacta y verificable, y unas reglas con las que la
reconciliación y un tercero lo comprueben.

**Lo que el SRI dice** (la investigación, con citas):
- se anula en línea, a petición del emisor, hasta el día 7 del mes siguiente;
- una factura se anula al instante; una retención, una nota de crédito o una nota de débito
  necesitan que el receptor acepte en 5 días hábiles;
- pasado el plazo, una factura solo se corrige con una nota de crédito (`codDoc` 04);
- desde 2026 las facturas «consumidor final» no se anulan;
- no se pide motivo;
- la única constancia es el estado «ANULADO» en el SRI. Una constancia firmada de la anulación
  queda **SIN CONFIRMAR**, y probablemente no existe.

## Decisión

### 1. El tipo del evento: `nucleo.void.v1`, del núcleo

El evento es un bloque del núcleo, con tipo **`nucleo.void.v1`**, igual que `nucleo.erasure.v1`.
No es un tipo de perfil como `ecuador.sri.factura.anulacion.v1`.

- **Lo sella Núcleo, nunca el integrador.** El prefijo `nucleo.` ya está reservado (PROTOCOL
  §5.1; `seal --type nucleo.…` es un error de uso). Así el contenido lo construye siempre el
  mismo código, con las mismas reglas, y la reconciliación sabe qué esperar.
- **Anular no es propio del SRI.** Se anula en cualquier régimen de facturación electrónica, y
  en general en cualquier registro emitido que deje de valer sin dejar de haber existido. Lo
  que es del SRI son los plazos y quién acepta, y eso vive fuera de Núcleo: en el SRI y en el
  ERP.
- **La regla de validez es estructural**, no fiscal (decisión 5): referencia, orden, tenant.
  Encaja en PROTOCOL igual que la supresión.

*Alternativa descartada: un tipo de perfil*, `ecuador.sri.factura.anulacion.v1`, sellado con
`seal --profile`. Tiene tres problemas:
- un tipo de perfil lo puede sellar el integrador con cualquier contenido, así que la
  reconciliación tendría que validar un payload que no construyó;
- habría que repetirlo en cada perfil y cada régimen;
- y la regla de la reconciliación quedaría atada al perfil, cuando lo que comprueba (que la
  referencia exista y sea anterior) no tiene nada del SRI.

*Alternativa descartada: no hacer nada y documentar la convención del JSON propio.* La
reconciliación seguiría sin entenderlo, y precisamente reconciliar es el producto.

### 2. La referencia a la emisión: el índice y el `payload_hash`, nunca la clave de acceso

El evento apunta a la emisión por dos datos que **ya son públicos** en la cadena, en el header
de un bloque anterior: su **índice** y su **`payload_hash`**. Lleva los dos porque cada uno
cubre un fallo distinto:
- el índice elige el bloque exacto, aunque el mismo contenido se haya sellado dos veces;
- el hash ata el evento al contenido, y un índice equivocado no casa con él.

**La clave de acceso no va nunca, ni en claro ni como hash desnudo.** Hay tres razones:
- **ADR-023 y PROTOCOL §5**: un identificador adivinable no viaja como hash desnudo. La clave
  tiene estructura pública: fecha, tipo, RUC, ambiente, serie, secuencial, tipo de emisión y
  dígito verificador. Lo que no se conoce son los 8 dígitos del código numérico, unos 10⁸
  valores para quien conoce lo demás. Eso no es entropía que proteja nada.
- **No hace falta.** El índice y el hash identifican la emisión sin ambigüedad.
- **El evento viaja en su recibo**, y ese recibo se entrega a terceros.

Si algún día hiciera falta cruzar por clave de acceso dentro del ledger, iría como **compromiso
del perfil** (HMAC con la subclave del tenant, ADR-003), en `vault_meta`, como los demás campos
sensibles, y nunca en el evento. Esta ADR no lo propone.

**Cómo encuentra el ERP el índice**, si solo guarda la clave de acceso: ver la decisión 8, que
propone `--payload` (el ERP tiene el XML).

*Alternativa descartada: solo el `payload_hash`*, como la supresión. Con el mismo contenido
sellado dos veces, no se sabría cuál de las copias se anula. La supresión no tiene este problema
porque suprime contenido y no registros, y por eso lleva `<k>` («todas las copias hasta k»).
Anular es de un registro concreto.

*Alternativa descartada: solo el índice.* Un error de una cifra apuntaría a otra factura, y nada
lo detectaría.

### 3. Contenido y entropía: determinista, sin motivo y sin campo aleatorio

El payload es la serialización JCS (RFC 8785) de exactamente dos miembros, los dos cadenas:

```json
{"voided_index":"<i>","voided_payload_hash":"<h>"}
```

- `<i>` es el índice decimal de la emisión, con la forma `0|[1-9][0-9]*` y como mucho 2^53 − 1.
  Va como cadena porque §5 manda que los identificadores viajen así.
- `<h>` es su `payload_hash`, en 64 cifras hexadecimales en minúscula.

El `payload_cid` del evento es `nucleo-void@v1:<i>`. El contenido no se guarda: se reconstruye.
El índice va en el header para que el recibo del evento diga por sí solo a qué apunta, y para
que la reconciliación distinga «apunta a un bloque que no existe» de «apunta a uno que existe
pero con otro contenido».

**Es determinista y no lleva los 16 bytes aleatorios de §5.** Sería la segunda excepción,
después de la supresión, y por la misma razón:
- todo lo que lleva ya es público en la cadena (el índice y el hash de un header anterior);
- y el índice va además en el header del propio evento.

Un campo aleatorio no ocultaría nada. Y obligaría a guardar el payload fuera de la cadena para
poder leerlo, con lo que la reconciliación dependería de un dato que se puede perder (el
argumento de ADR-031 §C). ADR-023 pide entropía para que el hash no confirme un documento
adivinable. Aquí el «documento» no tiene nada que adivinar.

**Sin motivo**, por tres razones:
- el SRI no pide motivo para anular (investigación, a);
- el motivo puede ser en sí un dato comercial o personal («error en la identificación del
  comprador»), y un recibo se entrega a terceros;
- un código cerrado de pocos valores se enumera con el recibo en la mano.

El motivo, si el ERP lo quiere, vive en el ERP. El motivo obligatorio del SRI está en la nota de
crédito, que es otro documento.

**Sin hash de la evidencia del SRI**, por dos razones:
- no hay una constancia firmada que sellar (SIN CONFIRMAR, investigación b);
- lo que sí hay (la respuesta del servicio web, el correo) contiene la clave de acceso, así que
  su hash desnudo confirmaría una clave adivinada (decisión 2).

Si el ERP quiere conservar esa constancia, la sella como un registro propio, con su campo
aleatorio (§5, SHOULD). Si el dev quiere atarla al evento, ver «Preguntas para el dev».

Vector, calculado fuera del código con Python (`json.dumps` con `sort_keys` y sin espacios) y con
`sha256sum`: para `<i>` = `3` y `<h>` =
`e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`, el payload es
`{"voided_index":"3","voided_payload_hash":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}`,
mide 109 bytes y su `payload_hash` es
`33e90e55d607b81ef2ed49ce302023676d443c424a8bc77506dd3b5c8ae72143`.

*Alternativas descartadas:*
- **El motivo como código cerrado.** Ver arriba: se enumera, y el SRI no lo pide.
- **Los 16 bytes aleatorios.** No ocultan nada que no esté ya en el header, y rompen la
  reconstrucción.
- **El índice como número JSON.** JCS lo serializa bien hasta 2^53, pero §5 pide cadenas para
  los identificadores. Una sola regla para todos los payloads de Núcleo vale más que ahorrar
  dos comillas.

### 4. Autoridad: basta la firma del tenant

El evento lo firma la clave del tenant, como cualquier bloque. **No pide otra clave.**

La supresión exige la clave de supresión (ADR-032) porque una supresión **disculpa un
hallazgo**: hace que un `faltante` deje de serlo. Y quien tiene la clave del servidor es justo
el adversario que borra registros. **La anulación no disculpa nada** (decisión 6):
- no cambia el código de salida;
- no convierte un `faltante` en otra cosa;
- no convierte una `discrepancia` en otra cosa;
- no toca el recibo de la emisión.

Lo único que añade es una afirmación sellada: «el emisor declara anulada esta emisión».

**El abuso: un emisor que anula para negar una venta.** Esto es lo que consigue y lo que no:
- **No borra la venta.** La emisión sigue en la cadena, sellada y atestiguada antes que la
  anulación, y su recibo sigue verificando. Quien tenga ese recibo sigue teniendo la prueba de
  que se emitió y de cuándo.
- **No puede antedatar la anulación.** El evento va después en la cadena, y lo atestigua el
  siguiente `sync`. Una anulación de diciembre para una factura de marzo se ve como lo que es.
- **No engaña a la reconciliación.** La anulación sale en `voided` en cada reconciliación, para
  siempre, con su fecha declarada.
- **Lo que sí puede: sellar una anulación que el SRI nunca registró.** Núcleo no lo detecta,
  porque no habla con el SRI y no debe hacerlo. Por eso el límite nuevo (decisión 7) dice que
  la anulación de Núcleo es la **declaración** del emisor, no el estado del SRI: quien tenga
  que saber si una factura está anulada lo consulta en el SRI (`consultarEstadoAutorizacionComprobante`).

Una clave aparte no cerraría ese hueco: la firma de un custodio tampoco prueba el estado del
SRI. Lo único que añadiría es una ceremonia humana en una operación que un ERP hace a diario.

*Alternativas descartadas:*
- **La clave de supresión.** Su custodia es humana y rara (ADR-032 §A). Anular es rutina del
  ERP, y una clave que se usa a diario acaba en el servidor, que es justo lo que ADR-032 quiso
  evitar. Y no protegería nada, porque anular no disculpa nada.
- **Una clave de anulación nueva en la política** (`voidKey`). El mismo problema, más un miembro
  de política nuevo que rompería los SDK 0.5, que la rechazarían por desconocido (ADR-018).
- **La firma del receptor.** El receptor no participa en Núcleo, y el SRI no pide su aceptación
  para anular una factura.

### 5. Las reglas de validez, cada una con su hallazgo

Sea `V` un bloque de tipo `nucleo.void.v1`. `V` es una **anulación válida** si y solo si se
cumplen las seis reglas de abajo. Cada regla que falla es un hallazgo de integridad en la
reconciliación, con estado **«anulación inválida»** y el motivo correspondiente. La
reconciliación sale con 2, porque la CLI de Núcleo nunca sella un evento así, y si está ahí
alguien la esquivó.

| # | regla | si falla, el motivo |
|---|---|---|
| R1 | `payload_cid` es exactamente `nucleo-void@v1:<i>`, con `<i>` en la forma de la decisión 3 | «el payload_cid de la anulación no tiene la forma nucleo-void@v1:<índice>» |
| R2 | `<i>` < `V.index`: la referencia es **anterior** | «la anulación apunta a un bloque que no es anterior a ella» |
| R3 | el bloque `B` de índice `<i>` existe y `V.payload_hash` = SHA-256 del payload para `<i>` y `B.payload_hash` | «la anulación no corresponde al contenido del bloque <i>» |
| R4 | `B.type` **no** empieza por `nucleo.` | «no se anula un evento de Núcleo» |
| R5 | `B.tenant` = `V.tenant` | «la anulación es de otro tenant que la emisión» |
| R6 | ninguna anulación válida anterior apunta ya a `B` | estado **«anulación repetida»**, con el índice de la primera |

Cómo se aplican a los casos dudosos:
- **Una sola anulación por emisión (R6).** La segunda es hallazgo. La CLI no la sella: contesta
  `already_voided: true`, como `erase` contesta `already_erased`. Si aparece en la cadena,
  alguien la selló sin pasar por la CLI. La emisión se cuenta como anulada una sola vez, por la
  primera anulación.
- **No se anula una anulación, ni se suprime una anulación (R4).** Anular un `nucleo.void.v1` o
  un `nucleo.erasure.v1` es hallazgo. **No existe «des-anular»**: el SRI tampoco lo permite (la
  anulación es irreversible, investigación a), y un evento que deshiciera otro haría que la
  respuesta a «¿está anulada?» dependiera del orden de lectura.
- **Anular contenido ya suprimido: permitido.** La regla solo usa el índice y el hash del
  header, que siguen en la cadena aunque el contenido se haya suprimido. La reconciliación
  enseña el bloque en `erased` y en `voided`. En el orden contrario (anular y después suprimir)
  pasa lo mismo.
- **«El destino es una factura»: no es una regla del protocolo.** Núcleo no puede decidir desde
  el tipo si un registro es una factura: un integrador sella con `--type sri.factura.v1`, otro
  con `--profile ecuador.sri.factura` (tipo `ecuador.sri.factura.v1`), y otro con un tipo
  propio. El protocolo exige solo R4 (no un evento de Núcleo). Si la CLI restringe a ciertos
  tipos, es una guarda al sellar, no un hallazgo (pregunta para el dev).

*Alternativa descartada: que la segunda anulación sea inocua y se ignore.* Una cadena con dos
anulaciones de lo mismo no la produce la CLI. Ignorarla sería aceptar en silencio un bloque
`nucleo.*` que nadie debía sellar, cuando ADR-031 hizo hallazgo precisamente de eso.

### 6. `reconcile`: una lista `voided`, sin tocar el código de salida

- **Lista nueva `voided`**, con el bloque anulado y quién lo anuló:
  `{index, sealed_hash, sealed_at, voided_by, voided_at}`, donde `voided_by` es el índice de la
  anulación válida y `voided_at` su tiempo declarado. Sale en cada reconciliación, siempre: una
  anulación no caduca.
- **Una anulación válida no cambia el código de salida.** El registro anulado se reconcilia
  como cualquier otro:
  - si el sistema vivo lo tiene igual, es `verificado` y además sale en `voided`;
  - **si el ERP lo borró, sigue siendo `faltante`** (código 2), salvo que esté suprimido. El
    SRI manda conservar lo anulado siete años (RCV art. 50), y Núcleo no puede distinguir una
    factura anulada y borrada de una que se hizo desaparecer;
  - si el ERP la cambió (por ejemplo, un `estado: "anulada"` dentro del registro sellado), es
    `discrepancia`. El estado de anulación no se escribe en el registro sellado: está en el
    evento.
- **Una anulación inválida o repetida es un hallazgo**: código 2, en `findings`, con el estado
  y el motivo de la decisión 5.
- **Los propios eventos `nucleo.void.v1` no son `faltante`**: los sella Núcleo, no el sistema
  vivo, igual que los de supresión.
- **`--json` crece, sin cambiar nada de lo que ya hay**: `voided` y los dos estados nuevos.
  Ojo: un campo nuevo en la salida `--json` toca los vectores de `testdata/vectors/cli-json`,
  así que, sin permiso del dev para cambiarlos, `voided` sale solo cuando tiene algo.

*Alternativa descartada: que una anulación disculpe un `faltante`.* Es exactamente la puerta
que ADR-032 cerró para la supresión. Con la firma del tenant bastando (decisión 4), quien
tuviera el servidor borraría una factura y la «anularía» para que la reconciliación saliera
con 0. Si algún día el dev quiere esa disculpa, la anulación necesitaría la autoridad de
ADR-032, y esta ADR la desaconseja.

### 7. Lo que la anulación NO hace

- **No invalida el recibo de la emisión.** Sigue verificando, en los tres verificadores, antes
  y después de la anulación. La emisión ocurrió, y eso es lo que el recibo prueba.
- **Un recibo no demuestra que el registro no esté anulado.** Quien tiene el recibo de una
  factura no sabe, por el recibo, si después se selló su anulación: para eso necesita el
  ledger, el recibo de la anulación o al emisor. Y aunque lo supiera, la anulación de Núcleo es
  la declaración del emisor, no el estado del SRI. Es un **límite nuevo, L24** de GARANTIAS
  (propuesto).
- **No es una supresión** (L18): no borra contenido, no pide la clave de supresión y no
  disculpa un `faltante`.
- **No implementa la nota de crédito.** La nota de crédito es un comprobante propio del SRI
  (`codDoc` 04), con su clave de acceso y su firma XAdES: se sella como cualquier XML, ya hoy.
  Enlazarla con la factura que modifica (`codDocModificado`, `numDocModificado`) sería trabajo
  del perfil `ecuador`, sin evento de núcleo. **Queda fuera de la v1.** Y no anula nada en
  Núcleo: una factura corregida con nota de crédito no se marca `voided`, porque para el SRI no
  está anulada.
- **No hace cumplir plazos ni prohibiciones del SRI**: ni el día 7, ni las facturas
  «consumidor final» que no se anulan desde 2026, ni la aceptación del receptor. Núcleo no
  puede saberlo: la identificación del comprador va comprometida, y el estado vive en el SRI.
  Es responsabilidad del ERP, y la documentación de operación lo dirá.

### 8. La CLI: `nucleo void`

```
nucleo void --block N                [--policy-file P] [--json]
nucleo void --payload factura.xml    [--policy-file P] [--json]
```

- **`--block N`** anula el bloque N.
- **`--payload F`** lo busca por el SHA-256 de los bytes del fichero, que es el XML que el ERP
  ya tiene. Así el ERP no necesita guardar el índice. Si el contenido está sellado más de una
  vez, la orden falla y pide `--block` con los índices candidatos: elegir por el integrador
  sería adivinar.
- **Rechaza, sin sellar nada:**
  - un bloque `nucleo.*`, con código de uso 1;
  - un índice que no existe;
  - una emisión ya anulada: código 0 con `already_voided: true` y el índice de la anulación;
  - y un tenant que no casa.
- **Sella en una transacción**, como `erase` (ADR-020 §C).
- **Pide la passphrase, como `seal`.** No pide tarjetas ni la clave de supresión.

*Alternativa descartada: `seal --profile ecuador.sri.factura.anulacion`.* El payload no es un
documento que traiga el integrador: lo construye Núcleo. Y un tipo `nucleo.*` no se sella con
`seal`, a propósito.

**¿Tienen que entender el evento TypeScript, PHP y la página?** En la v1, no. Ellos verifican
recibos, y el recibo de una anulación es el de un bloque cualquiera: verifica sin cambios. La
comprobación de un tercero (los dos recibos y un `sha256sum`) va en PROTOCOL §5.2, como la de
la supresión. Si un integrador la necesita en un SDK, son diez líneas y se añaden entonces.
**El `Sealer` de PHP sí podría envolver `void`**: a diferencia de `erase`, anular es una
operación del ERP, no la decisión de una persona con tarjetas. Es una pregunta para el dev.

### 9. Versión de protocolo y compatibilidad: 0.9-draft, y fallar cerrado

PROTOCOL sube a **0.9-draft** con §5.2. Lo que cambia:
- registra el tipo `nucleo.void.v1`, su contenido, su `payload_cid` y las reglas R1–R6;
- añade la segunda excepción al campo aleatorio de §5.

**Ningún byte de ningún artefacto existente cambia**: ni el bloque, ni la hoja, ni el
checkpoint, ni el recibo, ni la política. No hay miembro de política nuevo, así que los SDK 0.5
siguen leyendo las políticas de la 0.6 y verificando todos sus recibos, también el de una
anulación.

**Lo que hace un binario 0.5 ante el evento.** Su `reconcile` no conoce `nucleo.void.v1`: ve un
bloque que el sistema vivo no tiene y lo da por **`faltante`**, con código 2. **Falla cerrado**,
aunque con un nombre equivocado, y eso no se puede cambiar en un binario publicado. Lo dirá el
CHANGELOG de la versión que lo implemente: después de anular con la versión nueva, no se
reconcilia con la vieja.

**Lo que hará el binario 0.6 ante un evento `nucleo.*` que no conozca** (el de una versión
futura): un hallazgo explícito, **«evento de Núcleo desconocido»**, con código 2. No se ignora en
silencio, y no se llama `faltante`. Un evento del núcleo que un verificador no entiende puede
cambiar el veredicto, así que ignorarlo es apostar a que no lo cambia, y fallar cerrado no
apuesta.

*Alternativa descartada: ignorarlo explícitamente* (código 0 con un aviso). Es cómodo para
mezclar versiones, pero convierte cada evento futuro en algo que una versión vieja da por
bueno sin entenderlo. Para la supresión habría significado aceptar sin autorización lo que
ADR-032 exige autorizar.

## Lo que NO resuelve

- **Que la anulación sea verdad en el SRI.** Es la declaración del emisor (decisión 4, L24).
- **Que un tercero con solo el recibo de la factura sepa si se anuló** (L24).
- **La nota de crédito** y su enlace con la factura (decisión 7): fuera de la v1.
- **Los plazos y las prohibiciones del SRI** (decisión 7): son del ERP.
- **Atar una constancia del SRI al evento**: no hay una firmada (SIN CONFIRMAR).

## Consecuencias

- PROTOCOL 0.9-draft, §5.2, **propuesto** en este sprint: el texto normativo queda escrito y
  marcado como no implementado. Lo normativo empieza cuando el dev acepte esta ADR.
- GARANTIAS: el límite L24, **propuesto**. L18 deja de decir «pendiente, TODO» cuando se
  implemente.
- Código, cuando se acepte, en este orden:
  1. los vectores, calculados fuera (abajo);
  2. `internal/void` (o junto a `internal/erasure`) y `internal/reconcile`;
  3. la CLI;
  4. CLI-JSON y GARANTIAS;
  5. OPERACION, con el flujo del ERP;
  6. el ensayo.
  TS, PHP y la página no cambian.
- La 0.8-draft ya no está congelada (terminó al publicar v0.5.0-alpha). Este es el único cambio
  de protocolo en curso.

## Preguntas para el dev

Lo que depende de cómo opera un ERP real, y que esta ADR no puede decidir sola:

1. **¿Cuándo sella el ERP la anulación?** La propuesta es: cuando el SRI devuelve «ANULADO». Para
   una factura es inmediato. Para la retención, la nota de crédito y la nota de débito, eso es
   después de la aceptación del receptor, y nunca en «PENDIENTE DE ANULAR». ¿Tu ERP consulta
   `consultarEstadoAutorizacionComprobante`, o solo sabe que envió la solicitud?
2. **¿Qué conoce el ERP de la emisión: el índice de Núcleo (lo da `seal --json`) o solo la clave
   de acceso y el XML?** La decisión 8 propone `--payload factura.xml` para no depender del
   índice. Si el ERP no conserva ni el XML, haría falta un índice local de clave de acceso a
   índice de bloque, en `vault_meta` y comprometido (HMAC), nunca en la cadena. ¿Hace falta?
3. **¿Tu ERP borra o modifica las facturas anuladas en su base?** Si lo hace, la reconciliación
   dará `faltante` o `discrepancia` (decisión 6), y está bien que lo dé. Pero entonces la
   documentación tiene que decir cómo dejar de hacerlo.
4. **¿Necesitáis el motivo?** La propuesta no lo lleva (decisión 3). Si un auditor lo pide, ¿basta
   con que lo guarde el ERP?
5. **¿Atar una constancia del SRI al evento?** Por ejemplo, un `evidence_index` opcional que apunte
   a un registro sellado aparte con la respuesta del SRI y su campo aleatorio. La propuesta es
   que no en la v1.
6. **¿Restringe la CLI los tipos que se pueden anular** (por ejemplo, solo
   `ecuador.sri.factura.v1` y `sri.factura.v1`), o vale cualquier tipo que no sea `nucleo.*`,
   como propone la decisión 5?
7. **¿Envuelve el `Sealer` de PHP la orden `void`?** La propuesta es que sí (decisión 8), pero
   no en la primera entrega.
8. **La nota de crédito, fuera de la v1** (decisión 7): ¿de acuerdo?
9. **SIN CONFIRMAR, para validar con un contador antes de aceptar:**
   - que no exista una constancia firmada de la anulación;
   - que no haya reformas de 2026 sobre la anulación;
   - el formato de `numDocModificado`.
