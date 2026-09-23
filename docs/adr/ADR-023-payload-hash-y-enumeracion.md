# ADR-023-payload-hash-y-enumeracion

**Estado:** ACEPTADA el 2026-09-18 por el dev (Sprint 8) · **Fecha:** 2026-09-18 · **Fuentes:** [auditoría externa del 2026-09-13](../auditoria-externa-20260913.md) hallazgo H10; ADR-003 (compromisos VRF/HMAC), PROTOCOL.md §1 y §5, `profiles/ecuador/tipos.go`

## El hallazgo, reproducido

El header del bloque publica `payload_hash`: el SHA-256 de los bytes exactos del
documento. El header viaja **dentro de cada recibo**, así que no es un dato del fichero
local: lo tiene toda contraparte a la que se le entrega un recibo.

Un documento de baja entropía se recupera de ahí por enumeración. Con el binario real:

```
documento sellado : {"estado":"aprobado"}
payload_hash      : a79d21e038a049d4ae9b7fcb8bae5925a5191752dadc35f8898e9b81a92941dc
espacio           : la plantilla conocida × cuatro valores
resultado         : RECUPERADO al primer intento
```

Y lo que la auditoría no dijo, que es lo más incómodo: **el `payload_hash` puede derrotar
a los compromisos por campo**. ADR-003 pone la cédula, la razón social y el importe de una
factura como compromisos HMAC precisamente porque un hash desnudo de esos campos se
invierte con una lista. Pero si el documento ENTERO es enumerable, adivinarlo confirma de
golpe todos sus campos, comprometidos incluidos. La protección por campo no sube el listón
por encima de la entropía del documento completo.

El caso concreto que hay en este repositorio: el payload de `sas.acta.v1` —razón social,
fecha de junta, tipo de acta, lista de socios— sale de datos que están en el registro
mercantil. No es un ejemplo inventado. (Ese perfil vive en `profiles/` y `seal --profile`
todavía no lo expone; cuando lo exponga, esto es un requisito, no un consejo.)

## Decisión

### A. `payload_hash` sigue siendo el SHA-256 desnudo de los bytes exactos

No se cambia por un HMAC ni por un compromiso VRF, y la razón no es la compatibilidad:

Es lo ÚNICO que permite a quien recibe un recibo atar **su** documento al registro sin
ninguna clave, sin PKI y sin red. Recomputa el SHA-256 del fichero que tiene y lo compara
con el del header. Con un HMAC, ese verificador necesitaría la clave del emisor —o sea,
confiar en el emisor y guardar un secreto—, y la propiedad central del producto
—"un verificador no necesita nada más que el recibo y su política"— desaparece.

Un compromiso VRF tampoco: ADR-003 ya decidió que la verificabilidad por terceros no da
privacidad, y publicar la prueba de un valor de baja entropía lo vuelve enumerable otra
vez. El problema se movería, no se iría.

### B. La enumerabilidad es una propiedad del DOCUMENTO, y se dice así

Se escribe en PROTOCOL.md §5, en normativo, lo que antes solo se insinuaba:

- `payload_hash` **confirma una conjetura** del documento completo;
- el ledger **no oculta** un payload enumerable, lo guarde cifrado o no —el blob cifrado
  protege el contenido de quien lee la base, no del que tiene el recibo—;
- los compromisos por campo **no cubren** este caso: si el documento entero se adivina,
  sus campos comprometidos se adivinan con él.

### C. La entropía la pone quien escribe el documento, y Núcleo no la añade nunca

Núcleo hashea los bytes exactos que recibe (§5) y **no puede** añadirles nada: añadir un
nonce sería sellar algo distinto de lo que el integrador entregó, y el recibo dejaría de
atar el fichero que esa persona tiene en la mano.

Así que el remedio es del emisor, y funciona hoy sin una línea de código nueva:

```
documento : {"estado":"aprobado","nonce":"15deca904a6c8fa18caa5ded52aa6e90"}
enumeración con la plantilla conocida : falla
el destinatario, que TIENE el documento : lo ata byte a byte
```

Dieciséis bytes aleatorios dentro del payload bastan. La contraparte no nota la
diferencia, porque verifica con el documento, no con el espacio de documentos posibles.

**Para los perfiles que Núcleo escriba, esto es normativo**: un perfil que construya el
payload tiene que incluir un campo aleatorio de al menos 16 bytes. Para los payloads que
el integrador trae ya hechos —el XML del SRI, un PDF— es documentación: la entropía es
suya, y este ADR dice dónde mirar.

## Consecuencias

- Las afirmaciones publicadas se enmiendan donde están: PROTOCOL.md §5 (normativa),
  README (que ya se corrigió a medias tras la cuarta auditoría y le faltaba la mitad de
  los compromisos por campo) y CHANGELOG.
- Un integrador que sella documentos de plantilla —resoluciones, estados, aprobaciones—
  tiene una instrucción concreta en vez de una garantía falsa.
- Ningún cambio de formato: ni el header, ni la hoja, ni el recibo, ni los vectores, ni
  los tres verificadores. PROTOCOL sube a 0.5-draft por el texto normativo nuevo de §5,
  no por un cambio de bytes.
- Lo que sigue siendo verdad y conviene no perder de vista: quien no tiene el documento
  **ni puede adivinarlo** no aprende nada del `payload_hash`. La decisión no es "esto da
  igual", es "esto depende de una propiedad que el protocolo no controla y ahora lo dice".

## Alternativas descartadas

- **HMAC o VRF en el `payload_hash`.** Decisión A: mata la verificación sin claves, que
  es el producto.
- **Que Núcleo añada el nonce al sellar.** Decisión C: sellaría un documento distinto del
  que el integrador tiene. El recibo dejaría de atar su fichero, que es lo único que el
  recibo hace por él.
- **Publicar un hash truncado** (por ejemplo 16 bytes). No sube ningún listón frente a la
  enumeración —el atacante prueba igual— y baja el de las colisiones.
- **Un aviso en `seal` cuando el documento parece enumerable.** No se puede decidir desde
  los bytes: `{"estado":"aprobado"}` y una nota privada de veinte caracteres son
  indistinguibles para el sellador. Un aviso que se equivoca en las dos direcciones
  enseña a ignorar los avisos.
