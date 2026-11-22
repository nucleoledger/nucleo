# La anulación de comprobantes electrónicos del SRI (investigación, noviembre de 2026)

**Para qué:** la base normativa de [ADR-035](../adr/ADR-035-anulacion-de-facturas.md). **No es
texto legal ni una opinión legal**: es lo que dicen las fuentes oficiales citadas, leídas el
**2026-11-22**. Lo que no se pudo confirmar en una fuente oficial va marcado **SIN CONFIRMAR —
validar con contador**, y la ADR no diseña sobre ello como si fuera un hecho.

**Las tres fuentes de fondo** —leídas enteras; las citas de las dos resoluciones se cotejaron
contra el texto extraído de sus PDF—: la Resolución **NAC-DGERCGC25-00000014**, su reforma
**NAC-DGERCGC25-00000017** y la **Ficha técnica de comprobantes electrónicos, esquema offline,
versión 2.34** (julio de 2026). La guía del SRI para contribuyentes sobre la anulación (marzo de
2025) vale para la mecánica del portal, **no para los plazos**: cita aún los 90 días del art. 7
de la NAC-DGERCGC16-00000092, que la 25-00000014 derogó (Disposición Reformatoria Segunda).

**SIN CONFIRMAR — validar con contador:** que no haya una reforma de 2026 sobre la anulación. No
se encontró ninguna, pero no se revisó el Registro Oficial de 2026 entero.

## a) Cómo se anula hoy un comprobante autorizado

- **Por dónde.** En línea, en el portal del SRI (SRI en línea → Facturación electrónica →
  Producción o Pruebas → Anulación), o en el Facturador SRI si el comprobante se emitió ahí.
  25-00000014, art. 2: «La anulación en línea podrá realizarse a través del portal web
  institucional o el Facturador SRI, cuando la emisión se haya realizado en este aplicativo.»
- **Por qué medio, según el documento.** Art. 2: «La anulación de comprobantes de venta
  electrónicos se realizará en línea o mediante la emisión de una nota de crédito. La anulación
  de comprobantes de retención y documentos complementarios electrónicos se realizará
  exclusivamente en línea.»
- **Quién la pide.** El emisor. Guía, §1.2.1: la opción «permite al contribuyente emisor
  registrar la solicitud de anulación». Pide el tipo de comprobante, la fecha de autorización,
  la clave de acceso, el número de autorización, la identificación del receptor «exactamente
  como consta en XML» y su correo. **No pide un motivo.**
- **Plazo.** Hasta el **día 7 del mes siguiente** al de la emisión, o el siguiente día hábil si
  cae en descanso o feriado. Lo fija el art. 3 de la 25-00000014, cuyo «el día 10» sustituyó la
  25-00000017 (art. 1, lit. a) por «el día 7 (siete)». Se aplica a lo emitido desde el
  **2025-08-01** (Disposición Transitoria que añadió la 25-00000017). Hay dos excepciones: las
  retenciones del art. 26 del Reglamento del ISD, que no tienen este plazo, y los lotes de más
  de 1.000 comprobantes del mismo mes, que se anulan por trámite (Disposición General Cuarta).
- **¿Tiene que aceptarla el receptor? Depende del documento:**
  - **Factura, guía de remisión y liquidación de compra: no.** La anulación es inmediata. Guía,
    §1.2.1: «al presionar el botón Aceptar, la anulación se ejecutará y no será necesario ningún
    proceso posterior.»
  - **Retención, nota de crédito y nota de débito: sí.** 25-00000014, art. 4: «el receptor
    dispondrá de un plazo de 5 días hábiles a partir de la fecha de la solicitud de anulación,
    para aceptarla o rechazarla. En caso de no recibir respuesta dentro de dicho plazo, la
    solicitud quedará sin efecto y se mantendrá la validez del comprobante electrónico.»
    Mientras tanto, el comprobante está **«PENDIENTE DE ANULAR»** y conserva su validez
    tributaria (guía, §1.2.1). No hace falta la aceptación si el receptor tiene identificación
    del exterior o consta como fallecido (25-00000017, art. 1, lit. b).
- **¿Hay que acordarla antes con el receptor?** Ninguna norma lo exige. Sí obliga a avisarle
  después: la 25-00000014, Disposición Reformatoria Primera, añade al art. 5 de la
  NAC-DGERCGC18-00000233: «Los emisores de comprobantes electrónicos deberán informar a los
  receptores de dichos comprobantes cualquier modificación que se realice al estado del
  comprobante electrónico.»
- **Es irreversible.** Lo dicen la guía (§1.2.2, «Este proceso es irreversible») y sus notas
  aclaratorias (punto 9).

## b) Qué queda como constancia

- **El estado del comprobante**, consultable en el servicio web
  `consultarEstadoAutorizacionComprobante`, que según la Ficha técnica v2.34 §8.4 devuelve
  «"AUTORIZADO", "NO AUTORIZADO", "PENDIENTE DE ANULAR" o "ANULADO"». El portal añade las
  consultas de «comprobantes anulados» y «pendientes de anular», con un reporte descargable.
- **Una notificación** en el buzón del contribuyente y un correo, al emisor y al receptor, al
  pedir la anulación y al contestarla (guía, §1.2.1 y §1.2.2.1.1).
- **SIN CONFIRMAR — validar con contador: un XML, acuse o PDF firmado de la anulación.** Ni la
  guía ni la ficha describen ninguno, y probablemente no existe. Tampoco se pudo confirmar si la
  respuesta del servicio web va firmada. La ADR no se apoya en ninguna constancia firmada del SRI.
- **Conservar lo anulado.** El RCV, art. 50, citado en los considerandos de las dos
  resoluciones: los comprobantes «emitidos con errores y que hayan sido anulados, deberán ser
  conservados por siete años en los archivos del contribuyente». No se consultó el texto del
  RCV directamente.

## c) Cuándo ya no se anula y procede una nota de crédito

- **Pasado el plazo**, solo los comprobantes de venta tienen salida. 25-00000014, art. 3:
  «Superado este plazo, los comprobantes de venta electrónicos se podrán anular únicamente
  mediante el uso de notas de crédito». Las retenciones y los documentos complementarios no
  tienen esa vía.
- **El tope de 12 meses ya no existe.** El art. 5 que redactó la 25-00000017 dice: «Las notas
  de crédito deberán emitirse únicamente en los casos señalados en el Reglamento de Comprobantes
  de Venta, Retención y Documentos Complementarios.»
- **Lo que no admite ni anulación ni nota de crédito:**
  - **Las facturas «consumidor final», desde el 2026-01-01.** Art. 3, último inciso, cuya
    vigencia aplazó la 25-00000017 (lit. f): «no se podrán anular una vez emitidas y
    transmitidas al Servicio de Rentas Internas. En estos casos, no procede la emisión de notas
    de crédito.»
  - Las facturas comerciales negociables ya negociadas (Disposición General Segunda).
  - Los comprobantes que sustentan una devolución de impuestos (Disposición General Tercera).
- **La nota de crédito** es un comprobante propio, `codDoc` 04, con su clave de acceso. Ficha
  v2.34, `<infoNotaCredito>`: `codDocModificado` (obligatorio, 2 dígitos, `01` = factura),
  `numDocModificado` (obligatorio, `estab-ptoEmi-secuencial`), `fechaEmisionDocSustento`
  (obligatorio, dd/mm/aaaa), `motivo` (obligatorio, texto libre de hasta 300 caracteres) y
  `valorModificacion`. **SIN CONFIRMAR:** el formato exacto de `numDocModificado`. La ficha lo
  declara «Numérico 15», pero su ejemplo lleva guiones; hay que cotejarlo con el XSD.
- **Para Núcleo, una nota de crédito es un documento más**, firmado por el emisor y con su
  propia clave de acceso. Se sella como cualquier XML del SRI: no es un evento de Núcleo.

## d) ¿Cambia por ambiente o por tipo de emisión?

- **Ambiente.** El menú de anulación existe en Producción y en Pruebas (guía, §1.1). Ficha, §4:
  «los comprobantes emitidos en ambiente de pruebas no tendrán ninguna validez tributaria, ni
  legal». **SIN CONFIRMAR — validar con contador:** que los plazos sean distintos en Pruebas; no
  se encontró ninguna regla aparte.
- **Tipo de emisión.** Solo existe la normal, `1`. Ficha, nota de la tabla 2: «Para el método de
  autorización offline, solo existe el tipo de emisión normal.» La contingencia se eliminó en la
  versión 2.0 de la ficha (2015-08-05).
- **Tipo de documento.** Es lo que sí cambia; ver a) y c).

## e) La clave de acceso (confirmada: Ficha v2.34 §5.2, tabla 1)

Fecha ddmmaaaa (1–8) · tipo de comprobante (9–10) · RUC (11–23) · ambiente (24) · serie,
establecimiento y punto de emisión (25–30) · secuencial (31–39) · código numérico (40–47) · tipo
de emisión (48) · dígito verificador módulo 11 (49). Es lo mismo que fija
`profiles/ecuador/clave.go`. La clave es además el número de autorización.

## Lo que esto significa para el diseño (lo usa ADR-035)

1. **Lo que se anula está en el SRI, no en Núcleo.** Un evento de anulación de Núcleo es una
   **declaración del emisor**, sellada y fechada; no certifica el estado del SRI.
2. **Para una factura no hay estado intermedio**: está autorizada o anulada. Para la retención,
   la nota de crédito y la nota de débito sí lo hay, «PENDIENTE DE ANULAR», y la solicitud
   puede caducar. Solo tiene sentido sellar la anulación **cuando el SRI dice «ANULADO»**.
3. **El SRI no pide motivo para anular.** El motivo solo es obligatorio en la nota de crédito,
   que es otro documento.
4. **No hay una constancia firmada del SRI que sellar** (SIN CONFIRMAR). Una constancia que no
   esté firmada, como la respuesta del servicio web o el correo, contiene la clave de acceso:
   su hash desnudo confirmaría una clave adivinada.
5. **Lo anulado se conserva siete años** (RCV art. 50). Un ERP no debería borrar la factura
   anulada de su base, y una factura que desaparece sigue siendo un `faltante`.

## Fuentes

Oficiales, consultadas el 2026-11-22:

1. Resolución NAC-DGERCGC25-00000014 (SRI), firmada el 2025-06-27; Registro Oficial 70, tercer
   suplemento, 2025-06-30; aplicable desde el 2025-08-01. El PDF del SRI, en la copia de la
   UTPL:
   <https://procuraduria.utpl.edu.ec/NormativaExterna/RESOLUC%C3%93N%20SRI%20%20%20NAC-DGERCGC25-00000014.pdf>.
   Figura también en el índice de <https://www.sri.gob.ec/facturacion-electronica>.
2. Resolución NAC-DGERCGC25-00000017 (SRI), 2025-07-29, que reforma la anterior. El PDF del SRI,
   en la copia de Fielweb:
   <https://www.fielweb.com/App_Themes/InformacionInteres/NAC-DGERCGC25-00000017.pdf>.
3. Ficha técnica de comprobantes electrónicos, esquema offline, versión 2.34 (SRI, julio de
   2026):
   <https://www.sri.gob.ec/o/sri-portlet-biblioteca-alfresco-internet/descargar/f8d9bb36-5632-4f96-b463-b9265b55338c/FICHA%20TE%cc%81CNICA%20COMPROBANTES%20ELECTRO%cc%81NICOS%20ESQUEMA%20OFFLINE%20Versio%cc%81n%202.34.pdf>.
4. Guía para contribuyentes: anulación de comprobantes electrónicos (SRI, actualizada en marzo de
   2025): sirve para la mecánica, no para los plazos:
   <https://www.sri.gob.ec/o/sri-portlet-biblioteca-alfresco-internet/descargar/c97242e6-c271-4eb8-8f6a-f687313118ba/Guia%20para%20contribuyentes%20de%20anulaci%c3%b3n%20de%20comprobantes%20electr%c3%b3nicos.pdf>.
5. Página de Facturación electrónica del SRI: <https://www.sri.gob.ec/facturacion-electronica>.
6. gob.ec, trámite «Anulación de comprobantes electrónicos» (actualizado el 2025-06-23):
   <https://www.gob.ec/sri/tramites/anulacion-comprobantes-electronicos>.
7. gob.ec, trámite «Confirmar anulación de comprobantes electrónicos» (actualizado el
   2022-03-10): <https://www.gob.ec/sri/tramites/confirmar-anulacion-comprobantes-electronicos>.

Secundarias, solo como contexto; ninguna afirmación de arriba se apoya solo en ellas: NMS Law,
«Anulación de comprobantes electrónicos: régimen vigente… desde 2026»
(<https://nmslaw.com.ec/?p=15928>, no se pudo leer: HTTP 429); Sovos
(<https://sovos.com/mx/blog/iva/anulacion-de-comprobantes-electronicos-en-ecuador/>); las alertas
fiscales de EY de julio y agosto de 2025.
