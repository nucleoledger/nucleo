# ADR-019-resolucion-temporal

**Estado:** ACEPTADA el 2026-09-13 por el dev (Sprint 7f) · **Fecha:** 2026-09-13 · **Fuentes:** cuarta auditoría adversarial —la primera externa, GPT-6 vía OpenCode, solo lectura sobre el HEAD público `1c53e1c`— hallazgo H4.1 (crítico); ADR-002, ADR-014, ADR-015, PROTOCOL.md §1 y §4, `internal/ledger/block.go:79`, `internal/receipt/format.go:19` y `:169-170`, `sdk/ts/src/receipt.ts:601-620`

## El hallazgo, reproducido

Un ledger nuevo, el binario de **producción**, un testigo local y un recibo real:

```
timestamp firmado en el header : 2026-09-13T20:02:35.76868538Z
texto visible del recibo       : TIEMPO DECLARADO  : 2026-09-13T20:02:35Z
```

`ledger.NewHeader` firma `time.RFC3339Nano`, que conserva la fracción de segundo.
`receipt.Format` imprime el texto legible con un layout de segundos, así que **borra la
fracción**; `renderHeader` de TypeScript reimprime el literal del header, con fracción.
El texto que Go compone y el que TypeScript espera no coinciden, y el recibo se rechaza
por la regla de igualdad byte a byte del encabezado (PROTOCOL.md §3.1).

Veredictos sobre el MISMO recibo, emitido hoy por la CLI:

| verificador | veredicto |
|---|---|
| Go (`internal/receipt`) | **acepta** |
| SDK `@nucleoledger/verify` | **rechaza**: "el texto del recibo no coincide con lo que dice la prueba" |
| página `web/verify` (bundle) | **rechaza**, lo mismo |

No es un caso de borde: ocurre siempre que el reloj no cae en un segundo exacto, es
decir, casi siempre. El diferencial no lo vio porque sus recibos golden los produce una
escena de test cuyo reloj está fijado a un segundo entero.

## Decisión

### A. Núcleo firma tiempos con resolución de SEGUNDO

Todo timestamp que entre en material firmado se escribe en RFC 3339 con `Z` y **sin
fracción**: `2026-09-13T20:02:35Z`. `ledger.NewHeader` trunca antes de firmar.

Por qué el segundo y no el milisegundo:

- Es el dominio que ya comparten las tres implementaciones. Las cosignatures de
  `tlog-cosignature@v1` llevan el tiempo en **segundos Unix** (ADR-002), y el tiempo
  demostrable —que es el que prueba algo— ya vive ahí. Firmar los bloques con más
  resolución que la atestación es precisión que ninguna prueba respalda.
- El texto legible del recibo lleva segundos desde la primera versión publicada.
- `Date` de JavaScript llega al milisegundo, no al nanosegundo: cualquier resolución
  mayor obliga a un verificador de TypeScript a tratar el tiempo como texto opaco, y
  eso es justo lo que produjo este fallo.

Lo que se pierde: ordenar dos bloques sellados dentro del mismo segundo por su
timestamp. No importa, y conviene decir por qué: el orden del log **no** lo da el
reloj, lo da `index` con `prev_hash` (PROTOCOL.md §1). El timestamp es tiempo
DECLARADO; usarlo para ordenar sería justo la confusión que ADR-002 prohíbe.

### B. El texto visible transporta el literal del header, sin reformatear

Las tres implementaciones imprimen el timestamp **tal como está en el header**, sin
parsearlo y volver a formatearlo. Go deja de normalizar.

Esto es lo que hace que un ledger con bloques fraccionarios —los que la CLI selló hasta
hoy— siga sirviendo: **re-emitir** el recibo de uno de esos bloques produce un documento
que verifica en los tres, porque los tres imprimen la misma fracción que está en el
header. Comprobado sobre el ledger de la reproducción:

```
recibo RE-EMITIDO del bloque con fracción: Go ✔  SDK ✔  página ✔
TIEMPO DECLARADO  : 2026-09-13T20:02:35.76868538Z
```

Lo que NO arregla, y hay que decirlo: un fichero de recibo **ya entregado** a un tercero
lleva impresa la línea truncada que escribió el Go anterior, y esa línea no se deriva de
su header bajo ninguna de las dos reglas. Antes lo aceptaba Go y lo rechazaban los otros
dos; ahora lo rechazan los tres. Es peor para ese fichero y mejor para el sistema: un
recibo que un verificador acepta y otro rechaza es la ambigüedad que este proyecto
persigue; tres veredictos iguales, aunque sean negativos, son un estado que se puede
razonar. El emisor conserva el bloque y puede re-emitir. Es asumible porque `v0.1.0-alpha`
no tiene despliegues conocidos ni recibos de terceros; con usuarios reales, esta decisión
habría exigido un periodo de doble aceptación.

Es además la misma regla que C.3 (Sprint 7c) impuso a la parte de máquina: no se
normaliza lo que se compara: se compara lo que llegó. Reformatear un campo firmado es
inventar una segunda representación del mismo dato, y dos representaciones acaban
siempre en dos verificadores que no opinan lo mismo.

### C. Qué exige y qué acepta un verificador

- **Al sellar**, un timestamp con fracción es un error: lo rechaza `ledger.Seal`, que
  es la puerta por la que entra material NUEVO. No lo rechaza `Header.Validate`, porque
  esa misma función la llaman `Block.Verify` y el renderizado del recibo: ponerlo ahí
  invalidaría al verificar los recibos que la parte B viene a salvar.
- **Al verificar**, un header con fracción se acepta. Rechazarlos invalidaría los
  recibos ya entregados a terceros, que son correctos en todo lo demás y que la parte B
  hace verificables por igual en las tres implementaciones. La fracción es una
  desviación del emisor, no una manipulación: está dentro de la firma y dentro de la
  hoja.
- El timestamp tiene que ser RFC 3339 en UTC terminado en `Z`, con o sin fracción. Un
  desplazamiento horario (`+02:00`) no se acepta en ningún caso: dos textos para el
  mismo instante es, otra vez, dos representaciones.

## Alternativas descartadas

- **Milisegundos.** Acerca el dominio a JavaScript pero no lo cierra —`Date` redondea—,
  y sigue siendo más resolución que la de la atestación.
- **Que TypeScript trunque al renderizar.** Convierte al verificador en reformateador
  del dato firmado: el mismo error, con el signo cambiado, y con TypeScript teniendo
  que replicar el formateo de Go exactamente.
- **Rechazar al verificar los headers con fracción.** Mata recibos ya emitidos para
  ganar una pureza que la parte B da gratis.
- **Dejarlo como está y documentarlo.** Es un recibo real rechazado por el verificador
  que el propio README ofrece a la contraparte.

## Consecuencias

- PROTOCOL.md pasa a **0.4-draft**: cambia lo que se emite (§1, resolución del
  timestamp) y se hace normativa la regla de renderizado literal (§3.1).
- Los ledgers existentes siguen abriendo y verificando: la continuidad, las firmas y las
  raíces no dependen del formato del timestamp. Lo que caduca son los FICHEROS de recibo
  emitidos antes de este cambio, que ahora rechazan los tres verificadores en vez de uno;
  se re-emiten desde el mismo bloque.
- Vectores nuevos: un recibo golden con timestamp fraccionario —el caso "recibo ya
  emitido"— que los tres verificadores tienen que aceptar, y los bordes
  (`...T00:00:00Z`, `...T23:59:59Z`, `.000000001Z`, `.999999999Z`) en los tests de
  frontera del header.
- `ledger.Seal` gana una comprobación, así que un ledger con bloques fraccionarios que
  alguien quiera EXTENDER verá el rechazo en el bloque siguiente, no en los que ya
  tiene. Es correcto: el bloque nuevo es material nuevo.
