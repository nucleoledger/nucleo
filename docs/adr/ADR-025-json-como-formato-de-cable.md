# ADR-025-json-como-formato-de-cable

**Estado:** ACEPTADA el 2026-09-22 por el dev (Sprint 9) · **Fecha:** 2026-09-22 · **Fuentes:** [revisión externa, por un modelo, del 2026-09-19](../revision-externa-modelo-20260919.md), hallazgo medio (`SealResult::fromJSON` con casts laxos y defaults silenciosos); ADR-018 (la política como formato de cable), ADR-020 §E (ningún error del motor llega al usuario), ADR-021 (el SDK de PHP), `docs/CLI-JSON.md`

## El hallazgo, y la causa que lo explica

`SealResult::fromJSON()` leía la salida de la CLI con `(int)`, `(string)`, `(bool)` y
valores por omisión. Si faltaba `index`, quedaba `-1`; si faltaba `encrypted`, `attested`
o `freshness.stale`, quedaban `false`. Un binario antiguo, truncado, equivocado o
sustituido producía un objeto PHP **aparentemente utilizable**.

El síntoma es del SDK de PHP. La causa es de más arriba: **la salida `--json` de la CLI
es un formato de cable y no había recibido el trato que ADR-018 dio a la política.** La
consumen el SDK de PHP, los crons de los integradores y cualquier ERP. Tenía documento
—`docs/CLI-JSON.md`— pero no tenía ni parseo estricto ni vectores compartidos, que son
las dos cosas que convierten un documento en un contrato.

La diferencia no es teórica. Con la política, el mismo texto pasa por tres lectores
estrictos y por 9.929 vectores; con el JSON, el productor escribía lo que quería y el
consumidor aceptaba lo que llegara.

## Decisión

### A. `docs/CLI-JSON.md` es NORMATIVO, y la gramática vive ahí

No en PROTOCOL.md, y la razón importa: PROTOCOL describe los artefactos
criptográficos —lo que se firma, lo que viaja entre partes que no se conocen— y un
verificador de otro lenguaje tiene que poder implementarlo sin saber que existe una CLI.
La salida `--json` es el contrato de **este producto** con quien lo automatiza. Son dos
cosas distintas y mezclarlas haría de PROTOCOL un manual de usuario.

Lo que CLI-JSON.md ya decía y ahora es norma: los campos documentados no se renombran ni
cambian de tipo sin una entrada en el CHANGELOG; **se pueden añadir** campos nuevos; quien
parsea **debe ignorar** los que no conoce.

### B. El consumidor falla CERRADO

El SDK de PHP lee el contrato con un lector estricto (`Nucleo\Contract`), no con casts:

| regla | qué hace |
|---|---|
| campo obligatorio ausente | **excepción** (`SealContractError`), nunca un valor por omisión |
| tipo equivocado | **excepción**: `index` tiene que ser entero de verdad, no `"0"` ni `0.5`; un booleano tiene que ser booleano, no `"true"` ni `1` |
| hash o clave | exactamente 64 caracteres `[0-9a-f]`; en minúscula, como fija CLI-JSON.md |
| `attestation` | uno de `none`, `unverified`, `verified`, y nada más |
| `duplicate_of` | lista de enteros ≥ 0, o ausente; nunca `array_map('intval', …)` sobre lo que venga |
| `freshness`, `signer` | objetos, con sus propios campos obligatorios |
| campo desconocido | **se ignora**, que es la otra mitad de la regla de compatibilidad |
| stdout que no es JSON | excepción con los primeros bytes de lo que llegó, para poder diagnosticar |

Sin defaults no hay `-1` que confundir con un índice, ni `false` que confundir con "no
atestiguado". Un ERP que reintenta sobre un `SealResult` construido a partir de basura es
un ERP que cree tener un registro sellado.

### C. Vectores compartidos: Go los produce, PHP los consume

`testdata/vectors/cli-json/`. Los válidos los **emite la CLI de verdad** —un test de
`cmd/nucleo` corre las escenas con reloj y semilla fijos y guarda su stdout literal—; los
inválidos están **escritos a mano**, porque son precisamente lo que la CLI nunca produce.

Esa asimetría es deliberada y no viola la regla anti-circularidad. Aquí el vector no
certifica un cálculo criptográfico —eso lo hacen los vectores de recibo, con su oráculo
independiente—: certifica un CONTRATO entre dos programas. El productor es la definición
de lo que se produce; lo que hay que comprobar es que el consumidor acepta todo lo válido
y rechaza todo lo demás. Y el test de Go los regenera y compara, así que si la CLI cambia
un campo, el vector cambia, la suite de PHP lo ve y alguien tiene que decidir si era
intencionado.

### D. Lo que NO se hace

- **No se añade un campo de versión al JSON.** El conjunto de campos obligatorios ya es
  la comprobación de versión: un binario anterior al Sprint 8 no trae `idempotent` y el
  contrato lo rechaza con su nombre. Un `"contract": 1` en cada objeto sería más explícito
  y cambia la salida de todos los subcomandos; queda anotado como paso posible el día que
  haya más de un consumidor externo.
- **No se valida el JSON en el productor contra un esquema.** Los tests de `cmd/nucleo`
  ya afirman campo por campo, y los vectores de este ADR son la red que cierra el círculo.
  Un validador de esquema en Go sería una tercera descripción del mismo contrato.

## Consecuencias

- Un binario equivocado, truncado o antiguo da **excepción tipada**, no un objeto con
  ceros. Es lo que un producto de integridad debe hacer con un contrato inesperado.
- El SDK de PHP gana `Nucleo\Contract` y `Nucleo\SealContractError`; `status()` también
  pasa por el contrato, no solo `seal()`.
- Los vectores hacen visible en la suite de PHP cualquier cambio de la salida de la CLI.
  Antes, la única forma de enterarse era que a alguien se le rompiera el cron.
- Coste: un campo obligatorio nuevo en la CLI rompe a los SDK que no lo conozcan hasta
  que se actualicen. Es el precio de fallar cerrado y es el correcto para esto: la
  alternativa es lo que había, donde el SDK seguía adelante con un `false` inventado.

## Alternativas descartadas

- **Dejar los casts y documentar "usa un binario de la misma versión".** Es pedirle al
  integrador que garantice lo que el software puede comprobar por sí mismo.
- **Validar con un esquema JSON en PHP.** Una dependencia nueva en un paquete cuyo
  argumento es no tener ninguna (ADR-021 §D), para validar diez campos.
- **Aceptar `"0"` y `1` como entero y booleano.** Es la tolerancia que produce dos
  representaciones de lo mismo, la misma que ADR-018 cerró en la política. El productor
  es un solo programa y emite JSON canónico: no hay nada que tolerar.
- **Que `fromJSON` devuelva null en vez de lanzar.** Un null que nadie mira es un default
  silencioso con otro nombre.
