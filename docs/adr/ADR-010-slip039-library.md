# ADR-010-slip039-library

**Estado:** propuesta — pendiente de aprobación del dev · **Fecha:** 2026-09-05
**Fuentes:** ADR-004, PROTOCOL.md §6, spike ejecutado fuera del repositorio

## Contexto

ADR-004 fija SLIP-0039 para respaldar la KEK, umbral 2-de-3 por defecto. Hay que
elegir biblioteca. **Ninguna dependencia se ha añadido al repositorio**: el spike
se ejecutó en un módulo aparte y `go.mod` sigue sin tocarse.

Los 45 vectores oficiales se descargaron del repositorio canónico de Trezor
(`python-shamir-mnemonic/vectors.json`, sha256
`13ebecebdd869dd2bc2cdf69e7ce3a158cf106cac76c39d17682b1c6cdabbdc4`), **no** de
los `testdata/` que cada biblioteca trae consigo. Dejar que cada candidata se
corrija con sus propios vectores no habría probado nada: es la regla
anti-circularidad aplicada a la elección de dependencias.

## Comparativa

| Criterio | gavincarr/go-slip39 v0.1.3 | shurlinet/go-slip39 v0.1.0 |
|---|---|---|
| Vectores válidos recuperados | **15/15** | **15/15** |
| Vectores negativos rechazados | **30/30** | **30/30** |
| Total oficial | **45/45** | **45/45** |
| Tiempo de los 45 | 553 ms | **124 ms** (4,5×) |
| Round-trip 2-de-3 sobre KEK de 32 B | correcto | correcto |
| Módulos externos | **4**: `golang-set/v2`, `x/crypto`, `x/exp`, `gonum` | **1**: `x/crypto` |
| Paquetes no estándar compilados | 6 | 3 |
| Peso del cierre | +19 MB solo de `gonum` | 320 KB |
| Licencia | MIT | MIT (+ Apache 2.0 por el GF(2⁸) de Trezor) |
| Líneas de código | 3.568 | 5.036 |
| API | `GenerateMnemonicsWithPassphrase` + `MemberGroupParameters`; también shares etiquetadas | `Split`/`Combine` con opciones funcionales |
| Higiene de canal lateral | no declarada | GF(2⁸) bitsliced en tiempo constante (traducido del firmware Trezor), zeroing explícito, `subtle.ConstantTimeCompare` |
| Procedencia | autoría humana | **generada por IA (Claude) con revisión humana declarada** |

Ambas son correctas contra el estándar. La diferencia está en el resto.

## Lo que pesa de verdad

**`gonum` en la ruta de respaldo de claves.** Es el dato más incómodo del
spike: `gavincarr` arrastra una biblioteca de cálculo científico de 19 MB para
partir un secreto de 32 bytes. No es solo peso: es superficie de suministro y de
auditoría en el componente cuyo fallo es más caro de todos.

**La procedencia de `shurlinet`.** Su README lo declara sin rodeos: *"The AI
generated code; the human made every design decision, reviewed every line, and
owns every bug"*. Hay que ponderarlo, y también hay que decir lo que sigue: quien
escribe este ADR es una IA evaluando una biblioteca criptográfica generada por
IA. No es una descalificación mutua, pero sí un conflicto que corresponde nombrar
en vez de disimular, y una razón más para que la decisión final sea del dev.

Contra esa procedencia juegan además la versión (v0.1.0) y la adopción escasa.
A favor, que el algoritmo es cerrado y está completamente especificado, que pasa
los 45 vectores oficiales igual que la alternativa humana, y que su
documentación de seguridad es notablemente más concreta.

## Recomendación

**`shurlinet/go-slip39`, con dos condiciones**, o `gavincarr` si prefieres
priorizar la procedencia humana por encima del cierre de dependencias. Es una
decisión de riesgo, no técnica: las dos son correctas.

Condiciones si se adopta `shurlinet`:

1. **Round-trip obligatorio antes de enseñar las tarjetas.** Tras partir la KEK,
   recombinarla en el acto con el umbral mínimo y comparar con la original. El
   respaldo se hace una vez por tenant: el coste es irrelevante y convierte
   cualquier fallo del lado del `Split` en un error visible antes de que nadie
   escriba nada en papel.
2. **Los 45 vectores oficiales entran en `testdata/vectors/slip39/`** y se
   ejecutan en CI contra la biblioteca elegida, sea cual sea. Así la decisión es
   reversible: cambiar de biblioteca pasa a ser cambiar un import y volver a
   pasar el mismo banco.

Un matiz que reduce el peor escenario, y que este sprint acaba de asegurar: la
DEK se envuelve con XChaCha20-Poly1305, que es autenticado. Una KEK mal
restaurada **no descifra en silencio**: falla ruidosamente. El modo de fallo de
un error en la recombinación es "no puedo restaurar", no "restauré otra cosa".
Sigue siendo grave, pero es detectable, que es justo la propiedad que faltaba en
la lección de la semilla silenciosa.

## Lo que este ADR NO decide

No se añade ninguna dependencia. `go.mod` queda intacto hasta que apruebes esta
propuesta o elijas la alternativa.

## Addendum 2026-09-06 — auditoría externa y una corrección de dato

La dependencia se aprobó con la condición de aislamiento: `shurlinet/go-slip39`
v0.1.0 fijada, importada solo en `internal/vault/backup.go`, con
`TestSlip39StaysBehindTheVault` haciéndolo cumplir. Los 45 vectores oficiales
están en `testdata/vectors/slip39/` y se ejecutan en nuestra suite.

### Corrección de dato: la personalización de RS1024

La cadena de personalización canónica del checksum RS1024 es **`"shamir"`**, y
**`"shamir_extendable"`** para los mnemónicos con el bit de backup extensible.
Donde este ADR o mis notas dijeran otra cosa, manda esto. No cambia ninguna
decisión —la biblioteca elegida pasa los 45 vectores oficiales, incluidos los
cuatro extensibles— pero un dato equivocado en un ADR se propaga a quien lo lea
después, así que queda corregido aquí.

### BAJO — el contrato de `RestoreKEK`

`RestoreKEK` prueba la consistencia interna del conjunto de shares, **no** su
pertenencia a este vault. Un respaldo válido de otra KEK se restaura sin un solo
error, y debe hacerlo: matemáticamente es un secreto correcto y SLIP-0039 no
tiene forma de saber de qué vault salió. Quien pare ahí cifrará bajo una clave
equivocada.

La identidad la prueba el segundo paso, que no es opcional: `UnwrapDEK` contra
la DEK envuelta de este vault, cuyo envoltorio es autenticado y cuyo AAD lleva
el identificador del vault. Documentado en el doc-comment y probado en las dos
direcciones.

### Laxitud conocida: `groupIndex` en go-slip39

La biblioteca no valida el `groupIndex` con el rigor que el spec permitiría.
**No se le ha encontrado ruta de explotación** en el uso que hace Núcleo, que es
el más simple posible: un solo grupo, umbral k de n, y toda la superficie
encapsulada tras `BackupKEK`/`RestoreKEK`. Un `groupIndex` inconsistente entre
shares acaba en un secreto que no reconstruye, y ahí espera `UnwrapDEK`, que
falla ruidosamente.

Queda anotado porque es exactamente el tipo de laxitud que importa si algún día
se usan varios grupos, y porque es un argumento más para mantener el
aislamiento: cambiar de biblioteca sigue siendo tocar un fichero.

### Condición 1: CERRADA el 2026-09-06

La condición 1 de este ADR —round-trip obligatorio antes de enseñar las
tarjetas— **está implementada**. `BackupKEK` recombina los shares recién
generados y los compara con la KEK original antes de devolverlos; si difieren,
devuelve error y no entrega nada.

Se prueban **n ventanas circulares de k shares**, no una sola, de modo que cada
share participa en al menos una reconstrucción. Verificar un único subconjunto
dejaría fuera a los shares no incluidos, y un share corrupto entre ellos pasaría
el control para reaparecer años después: justo el fallo que la condición existe
para impedir.

