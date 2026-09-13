# ADR-018-politica-formato-de-cable

**Estado:** ACEPTADA el 2026-09-12 por el dev (Sprint 7e) · **Fecha:** 2026-09-12 · **Fuentes:** tercera auditoría adversarial 2026-09-12 (hallazgos ALTO #1, MEDIO #4 y #5, BAJO #6, #7 y #8), ADR-002, ADR-016, ADR-017, PROTOCOL.md §3, `golang.org/x/mod/sumdb/note` v0.40.0 (`Open`), `sdk/ts/src/note.ts`, `sdk/ts/src/receipt.ts`

## Los hallazgos

La tercera auditoría no encontró ningún fallo nuevo en los bytes del recibo: 2.269
mutaciones del CI y 132 más de la auditoría, cero divergencias. Todo lo que encontró
estaba **al lado** del recibo, en dos sitios que el proyecto trataba como datos
sueltos y no como formatos:

**La política.** ADR-017 la hizo raíz de confianza única, y su parseo se quedó en
"lo que haga `encoding/json`" en Go y "lo que haga `JSON.parse`" en TypeScript.
El mismo fichero —`"signerKey": A, "signerkey": B`— da la clave B a la CLI (Go
empareja claves sin distinguir mayúsculas y gana la última) y la clave A a la
página. Una política sin testigos da "✔ Recibo válido" en los tres verificadores,
aunque D.3 ya había declarado que una política que no verifica nada es un error.
Una misma clave bajo dos nombres cuenta dos veces para el quórum. El `origin` del
fichero no se coteja al abrir el ledger.

**El bloque de firmas de la nota.** Go delega en `x/mod`, que descarta una firma
repetida de una clave conocida **antes de verificarla** y se queda con la primera.
TypeScript cuenta cada línea. Resultado: un emisor con un solo testigo cómplice
duplica su línea, vuelve a firmar el recibo y cumple un quórum 2-de-2 en la página.
Y con dos cosignatures genuinas del mismo testigo, Go muestra la primera y TS la más
temprana: uno acepta y el otro rechaza el mismo recibo.

El diferencial no podía ver nada de esto: muta los bytes del recibo **sin volver a
firmarlo** —así que cualquier cambio en la nota rompe la firma del emisor en los dos
lados— y nunca muta la política.

## Decisión

La política y el bloque de firmas de la nota son **formatos de cable**, y reciben el
mismo trato que el header JCS o las líneas base64: una gramática estricta escrita en
PROTOCOL.md, la misma en Go y en TypeScript, vectores compartidos y diferencial.

### A. La política (PROTOCOL.md §3.2)

Un documento JSON (RFC 8259) en UTF-8, sin BOM, de como mucho 64 KiB, cuyo único
valor es un objeto:

| clave | tipo | regla |
|---|---|---|
| `origin` | cadena | obligatoria, no vacía |
| `logKey` | cadena | obligatoria, exactamente 64 caracteres `[0-9a-f]` |
| `signerKey` | cadena | opcional **en el formato**; obligatoria para verificar un recibo (ADR-017) |
| `witnesses` | objeto | obligatorio, al menos una entrada; cada nombre no vacío; cada valor, 64 `[0-9a-f]`; **ninguna clave repetida bajo dos nombres** |
| `quorum` | entero | obligatorio; literal JSON sin fracción ni exponente; `1 ≤ quorum ≤ len(witnesses)` |

Y es error, en cualquier nivel del documento:

- una clave de objeto **repetida**, comparada tras decodificar los escapes;
- una clave desconocida, **incluidas las variantes de mayúsculas** de una conocida
  (`signerkey`, `LogKey`): no son claves desconocidas inocentes, son la forma exacta
  del ataque #4;
- `null` en lugar de cualquier valor;
- cualquier cosa distinta de espacio en blanco JSON después del objeto.

Las claves en hexadecimal van en **minúsculas**. `sync` siempre las ha emitido así;
aceptar las dos grafías sería una segunda representación del mismo documento, que es
lo que C.3 prohibió para el recibo.

Una política sin testigos o con `quorum < 1` **no es una política de recibos**. No
existe modo "sin testigos" por omisión. Si alguna vez hace falta —un emisor que
quiere dar recibos antes de tener testigo—, será una bandera explícita con su propio
nombre en el formato, y un ADR; nunca el valor que sale de olvidar un campo.

Consecuencia: la línea `TIEMPO DEMOSTRABLE: SIN TIEMPO DEMOSTRABLE` no puede aparecer
en un recibo válido bajo 0.3-draft. Se conserva en el formato porque la derivación del
texto es la misma función en todas las versiones.

### B. El bloque de firmas de la nota (PROTOCOL.md §3.3)

Un verificador de Núcleo NO delega la lectura de las líneas de firma. Las reglas
son las de `x/mod` endurecidas donde `x/mod` es laxo, y el endurecimiento es el
mismo en los dos lenguajes:

1. La nota es UTF-8 válido sin caracteres de control salvo `\n`. El texto y las
   firmas se separan por la **última** `\n\n`; el bloque de firmas no está vacío y
   termina en `\n`.
2. **Toda** línea del bloque es `— <nombre> <base64>`. Una línea que no lo es
   invalida la nota (TS la saltaba).
3. El nombre no está vacío, no contiene `+` ni espacio Unicode (el conjunto de
   `unicode.IsSpace` de Go, enumerado en PROTOCOL.md).
4. El base64 es estándar y **canónico** (`x/mod` usa el decodificador no estricto) y
   decodifica a 5 bytes o más; los 4 primeros son el key ID.
5. Como mucho 100 líneas de firma.

### C. Cómo cuentan las firmas (PROTOCOL.md §3.3)

- Una línea cuyo (nombre, key ID) corresponde a una clave de la política —la del log
  o la de un testigo— **tiene que verificar**. Si una sola no verifica, la nota es
  inválida, aunque haya otra línea de la misma clave que sí. `x/mod` no verifica las
  repeticiones; Núcleo sí.
- Un testigo cuenta **una vez** para el quórum, tenga las líneas que tenga.
- El tiempo de un testigo es el de su cosignature **más temprana** entre las que
  verifican, y el tiempo demostrable es el mínimo entre testigos (ADR-002). Se
  descarta "la primera línea", que es lo que hace `x/mod`: convierte el orden de las
  líneas —que elige el emisor— en la fecha del recibo.
- Las líneas de claves desconocidas se ignoran (c2sp.org/signed-note).

### D. La política al abrir el ledger

- `--policy-file ""` es error de uso. Una variable de entorno vacía en un cron no puede
  degradar en silencio a "sin política".
- El `origin` del fichero se coteja con el que declara el ledger, igual que `logKey`.
- Un fichero con permisos distintos de `0600` y `0644` produce un aviso por stderr (no
  en Windows, donde esos bits no significan lo mismo). No es un error: la política no
  es secreta, pero quien pueda escribirla decide qué se verifica.

### E. Vectores y diferencial

- `testdata/vectors/policy/`: textos de política exactos con su veredicto (válida o
  inválida y por qué), escritos a mano **a partir de esta tabla**, no generados por el
  código que los lee. Los leen el parser de Go, el del SDK y el del bundle de la página.
- `testdata/vectors/receipt/`: `invalido-cosignature-duplicada` (política 2-de-2, una
  línea duplicada, recibo re-firmado) y `valido-dos-cosignatures-mismo-testigo` (dos
  tiempos; vale el más temprano).
- El diferencial pasa a tener **tres catálogos**: mutaciones de bytes (el de 7c),
  mutaciones de nota **re-firmadas por el emisor** —duplicar, reordenar, injertar y
  quitar líneas, y volver a llamar a `receipt.Sign`— y mutaciones de la política.

## Alternativas descartadas

- **Seguir usando `encoding/json` y comprobar después.** Cuando `Unmarshal` devuelve,
  la clave duplicada ya se ha perdido: no hay "después" en el que mirarla. Hay que leer
  el flujo de tokens.
- **Deduplicar como `x/mod`, quedándose con la primera línea.** Cierra el quórum pero
  deja la fecha en manos del orden de las líneas.
- **Aceptar hexadecimal en mayúsculas "por robustez".** Robustez para un formato que
  solo emite nuestro propio `sync` es una segunda representación sin usuario.
- **Un modo sin testigos implícito con `quorum: 0`.** Es exactamente el valor que
  produce olvidar el campo.

## Consecuencias

- **Ruptura en el verificador, no en el recibo.** Ningún recibo emitido por la CLI deja
  de verificar: todos llevan al menos una cosignature y líneas canónicas. Lo que deja de
  aceptarse son **políticas**: sin `quorum`, con `quorum: 0`, sin testigos, con claves
  en mayúsculas o con claves repetidas. PROTOCOL.md pasa a 0.3-draft.
- El vector `cosignature-no-confiable` usaba una política sin testigos; pasa a usar una
  con un testigo que no cosignó, y su motivo pasa a ser el quórum.
- El parser de la política deja de vivir en `cmd/nucleo` y pasa a `internal/policy`,
  para que los vectores y el diferencial lo ejerzan sin pasar por la CLI.
