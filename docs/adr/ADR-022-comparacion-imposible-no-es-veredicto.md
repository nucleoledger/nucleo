# ADR-022-comparacion-imposible-no-es-veredicto

**Estado:** ACEPTADA el 2026-09-18 por el dev (Sprint 8) · **Fecha:** 2026-09-18 · **Fuentes:** auditoría externa hallazgo H7 (`internal/store/integrity.go:415-435`); ADR-016 (la atestación al abrir), ADR-017 (la política como raíz de confianza), ADR-009 (`vault_meta` es mutable por diseño)

## El hallazgo, reproducido

`checkLogKey` compara la identidad que trae la política —`origin` y la clave del log—
con la que el ledger declara en `vault_meta`. Cuando esos metadatos no estaban, la
función devolvía `nil`.

Eso convierte "no pude comparar" en "la comparación no presenta problema", que es
exactamente el patrón que ADR-016 cerró en la atestación —donde "hay una nota" se
reportaba como "un tercero avala esta historia"—, en otro sitio del mismo fichero.

Y es explotable, no teórico, porque `vault_meta` es **mutable por diseño**: no lleva los
disparadores append-only del ledger, a propósito, porque guarda parámetros de derivación
que cambian. Quien pueda escribir el fichero puede borrar dos filas.

Comprobado quitando el arreglo y volviendo a correr el test (`internal/store/h7_test.go`):

```
ledger de 5 bloques, sin checkpoints, política de la víctima con la clave de OTRO log

sin log/pubkey/v1              → ABRE, sin un solo error   ← el agujero
sin log/pubkey/v1 y log/origin/v1 → ABRE, sin un solo error   ← el agujero
sin log/origin/v1              → ErrLogKeyMismatch: la comparación que SÍ se podía
                                 hacer seguía cazando la política ajena
```

El caso peor es sin checkpoints, y por eso el test los quita: con ellos, la atestación al
menos degrada a "presente, no verificada", porque `logPolicy` falla al no encontrar la
clave. Sin ellos no quedaba ninguna señal.

## Decisión

**Una política que AFIRMA una identidad y un ledger que no declara la suya es un error de
integridad** (`ErrIdentityUnknown`, código 2 en la CLI), con el nombre de la fila que
falta en el mensaje.

Lo que **no** cambia: una política que no afirma nada no tiene nada que comparar. Con
`--witness-name` y `--witness-key` sueltas no viajan ni el origin ni la clave del log, y
entonces no hay pregunta que contestar. La diferencia es quién se queda callado: antes
callaba el ledger ante una pregunta; ahora solo calla quien no preguntó.

Por qué se puede fallar cerrado sin romper a nadie: `nucleo init` escribe
`log/pubkey/v1`, `log/origin/v1` y `log/signer-pubkey/v1` desde que existen, así que
**todo** ledger creado por una versión publicada las declara. Un ledger que no las declara
es uno al que alguien se las quitó.

## Consecuencias

- Un ledger sustituido al que le hayan borrado los metadatos ya no abre limpio bajo la
  política de la víctima: lo dice, y con código 2.
- Un ledger de desarrollo anterior a `vault_meta` —si queda alguno— deja de abrir **con
  política**. Sin política abre igual que antes. Es el precio y es pequeño.
- El mensaje nombra la fila que falta, porque el arreglo del usuario legítimo es distinto
  según cuál sea, y porque un error que no dice qué buscar se resuelve adivinando.

## Alternativas descartadas

- **Avisar por stderr y seguir.** Es lo que hacía, escrito de otra manera: el aviso se
  pierde en un log y el veredicto sigue siendo "abre". Un cron no lee avisos.
- **Reconstruir la identidad del ledger desde el primer bloque o desde el checkpoint.**
  Sería comparar la política contra lo que el propio fichero afirma de sí mismo, que es
  la circularidad que ADR-017 cerró. El ledger es fuente de COMPARACIÓN, nunca raíz de
  confianza.
- **Escribir los metadatos que falten al abrir.** Abrir no escribe, y menos la identidad:
  el primero que abriera un ledger sustituido le pondría la identidad de la víctima.
