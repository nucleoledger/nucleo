# ADR-007-mldsa44-adicional

**Estado:** aceptada · **Fecha:** 2026-08-31 · **Fuentes:** docs/CONCEPTO-v1.2-es.md §9

Ademas de la firma Ed25519 obligatoria, los checkpoints llevaran una firma ML-DSA-44 (crypto/mldsa, stdlib Go 1.27) para resistencia post-cuantica. Los verificadores de notas firmadas ignoran firmas desconocidas, por lo que anadirla es retrocompatible.

## Addendum 2026-09-06 — la extensión 0xff, decidida y fijada

### La decisión

La firma ML-DSA-44 del log usa el **mecanismo de extensión** de
`c2sp.org/signed-note`: byte de tipo `0xff` seguido de un identificador largo
propio. El key ID queda FIJADO así:

```
keyID = SHA-256( <name> || "\n" || 0xff || "nucleoledger.com/sig/ml-dsa-44@v1"
                 || "\n" || <clave pública ML-DSA-44 de 1312 bytes> )[:4]
```

**Este formato no se cambia sin rotar la clave.** El key ID identifica la clave
en cada línea de firma: tocarlo convierte en ilegibles todas las firmas ya
emitidas con ella. Un cambio aquí es una rotación de identidad, no un ajuste.

El identificador largo va **dentro** del hash, no solo detrás del byte de tipo.
Sin eso, dos extensiones distintas que compartieran el `0xff` producirían el
mismo key ID para la misma clave, y el propósito del identificador —evitar
colisiones— se perdería justo donde importa. Hay un test de control que lo
comprueba.

### Fundamento

**No hay byte asignado para una firma de log ML-DSA-44 llana.** `signed-note`
asigna `0x01` a Ed25519, `0x02` a ECDSA, `0x03` reservado, `0x04` a las
cosignatures Ed25519 con timestamp, `0x05` a los `TreeHeadSignature`, `0x06` a
las cosignatures ML-DSA-44 con timestamp, `0xfa`–`0xfe` reservados, y `0xff` a
los tipos *"sin byte asignado por esta especificación"*.

**El `0x06` se rechazó por semántica.** Es de COSIGNATURES:
`c2sp.org/tlog-cosignature` lo define sobre el mensaje
`"cosignature/v1\ntime <unix>\n"` y habla de *cosigner public key*. Usarlo para
la firma del log haría que el log firmara como testigo de sí mismo, lo cual es
falso; y PROTOCOL.md §3 ya lo tiene reservado para las cosignatures ML-DSA de
testigos, que llegarán.

**Rotación prevista.** Si C2SP asigna algún día un byte a las firmas de log
ML-DSA-44, Núcleo migrará a él. Eso cambiará los key ID, así que será una
rotación de clave con su propio ADR, no una edición de este.

### Estado

| | |
|---|---|
| firma del log | Ed25519 (`0x01`) **+ ML-DSA-44** (extensión `0xff`), las dos en la misma nota |
| cosignatures de testigo | Ed25519 (`0x04`) |
| cosignatures ML-DSA-44 de testigo | no implementadas |

`checkpoint.Log.AddSigner` mete la segunda firma en todos los checkpoints que
emite el log, así que los checkpoints reales ya salen con las dos.

Las cosignatures del testigo siguen siendo Ed25519. `c2sp.org/tlog-witness` dice
que los testigos *SHOULD* usar ML-DSA-44: es una **desviación consciente de un
SHOULD**, ya registrada en ADR-011. Cuando entren, el key ID usará el `0x06` que
el spec sí asigna y que PROTOCOL.md §3 tiene reservado.

### Retrocompatibilidad: la propiedad que lo permite todo

Un verificador que solo conoce la clave Ed25519 —un cliente viejo, el futuro SDK
de TypeScript, cualquiera que no sepa qué es ML-DSA— abre la nota exactamente
igual e ignora la firma que no entiende. Está probado en las tres direcciones
—solo Ed25519, solo ML-DSA, ambas— y sobre checkpoints REALES emitidos por
`checkpoint.Log`, no solo sobre notas armadas en un test.

Si esto fallara, la firma "adicional" no sería adicional: sería un cambio de
formato encubierto que dejaría fuera a todo el que no se actualizara.

### Los goldens se calcularon fuera del código

El key ID se fija con valores calculados por un script de **python3 con
hashlib**. Un programa Go aparte vuelca solo las claves públicas de semillas
deterministas —volcar una clave no es calcular un key ID— y python concatena los
bytes y hashea sin saber nada de `MLDSAKeyHash`. Tres goldens: `5fa5e8ea`,
`7c30f8b0` y `75c04ba5`.

Aquí la regla anti-circularidad importaba más que en ningún otro sitio: la
lección de SC-2 fue exactamente esta, un key ID equivocado que pasó todos los
tests porque los tests lo calculaban con la misma función que verificaban.

### Tamaños

Semilla 32 bytes, clave pública 1312, firma 2420 (comprobados contra
`crypto/mldsa`). Una nota con las dos firmas del log crece unos 2,4 kB.

`crypto/mldsa` **no está disponible bajo el módulo FIPS 140-3 v1.0.0**. Si alguna
vez se compila con `GOFIPS140`, la firma ML-DSA fallaría.

### Adición al esquema, pendiente de recoger en ADR-009

Cerrar el hueco entre firmar y cosignar exigió una tabla nueva,
`log_state(k, v)`, donde el log guarda el último checkpoint que firmó antes de
salir a buscar la cosignature. Es una adición pura —`CREATE TABLE IF NOT EXISTS`,
sin tocar tablas ni disparadores existentes, sin migración de datos— pero
**ADR-009 dice que cambiar el esquema exige un ADR nuevo**, y queda anotado aquí
a la espera de que el dev decida cómo recogerlo.
