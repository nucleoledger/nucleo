# ADR-007-mldsa44-adicional

**Estado:** aceptada · **Fecha:** 2026-08-31 · **Fuentes:** docs/CONCEPTO-v1.2-es.md §9

Ademas de la firma Ed25519 obligatoria, los checkpoints llevaran una firma ML-DSA-44 (crypto/mldsa, stdlib Go 1.27) para resistencia post-cuantica. Los verificadores de notas firmadas ignoran firmas desconocidas, por lo que anadirla es retrocompatible.

## Addendum 2026-09-06 — qué quedó implementado y qué diferido

### Implementado

`internal/checkpoint` gana `MLDSASigner` y `MLDSAVerifier` (ML-DSA-44, FIPS 204,
`crypto/mldsa` de la stdlib con Go 1.27.1). Un checkpoint puede firmarse con la
Ed25519 del log y con su ML-DSA-44 en la misma nota. Las firmas son
deterministas (`SignDeterministic`), como ya lo eran las Ed25519: dos copias del
mismo checkpoint tienen que poder compararse byte a byte.

**La regla de oro está probada.** Un verificador que solo conoce la clave Ed25519
—un cliente viejo, el futuro SDK de TypeScript, cualquiera que no sepa qué es
ML-DSA— abre la nota exactamente igual e ignora la firma que no entiende. Si eso
fallara, la firma "adicional" no sería adicional: sería un cambio de formato
encubierto que dejaría fuera a todo el que no se actualizara. El test lo
comprueba en las tres direcciones: solo Ed25519, solo ML-DSA, y ambas.

Tamaños, comprobados contra la stdlib: semilla 32 bytes, pública 1312, firma
2420. Una nota con las dos firmas crece unos 2,4 kB.

### Diferido, y por qué

**El byte de algoritmo del key ID está PENDIENTE DE DECISIÓN.** No es un olvido:
el spec no lo determina.

`c2sp.org/signed-note` (sha256 `0aaa21aa…`) asigna 0x01 a Ed25519, 0x02 a ECDSA,
0x04 a las cosignatures Ed25519 con timestamp, 0x05 a los `TreeHeadSignature`,
**0x06 a las cosignatures ML-DSA-44 con timestamp**, y 0xff a los tipos "sin byte
asignado por esta especificación".

No hay byte para una firma de log ML-DSA-44 llana. El 0x06 es de cosignatures:
`c2sp.org/tlog-cosignature` lo define sobre el mensaje
`"cosignature/v1\ntime <unix>\n"` y habla de *cosigner public key*. Usarlo para
la firma del log haría que el log firmara como testigo de sí mismo, lo cual es
falso, y PROTOCOL.md §3 ya lo tiene reservado para las cosignatures ML-DSA de
testigos, que siguen sin implementarse.

Queda el 0xff, que el spec destina a este caso, pero recomienda seguirlo de "un
identificador más largo que sea improbable que colisione" sin fijar cuál. Ese
identificador sería una extensión de Núcleo, no algo que el spec determine.

Mientras tanto el byte es un parámetro con valor provisional 0xff, marcado
`// SPEC-CHECK` en `mldsa.go`, y **no hay golden del key ID**. Fijar uno ahora
repetiría el error de SC-2: un key ID equivocado que pasa los tests porque los
tests lo calculan con la misma función que verifican. Lo que sí está probado es
todo lo que no depende de ese byte.

**Las cosignatures ML-DSA-44 de testigos no entran todavía.** `c2sp.org/tlog-witness`
dice que los testigos *SHOULD* usarlas; Núcleo emite cosignatures Ed25519 (0x04).
Es una desviación consciente de un SHOULD, registrada en ADR-011.

**El checkpoint del log todavía no se emite con la segunda firma en producción.**
El mecanismo está y probado; enchufarlo a `checkpoint.Log` y a la sincronización
espera a que el byte quede decidido, porque cambiarlo después cambiaría los key
ID de claves ya publicadas.
