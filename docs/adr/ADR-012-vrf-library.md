# ADR-012-vrf-library

**Estado:** PROPUESTA, pendiente de decisión del dev · **Fecha:** 2026-09-07 · **Fuentes:** ADR-003, PROTOCOL.md §5, `c2sp.org/vrf-r255`, RFC 9381

ADR-003 dejó dos vías para los compromisos: HMAC-SHA-256 con clave del tenant
para lo interno, y **VRF `vrf-r255` cuando se requiera verificabilidad por
terceros sin revelar la clave**. La primera está implementada (`internal/commit`,
Sprint 5). Este ADR evalúa la segunda. **No se añade ninguna dependencia.**

## El caso que motiva el VRF

Un auditor —o la contraparte de una factura, o un perito— quiere comprobar que el
compromiso registrado corresponde a la cédula `1712345678`. Con HMAC **no puede**:
verificar exige exactamente la misma clave que comprometer, así que el tenant
tendría que entregarle su clave, y con ella el auditor podría verificar todos los
demás compromisos del ledger, no solo el que le interesa.

Un VRF rompe esa disyuntiva: quien tiene la clave privada produce una prueba, y
cualquiera con la **clave pública** puede verificarla.

## La biblioteca

`filippo.io/mostly-harmless/vrf-r255`, implementación de la ciphersuite
ECVRF-RISTRETTO255-SHA512 de `c2sp.org/vrf-r255` (estilo RFC 9381).

| dato | valor |
|---|---|
| versión disponible | `v0.0.0-20260904084346-d3c4507858ea` — **pseudo-versión, sin release etiquetado** |
| licencia | MIT (© 2022 M Ember Mou) |
| tamaño | 312 líneas en `vrf.go`, 36 KB de módulo |
| dependencias | `github.com/gtank/ristretto255` (56 KB) → `filippo.io/edwards25519` (248 KB) |
| vectores | el test incluye el vector oficial de `C2SP/C2SP/vrf-r255.md` |
| API | `GenerateKey`, `NewPrivateKey`, `Prove(alpha) *Proof`, `PublicKey.Verify(p, alpha) (beta, error)`, `Proof.Hash()` |

La API es minúscula y encaja con lo que hace falta: cuatro tipos, sin opciones
que configurar mal.

## Medido en el spike

Ejecutado fuera del repositorio, sobre esta máquina:

| | VRF | HMAC-SHA-256 |
|---|---:|---:|
| comprometer | 154,5 µs | 2,97 µs |
| verificar | 199,1 µs | ~3 µs |
| tamaño del compromiso | 80 B (prueba) + 64 B (hash) | 32 B |
| clave privada / pública | 32 B / 32 B | 32 B / — |

**52× más lento comprometer** y **4,5× más grande**. Para un sellado por factura,
154 µs es irrelevante. Lo que sí importa es lo de abajo.

Comprobado además: la prueba y el hash son **deterministas** —dos ejecuciones
sobre el mismo valor dan los mismos bytes—, lo cual es indispensable para un
compromiso, y un valor distinto **no verifica** contra una prueba ajena.

## El hallazgo que decide el diseño

**Publicar la prueba VRF convierte el compromiso en atacable por fuerza bruta.**

Con HMAC, un atacante sin la clave no puede computar candidatos: el diccionario
no sirve, y eso es todo lo que hay que decir. Con VRF, cualquiera que tenga la
prueba y la clave pública puede probar valores llamando a `Verify`, a 199 µs cada
intento. Y los datos que se comprometen tienen espacios diminutos:

| dato | espacio | un núcleo | 100 núcleos |
|---|---:|---:|---:|
| cédula ecuatoriana (provincia 01–24, tercer dígito <6, verificador determinado) | 1,4 × 10⁸ | 8 h | **5 min** |
| importe entre 0 y 100.000,00 | 10⁷ | 33 min | ~20 s |

Es decir: **el VRF no da privacidad frente a quien tiene la prueba.** Da
verificabilidad. Son cosas distintas y ADR-003 no las separa con suficiente
claridad.

La consecuencia de diseño es concreta: **la prueba VRF no puede ir en el ledger**.
Lo que se registra es `beta` (el hash); la prueba `pi` se guarda aparte y se
entrega **solo al tercero que deba verificar ese registro concreto**. Entregar
una prueba es autorizar a esa persona a atacar por fuerza bruta ese campo, y solo
ese. Eso es aceptable —es justamente a quien se le quiere demostrar el valor—
mientras la entrega sea deliberada y no un efecto secundario de publicar el log.

## Qué ganaría el perfil Ecuador

1. **Un auditor puede comprobar una factura concreta** sin recibir la clave con
   la que se comprometió todo lo demás. Hoy la única forma es entregarle la
   clave del tenant, que es entregarle el ledger entero.
2. **Una contraparte puede comprobar que la factura que tiene en la mano es la
   que se selló**, con el recibo y la prueba, sin llamar a nadie.
3. **No hace falta confiar en el emisor** para creerse el compromiso, que es la
   misma propiedad que ya dan los testigos para el tiempo.

## Riesgos

- **Sin release etiquetado.** Una pseudo-versión de un repositorio llamado
  *mostly-harmless* no es un compromiso de estabilidad. Se puede fijar la
  pseudo-versión exacta, igual que se hizo con SLIP-0039, pero conviene saber
  que no hay promesa de compatibilidad.
- **Dos dependencias transitivas más**, aunque pequeñas y de la misma familia
  (`filippo.io/edwards25519` ya es de facto estándar en el ecosistema Go).
- **La ciphersuite `vrf-r255` es un draft de C2SP**, no un RFC. Su formato podría
  cambiar, y con él los compromisos ya emitidos.
- **Complejidad conceptual.** Explicar a un usuario cuándo entregar una prueba y
  qué implica hacerlo es más difícil que explicar una clave secreta.

## Recomendación

**Adoptarlo, pero no todavía, y no como sustituto.**

El HMAC de `internal/commit` cubre el caso interno y debe quedarse: es más
rápido, más pequeño, no añade dependencias y —esto es lo importante— da una
privacidad que el VRF no da. El VRF resuelve un caso distinto y real, pero que
hoy nadie ha pedido: no hay todavía un auditor externo pidiendo verificar una
factura concreta.

Cuando llegue ese caso, el diseño debería ser:

1. `internal/commit` gana un segundo esquema, `vrf-r255/v1`, junto al existente.
   El prefijo del algoritmo ya viaja en cada compromiso justamente para esto.
2. En el ledger se registra `beta`; `pi` vive fuera, en el vault, cifrada.
3. `nucleo prove --block N --field cedula` emite la prueba para entregarla, y la
   documentación explica en una frase qué autoriza esa entrega.
4. El verificador de TypeScript necesitaría ristretto255, que **no está en
   WebCrypto**: sería la primera dependencia de runtime del SDK, o unas 400
   líneas de aritmética propia. Esto merece su propia decisión y probablemente
   sea el argumento más fuerte para esperar.

## Lo que este ADR NO decide

No se añade ninguna dependencia. `go.mod` queda intacto hasta que el dev apruebe
esta propuesta o elija otra cosa.
