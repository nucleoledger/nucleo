# ADR-003-compromisos-vrf-hmac

**Estado:** aceptada · **Fecha:** 2026-08-31 · **Fuentes:** docs/CONCEPTO-v1.2-es.md §9

Los datos adivinables nunca se comprometen como hash desnudo. VRF vrf-r255 (RFC 9381 style) cuando se requiera verificabilidad por terceros sin revelar la clave; HMAC-SHA-256 con clave del tenant para lo interno. Blobs cifrados borrables satisfacen supresion LOPDP; redaccion oficial: disenado para alinearse, nunca certificado sin dictamen.

---

## Enmienda 2026-09-07 — verificabilidad no es privacidad

El texto de arriba ofrece VRF y HMAC como dos opciones para lo mismo, a elegir
según haga falta «verificabilidad por terceros». El spike de ADR-012 midió el
VRF y demostró que **no son dos formas de lo mismo**: dan propiedades distintas,
y una de ellas es peor en privacidad que la otra.

Esta enmienda corrige esa lectura y fija la regla que se deriva de ella. La
decisión original —los datos adivinables nunca se comprometen como hash desnudo—
se mantiene intacta.

### Lo que se midió

Un compromiso VRF se verifica con la clave **pública**: cualquiera que tenga la
prueba `pi` puede comprobar si un valor candidato la satisface, sin conocer la
clave privada del tenant. Eso es exactamente lo que se buscaba, y también es el
problema, porque «cualquiera» incluye a quien quiera adivinar el valor.

Verificar cuesta 199 µs. Los datos que este proyecto compromete viven en
espacios diminutos:

| dato | espacio de búsqueda | un núcleo | cien núcleos |
|---|---:|---:|---:|
| cédula ecuatoriana (provincia 01–24, tercer dígito < 6, verificador determinado por los otros nueve) | 1,4 × 10⁸ | 8 h | **5 min** |
| importe entre 0 y 100.000,00 | 10⁷ | 33 min | ~20 s |

Con HMAC y clave secreta ese ataque no existe: sin la clave no se puede computar
ningún candidato, y el tamaño del espacio deja de importar.

### La regla

**El compromiso que va al ledger es, y seguirá siendo, HMAC-SHA-256 con clave
por tenant.** No es una decisión provisional a la espera del VRF: es la que
protege el dato.

**La prueba VRF nunca va en el ledger.** El ledger se publica, se replica y se
entrega a testigos; poner ahí una prueba VRF sería autorizar a todo el que lo lea
a atacar por fuerza bruta cada campo sensible. Si algún día se emiten pruebas
VRF, `beta` podrá registrarse pero `pi` vive fuera, cifrada en el vault.

**El VRF queda como revelación selectiva, fuera del ledger.** Su caso es
concreto: un auditor o una contraparte que necesita comprobar UN registro sin
recibir la clave con la que se comprometió todo lo demás. Entregar una prueba es
autorizar a esa persona a atacar por fuerza bruta ese campo y solo ese, lo cual
es aceptable cuando es deliberado —es justo a quien se le quiere demostrar el
valor— y nunca como efecto secundario de publicar algo.

**El diseño de esa revelación está pendiente y tendrá su propio ADR** cuando haya
un caso real que lo pida. Hoy no lo hay. Ver ADR-012 para la evaluación de la
biblioteca, las cifras completas y el obstáculo que no se ha resuelto:
ristretto255 no está en WebCrypto, así que el verificador de TypeScript
necesitaría su primera dependencia de runtime.

### Corrección de la hoja de ruta

`docs/CONCEPTO-v1.2-es.md` §17 describe el Sprint 5 como «Perfil Ecuador (VRF en
campos sensibles)». Eso se escribió antes de medir. El perfil Ecuador se entregó
con compromisos **HMAC**, y así se queda: la medición dice que para proteger un
dato adivinable el VRF es la herramienta equivocada.

