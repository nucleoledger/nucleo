# ADR-024-material-mldsa-de-los-vectores

**Estado:** ACEPTADA el 2026-09-18 por el dev (Sprint 8) · **Fecha:** 2026-09-18 · **Fuentes:** [revisión externa, por un modelo, del 2026-09-13](../revision-externa-modelo-20260913.md) hallazgo H9 (la independencia de los golden), cerrado en dos pasos: el oráculo Python del Sprint 7f y este ADR; ADR-007 (ML-DSA-44 adicional), `testdata/vectors/receipt/generar.py`, `internal/receipt/vectors_export_test.go`

## El problema

La regla del proyecto dice que todo valor golden se calcula FUERA del código bajo prueba.
El Sprint 7f la hizo cierta para los recibos escribiendo un oráculo Python independiente…
con una excepción: `valido-firma-mldsa-del-log` lo seguía generando Go **entero**, porque
lleva una firma ML-DSA-44 y no hay ML-DSA en la caja de herramientas del oráculo.

Es decir: un vector completo —la nota, el árbol, la hoja, el texto legible, la firma del
emisor— salía del paquete que ese vector verifica. La firma ML-DSA era la razón, pero la
circularidad se comía el fichero entero.

## Decisión

**El oráculo construye el vector completo y PRESTA solo los bytes que no puede calcular.**

`testdata/vectors/receipt/material/mldsa.json` lleva 1312 bytes de clave pública y 2420
de firma, en hexadecimal, generados por `internal/checkpoint.MLDSASigner` de forma
determinista. Todo lo demás del vector lo produce `generar.py` como el de los otros
diecisiete, **incluido el key ID de la propia línea ML-DSA**, que recompone desde la
especificación: `SHA-256(nombre ‖ "\n" ‖ 0xff ‖ "nucleoledger.com/sig/ml-dsa-44@v1" ‖ "\n" ‖ pub)`.

Y el oráculo comprueba la precondición que no puede verificar: que la firma prestada sea
sobre **exactamente** el cuerpo de nota que él produce. Si la escena cambia, el material
caduca y el oráculo lo dice con las dos órdenes que hay que ejecutar, en vez de escribir
un vector cuya firma no corresponde a su nota.

Por qué es aceptable prestar justo esos bytes: **ningún verificador los comprueba**. Lo
que el vector demuestra es que los tres verificadores IGNORAN una firma adicional del log
sin listarla como clave desconocida y sin cambiar el veredicto (ADR-007). Los valores de
los que depende esa demostración —el nombre, el key ID, el tamaño de 2420 bytes y la
posición de la línea— los calcula el oráculo.

La comprobación de que el cambio no movió nada: el vector que salió del oráculo es **byte
a byte** el que generaba Go. Eso valida de paso el key ID, el orden de las líneas y la
firma del emisor sobre el recibo con la línea ML-DSA dentro.

## Consecuencias

- Los 18 vectores de recibo salen del oráculo, y `generar.py --check` los cubre todos
  (antes 17 de 18). La regla anti-circularidad ya no tiene excepciones de fichero: tiene
  una excepción de 3732 bytes que nadie verifica, escrita donde vive.
- La huella de `TestMain` incluye `material/`, así que una suite que reescribiera el
  material hundiría la ejecución igual que si reescribiera un vector.
- La regeneración es de dos pasos y está documentada en `testdata/vectors/README.md`. Es
  más incómoda que antes, y a cambio el oráculo no se cree nada de lo que Go le da salvo
  los bytes que no puede producir.
- Queda una dependencia nueva y pequeña en el test de regeneración: ejecuta `python3`
  para preguntarle al oráculo qué firmar. Está detrás de su variable de entorno y no
  corre en el CI; copiar el cuerpo a mano habría sido la alternativa, y es justo donde se
  cuela una divergencia.

## Alternativas descartadas

- **Implementar ML-DSA-44 en Python dentro del oráculo.** Sería escribir criptografía
  nueva —FIPS 204— para un fichero de test, sin vectores propios que la respalden, y
  contra la regla criptográfica del proyecto. Un oráculo con un bug de Dilithium es peor
  que ningún oráculo.
- **Instalar una biblioteca PQ (`dilithium-py`, `liboqs`, OpenSSL 3.5).** Es una
  dependencia nueva y no está aprobada; el OpenSSL de esta máquina es 3.0.2, que no la
  trae. Si algún día entra una, este ADR se revisa y el material desaparece.
- **Rellenar la línea con 2420 bytes aleatorios.** El oráculo podría producirlos y el
  vector seguiría probando lo mismo HOY, porque nadie verifica esa firma. Se descarta
  porque hornea la suposición "nadie la verificará nunca": el día que Núcleo verifique su
  propia firma ML-DSA en el camino del recibo, un vector con ruido dentro pasaría de ser
  golden a ser mentira, y sin avisar. Prestar una firma real mantiene el vector honesto
  para ese día.
- **Quitar el vector.** Es el único que cubre ADR-007 de punta a punta en los tres
  verificadores, incluida la fila que la página enseña.
