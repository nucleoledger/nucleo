# Shared test vectors

Cross-language ground truth. Every implementation (Go core, TS/PHP/Python verifiers)
MUST reproduce these byte-for-byte. Changing anything here requires an ADR.

- jcs/       RFC 8785 vectors (official RFC examples + Nucleo cases), read by both
             internal/jcs and sdk/ts
- merkle/    RFC 6962 roots and proofs (8 canonical leaves, roots n=1..8,
             consistency proofs (1,8), (6,8), (2,5),
             inclusion paths (0,1), (0,8), (5,8), (2,3), (1,5))
             adición autorizada por el dev (auditoría 2fd2745)

             PROCEDENCIA (registrada el 2026-09-26, Sprint 13). Al añadirlos (commits
             8bb4125 y 72bf7bd, 2026-09-04) no se anotó de dónde salían, y el campo
             "source" de los JSON dice «RFC 6962 reference test data», que es impreciso:
             la RFC 6962 no contiene vectores numéricos. El origen de la sesión que los
             escribió no se puede reconstruir. Lo que sí se ha comprobado, valor a valor:

             - Son los datos de prueba del proyecto Certificate Transparency de Google,
               hoy en github.com/transparency-dev/merkle (Apache-2.0, © Google LLC),
               commit fbbcd741c3d1c69d8498487baa8edc9e5824847c:
                 testonly/constants.go      LeafInputs, RootHashes, EmptyRootHash
                   sha256 6faf1957b5727c99593412ca0375f7e1f90ba10d7747dc42624585f948da32a8
                 testonly/reference_test.go TestRefInclusionProof, TestRefConsistencyProof
                   sha256 1891314f4c1e551c532190e4f072a41d103b42c952ea4a9454a9bc75dba5333f
               Las 8 hojas, la raíz vacía, las 8 raíces, los 5 caminos de inclusión y
               las 3 pruebas de consistencia coinciden con esas tablas; ninguno falta
               en ellas ni difiere.
             - Además se recalcularon todos desde la especificación (RFC 9162 §2.1:
               MTH, PATH y SUBPROOF) con Python y hashlib, sin una línea de este
               repositorio: coinciden todos. Una mutación de un solo nibble en
               cualquier fichero la detectan las dos comparaciones.

             sha256 de los ficheros tal como están:
               f23bf514af9ac6e23726bf62f5b32e6d6da97b1fc71fc2c5f5c223e8094fc0e9  consistency.json
               b33e05a58ddcc07d1052849822d4275a286e1d3ed4e2cc6005adebb8a188b6b0  inclusion.json
               b8290a09414ef888ac2ea64e4729a494207798acf9457c2c3566347459cac62d  leaves.json
               18c90345ba9c292d8ea867df151a101ce6fa4d6006fd685277681c05993bc10c  roots.json
- slip39/    45 official SatoshiLabs vectors (15 valid + 30 that MUST be rejected)
             descargados del repositorio canónico de Trezor (python-shamir-mnemonic),
             NO del testdata de la biblioteca que se evalúa; adición autorizada por
             el dev (ADR-010). sha256(vectors.json) =
             13ebecebdd869dd2bc2cdf69e7ce3a158cf106cac76c39d17682b1c6cdabbdc4
- leaf/      vectores de la REGLA DE HOJA leaf/v2 (PROTOCOL.md §2.1): 5 casos de
             leaf_data y leaf_hash, más las 8 raíces de un árbol de 8 hojas.
             Calculados por leaf/generar.py con hashlib y NADA más —ni una línea del
             código Go que verifican—, y el caso de ceros contrastado además con
             sha256sum. El generador se versiona para que cualquiera pueda repetir
             el cálculo sin confiar en nosotros. Adición autorizada por el dev
             (ADR-014, Sprint 7b).

- receipt/   recibos golden generados por receipt/generar.py, un ORÁCULO INDEPENDIENTE
             (Sprint 7f). Implementa leaf/v2, la nota firmada, las cosignatures, el
             header JCS y el recibo entero desde la especificación, con hashlib, json y
             la primitiva Ed25519; no importa una línea de Go. Antes los generaba
             internal/receipt —el paquete que verifican—, y la cuarta auditoría señaló
             que eso falsificaba la regla anti-circularidad del proyecto: un golden que
             sale del código bajo prueba reproduce sus errores.

             Al comparar las dos implementaciones coincidieron BYTE A BYTE en 16 de 17;
             la 17.ª destapó que Go copiaba provable_time a un vector inválido.

                 python3 testdata/vectors/receipt/generar.py          # reescribe
                 python3 testdata/vectors/receipt/generar.py --check  # compara sin escribir

             La suite de Go ya no los escribe: TestVectoresGoldenDicenLaVerdad los lee y
             comprueba que Go se comporta como declaran, y TestMain toma la huella del
             directorio —material/ incluido— antes y después y falla si algo cambió.

             ENMENDADO el 2026-09-18 (ADR-024). Aquí decía que la ÚNICA excepción era
             valido-firma-mldsa-del-log, que lo generaba Go entero. Ya no: ese vector lo
             construye el oráculo como los demás y solo PRESTA los bytes ML-DSA-44 de
             material/mldsa.json —1312 de clave pública y 2420 de firma—, que ningún
             verificador comprueba. El oráculo recompone hasta el key ID de esa línea
             desde la especificación (el byte 0xff lleva detrás el identificador de
             ADR-007) y exige que la firma prestada sea sobre EXACTAMENTE el cuerpo de
             nota que él produce; si la escena cambia, el material caduca y lo dice.
             Comprobación de que el cambio no movió nada: el vector que salió del oráculo
             es byte a byte el que generaba Go.

             El material se regenera en dos pasos, porque el oráculo tiene que decir
             primero qué hay que firmar:

                 python3 testdata/vectors/receipt/generar.py --mldsa-body
                 NUCLEO_REGENERAR_MATERIAL_MLDSA=1 go test ./internal/receipt \
                     -run TestRegeneraMaterialMLDSA

             (el test ejecuta el primer paso por su cuenta; está escrito para no copiar
             el cuerpo a mano, que es donde se cuela una divergencia).

             Historia: 3 recibos golden generados por internal/receipt:
             valido-1-cosignature, alterado-encabezado, cosignature-no-confiable.
             Cada fichero lleva el recibo completo, la política de verificación
             (claves en hex), el entry_hash esperado y los dos tiempos. Son LA VARA
             del verificador de TypeScript: si Go y TS no coinciden byte a byte,
             uno de los dos está mal. Se regeneran ejecutando ese test.

             REGENERADOS el 2026-09-10 para leaf/v2 (ADR-014, PROTOCOL 0.2-draft).
             El magic pasó de nucleo.org/receipt@v1 a @v2, la parte de máquina gana
             una línea con la firma del bloque en base64, y el campo entry_hash
             —32 bytes— se sustituye por leaf_data —96: hash ‖ signature— más
             leaf_rule y block_signature. Los recibos de la versión anterior NO
             verifican con el código actual, y eso es deliberado: cambio de ruptura
             pre-1.0 sin consumidores. Los goldens viejos no se conservan; la
             historia de git los tiene si alguien los necesita.

             Y en el mismo sprint, ADR-015: la parte de máquina gana una segunda
             línea con la FIRMA DEL EMISOR sobre el recibo entero, destinatario
             incluido, y la etiqueta del destinatario pasa de "(anotado por el
             emisor, no firmado)" a "(firmado por el emisor)". Se verifica con
             signer_pubkey, que ya viaja en el header: cero claves nuevas que
             repartir.

             Sprint 7d (D.6): valido-n{1,2,4,8,9}-i{0,último} y
             valido-destinatario-imita-firma.

             Sprint 7e (ADR-018, adición autorizada por el dev):
             invalido-cosignature-duplicada — un testigo, su línea DOS veces en la
             nota, recibo re-firmado por el emisor, política 2-de-2. Un testigo
             cuenta una vez (PROTOCOL.md §3.3): los tres verificadores lo rechazan.
             valido-dos-cosignatures-mismo-testigo — el mismo testigo cosigna dos
             veces y la línea TARDÍA va primero; vale la más temprana, que es el
             tiempo demostrable que el vector declara.
             cosignature-no-confiable REGENERADO: su política ya no es "sin
             testigos" —desde ADR-018 esa política no existe—, sino una que acepta a
             un testigo que no cosignó; el rechazo pasa a ser por quórum.
             valido-firma-mldsa-del-log — la nota trae la firma ML-DSA-44 del log
             (ADR-007), como la emite la CLI: los verificadores la ignoran y la
             página la reconoce como del log.

             Sprint 7f (cuarta auditoría, la primera externa; adición autorizada por
             el dev):
             valido-timestamp-con-fraccion — header con fracción de segundo, como los
             que la CLI selló hasta ADR-019; los tres verificadores lo aceptan porque
             el texto lleva el LITERAL del header.
             valido-testigo-proto — el testigo se llama "__proto__": nombre válido de
             signed-note que en JavaScript desaparecía del mapa de testigos.

- policy/    vectores de la POLÍTICA de verificación (PROTOCOL.md §3.2, ADR-018):
             el texto EXACTO de cada documento y su veredicto. Escritos a mano por
             policy/generar.py leyendo la tabla de PROTOCOL.md —ninguna línea del
             generador usa internal/policy ni sdk/ts/src/policy.ts—, que se versiona
             para que cualquiera repita el cálculo. Los leen el parser de Go, el del
             SDK y el del bundle de la página, y los tres tienen que dar el mismo
             veredicto. Adición autorizada por el dev (Sprint 7e).
