# Shared test vectors

Cross-language ground truth. Every implementation (Go core, TS/PHP/Python verifiers)
MUST reproduce these byte-for-byte. Changing anything here requires an ADR.

- jcs/       RFC 8785 vectors (official RFC examples + Nucleo cases), read by both
             internal/jcs and sdk/ts
- merkle/    RFC 6962 roots and proofs (8 canonical leaves, roots n=1..8,
             consistency proofs (1,8), (6,8), (2,5),
             inclusion paths (0,1), (0,8), (5,8), (2,3), (1,5))
             vectores oficiales RFC 6962; adición autorizada por el dev (auditoría 2fd2745)
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

- receipt/   3 recibos golden generados por internal/receipt (TestExportReceiptVectors):
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

