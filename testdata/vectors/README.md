# Shared test vectors

Cross-language ground truth. Every implementation (Go core, TS/PHP/Python verifiers)
MUST reproduce these byte-for-byte. Changing anything here requires an ADR.

- jcs/       RFC 8785 vectors (official RFC examples + Nucleo cases)  <PENDIENTE: externalizar desde internal/jcs tests>
- merkle/    RFC 6962 roots and proofs (8 canonical leaves, roots n=1..8,
             consistency proofs (1,8), (6,8), (2,5),
             inclusion paths (0,1), (0,8), (5,8), (2,3), (1,5))
             vectores oficiales RFC 6962; adición autorizada por el dev (auditoría 2fd2745)
- slip39/    45 official SatoshiLabs vectors (15 valid + 30 that MUST be rejected)
             descargados del repositorio canónico de Trezor (python-shamir-mnemonic),
             NO del testdata de la biblioteca que se evalúa; adición autorizada por
             el dev (ADR-010). sha256(vectors.json) =
             13ebecebdd869dd2bc2cdf69e7ce3a158cf106cac76c39d17682b1c6cdabbdc4
