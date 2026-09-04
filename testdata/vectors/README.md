# Shared test vectors

Cross-language ground truth. Every implementation (Go core, TS/PHP/Python verifiers)
MUST reproduce these byte-for-byte. Changing anything here requires an ADR.

- jcs/       RFC 8785 vectors (official RFC examples + Nucleo cases)  <PENDIENTE: externalizar desde internal/jcs tests>
- merkle/    RFC 6962 roots and proofs                                 <PENDIENTE>
- slip39/    45 official SatoshiLabs vectors                           <PENDIENTE: al integrar SLIP-0039>
