# ADR-007-mldsa44-adicional

**Estado:** aceptada · **Fecha:** 2026-08-31 · **Fuentes:** docs/CONCEPTO-v1.2-es.md §9

Ademas de la firma Ed25519 obligatoria, los checkpoints llevaran una firma ML-DSA-44 (crypto/mldsa, stdlib Go 1.27) para resistencia post-cuantica. Los verificadores de notas firmadas ignoran firmas desconocidas, por lo que anadirla es retrocompatible.
