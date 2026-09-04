# ADR-001-c2sp-base

**Estado:** aceptada · **Fecha:** 2026-08-31 · **Fuentes:** docs/CONCEPTO-v1.2-es.md §9

Adoptar C2SP (tlog-checkpoint, tlog-cosignature v1, tlog-witness, tlog-proof, tlog-tiles) como base del protocolo en lugar de un formato propio o Sigstore bundles. Razón: interoperabilidad con testigos y verificadores existentes, bibliotecas Go mantenidas por el ecosistema (x/mod/sumdb/note, transparency-dev, torchwood), y contribución académica más sólida. Versiones exactas de cada spec se fijan al implementar.
