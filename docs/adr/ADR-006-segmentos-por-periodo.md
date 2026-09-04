# ADR-006-segmentos-por-periodo

**Estado:** aceptada · **Fecha:** 2026-08-31 · **Fuentes:** docs/CONCEPTO-v1.2-es.md §9

El ledger cierra periodos (mensual o anual segun volumen) con un checkpoint atestiguado; segmentos historicos se archivan como tiles estaticos; la cadena de segmentos se verifica con pruebas de consistencia RFC 9162 2.1.4 entre checkpoints de cierre (modelo de shards de Rekor v2).
