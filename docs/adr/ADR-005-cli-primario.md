# ADR-005-cli-primario

**Estado:** aceptada · **Fecha:** 2026-08-31 · **Fuentes:** docs/CONCEPTO-v1.2-es.md §9

Modo primario: CLI invocable por ejecucion (compatible con hosting compartido CloudLinux/CageFS que bloquea daemons). Daemon localhost opcional para VPS. Modulo Go importable. SQLite Go puro (modernc.org/sqlite). API descrita en OpenAPI para clientes delgados TS-PHP-Python-Java. Wasm pospuesto (Argon2id costoso).
