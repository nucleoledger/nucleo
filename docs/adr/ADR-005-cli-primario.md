# ADR-005-cli-primario

**Estado:** aceptada · **Fecha:** 2026-08-31 · **Fuentes:** docs/CONCEPTO-v1.2-es.md §9

Modo primario: CLI invocable por ejecucion (compatible con hosting compartido CloudLinux/CageFS que bloquea daemons). Daemon localhost opcional para VPS. Modulo Go importable. SQLite Go puro (modernc.org/sqlite). API descrita en OpenAPI para clientes delgados TS-PHP-Python-Java. Wasm pospuesto (Argon2id costoso).

## Enmienda 2026-10-10 (Sprint 17) — lo que se hizo y lo que no

El texto de arriba se deja como se escribió. Lo que pasó con cada pieza:

- **CLI invocable por ejecución**: es el producto, como se decidió.
- **Daemon localhost opcional**: no existe y **no está planificado para la v1** (enmienda del
  CONCEPTO, Sprint 15). Lo que iba a resolver —clientes de otros lenguajes— lo resolvió la
  propia CLI con su salida `--json`, que es un formato de cable normativo (ADR-025).
- **Módulo Go importable**: no lo es. Todos los paquetes están bajo `internal/`, que Go no deja
  importar desde otro módulo. Un integrador de Go llama a la CLI. Publicar una API de Go sería
  otra decisión, con su ADR.
- **API descrita en OpenAPI**: no hay API HTTP que describir, así que no hay OpenAPI. Los
  clientes delgados existen sin ella: `@nucleoledger/verify` en TypeScript, solo verificación,
  y el SDK de PHP, con verificador nativo y sellador que envuelve el binario (ADR-021). Python
  y Java, no.
- **SQLite en Go puro** (`modernc.org/sqlite`): como se decidió.
- **Wasm pospuesto**: sigue pospuesto.

PROTOCOL.md §9 lleva la misma enmienda, en inglés.
