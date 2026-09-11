# PLAN.md — Fase actual

Estado: **post-lanzamiento de `v0.1.0-alpha`** (tag firmado el 9-sep-2026, release
borrador verificado: cosign + procedencia SLSA; `@nucleoledger/verify@0.1.0-alpha.0`
en npm). Sprint en curso: **Sprint 7 — cerrar la revisión externa.**

# 🎯 OBJETIVO DE LA FASE ACTUAL

La v1 ya cumple su criterio de éxito de punta a punta (`scripts/demo-criterio-exito.sh`,
7 pasos, 30 aserciones). Lo que falta **no es más criptografía**: es el producto
alrededor del teorema. La revisión externa del 10-sep-2026 lo resumió en una
frase que conviene no suavizar:

> Falta quién atestigua, cómo sella el PHP del ERP en la misma transacción, qué
> pasa cuando restauran el backup, qué dice el recibo ante un juez, y una
> auditoría que no sea otro modelo.

Sprint 7 ataca cuatro de esos cinco frentes. La auditoría humana no depende de
código y queda fuera a propósito (ver abajo).

# 🧭 ORDEN DEL SPRINT 7

1. **Higiene P0.** Ningún binario compilado en el árbol; documentación de proceso
   que diga la verdad; README preciso sobre qué es y qué no es ML-DSA-44.
2. **El recibo ante un humano y un juez.** Disclaimer legal en español en el
   recibo y en el verificador HTML; el destinatario etiquetado como lo que es.
3. **ADR-014 — la hoja y la firma.** Decisión sobre mover la firma del bloque
   dentro de la hoja de Merkle. Es ahora o nunca: hoy hay cero usuarios y cero
   recibos ajenos; dentro de un año el coste es infinito.
4. **Operación que no miente.** Política *fail-stale*: una atestación vieja es un
   incidente que se anuncia solo, sin que nadie tenga que mirar `status`.
   Perfiles de KDF medidos para el hosting compartido que el propio ADR-005 eligió.
5. **Fuzz del formato de cable.** No solo JCS: note firmada, checkpoint,
   cosignature, recibo y el cuerpo de la petición del testigo.

# 🧠 DECISIONES YA TOMADAS (no se re-litigan)

Detalle y fuentes en `docs/adr/`. Resumen de lo que está cerrado:

- Protocolo base **C2SP** (checkpoint, cosignature v1, witness HTTP, proof) — ADR-001, ADR-011.
- Ed25519 sobre digest SHA-256, **más ML-DSA-44** como firma adicional del log por
  la extensión `0xff` de `signed-note` — ADR-007 y su addendum. Las cosignatures
  de testigo siguen siendo Ed25519.
- Tiempo declarado vs. demostrable, con política obligatoria para lo segundo — ADR-002.
- Compromisos **HMAC-SHA-256** con subclave por tenant; el VRF queda descartado
  para el ledger porque da verificabilidad pero no privacidad — ADR-003 y su
  enmienda, ADR-012.
- SLIP-0039 2-de-3 para el respaldo de la KEK — ADR-004, ADR-010.
- **CLI como modo primario**, sin daemon obligatorio — ADR-005.
- SQLite append-only con apertura rápida respaldada por checkpoint cosignado — ADR-009 y sus enmiendas.

# ⏳ DECISIONES ESPERANDO AL DEV

- **ADR-012** — VRF: evaluado, dependencia no añadida. Sin decidir.
- **ADR-014** — hoja de Merkle que incluya la firma. Escrito en este sprint, sin implementar.
- **ADR-015** — destinatario firmado por el emisor. Escrito en este sprint, sin implementar.

# ✅ MÓDULOS ESTABLES (NO TOCAR)

- `internal/jcs` — RFC 8785 nativo; pasa los vectores oficiales. Congelado.
- `internal/ledger` — header/hash/firma/cadena y Merkle RFC 6962 con inclusión y
  consistencia. Ampliar, no reescribir.
- `internal/keys` — helpers Ed25519.
- `cmd/nucleo-demo`, `cmd/nucleo-poc*` — pruebas de concepto históricas. Compilan y
  se quedan como referencia de cómo se llegó hasta aquí; **no se editan**. El
  producto es `cmd/nucleo`.

# 🏁 CRITERIOS DE ACEPTACIÓN DEL SPRINT 7

1. `git ls-files` sin un solo ejecutable; `.gitignore` con las rutas ancladas.
2. Un recibo recién emitido lleva el disclaimer legal en español, y el
   destinatario dice en su propia línea que va anotado y no firmado.
3. ADR-014 y ADR-015 escritos con recomendación y plan de ejecución, sin una
   línea de código de producción tocada.
4. `status` y `seal` avisan por stderr y en `--json` cuando la última atestación
   pasa del umbral; `verify` lo reporta. Con reloj inyectado en los tests.
5. `init --kdf-profile constrained` persiste sus parámetros y `Unlock` los honra,
   con el coste de las dos configuraciones medido, no estimado.
6. Un fuzzer por formato de cable, cada uno ≥ 2 minutos sin pánico y sin aceptar
   lo que debe rechazar.

# 🚫 FUERA DE ESTE SPRINT, A PROPÓSITO

Escrito aquí para que no se confunda "no hecho" con "olvidado":

- **Sealer PHP.** Es el hueco más grande del producto —el mercado es PHP en cPanel
  y hoy solo hay CLI Go y verificador TS— pero es un sprint entero, no un bloque.
- **Producto-testigo.** Sin una red de testigos que el emisor no controle, el
  tiempo demostrable no existe para una pyme. Siguiente sprint.
- **Dual-license con texto y precio.** Decisión de negocio, no de ingeniería.
- **Auditoría humana pagada.** Cuando haya ingresos. Hasta entonces el README
  dice que no hay auditoría externa, y eso no se maquilla.
- **HSM.** v1 es software-only; queda documentado como límite, no como pendiente.
- **Identidad de registro y eventos (`issued`/`voided`) en el perfil genérico.**
  Hallazgo real de la revisión, no abordado aquí: toca el protocolo y pide su
  propio ADR.
