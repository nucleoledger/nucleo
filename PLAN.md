# PLAN.md — Fase actual

# 🎯 OBJETIVO DE LA FASE ACTUAL
**Fase D + Fase 0 (según `docs/CONCEPTO-v1.2-es.md` §17):** dejar el laboratorio operativo (CI multiplataforma, fuzzing, vectores externalizados) y ejecutar la **prueba de concepto C2SP**: emitir un checkpoint firmado del árbol actual, construir un recibo estilo tlog-proof y verificarlo offline con un testigo simulado. La Fase 0 resuelve las mediciones pendientes (tamaño real del recibo, sellos/segundo).

# 🧠 DECISIONES TÉCNICAS
(Detalle y fuentes en `docs/adr/` y `docs/CONCEPTO-v1.2-es.md` §9)
- Protocolo base **C2SP** (checkpoint, cosignature v1, witness, proof, tiles) — no formato propio.
- Firma Ed25519 sobre digest SHA-256; **ML-DSA-44 adicional** cuando entre Go 1.27 (stdlib `crypto/mldsa`).
- Tiempo declarado (reloj local) vs. tiempo demostrable (mín. timestamps de cosignatures) — dos campos en el recibo.
- Compromisos no adivinables: VRF `vrf-r255` (terceros) / HMAC (interno); blobs cifrados borrables (LOPDP).
- Respaldo de KEK con SLIP-0039 2-de-3; rotación de identidad como bloque firmado por la llave saliente.
- Modo primario **CLI invocable**; daemon opcional; SQLite Go puro; API OpenAPI para clientes delgados.
- Segmentos por período con checkpoint atestiguado (modelo Rekor v2).
- QR del recibo = URL a verificador estático + hash (no el proof completo).

# ✅ MÓDULOS ESTABLES (NO TOCAR)
- `internal/jcs` — RFC 8785 nativo; pasa vectores oficiales. Congelado.
- `internal/ledger/block.go` — header/hash/firma/cadena. Ampliar (no reescribir) solo para checkpoint/consistencia.
- `internal/ledger/merkle.go` — RFC 6962 + inclusión. Se le AÑADE la prueba de consistencia; lo existente no se modifica.
- `internal/keys` — helpers Ed25519.
- `cmd/nucleo-demo` — referencia funcional; se reemplazará por la CLI real, no se edita mientras tanto.

# 🏁 CRITERIOS DE ACEPTACIÓN
1. CI en verde en Linux, macOS y Windows (gofmt + vet + test -race).
2. Fuzzing de JCS corre ≥ 5 minutos sin pánico ni divergencia de round-trip.
3. Prueba de consistencia RFC 9162 §2.1.4 implementada y verificada con tests (incluye caso de árbol reescrito → falla).
4. `nucleo-demo` (o un nuevo cmd de PoC) emite: checkpoint firmado (formato nota firmada) + recibo con inclusion proof, y un verificador lo valida offline **sin acceso al ledger**; con un testigo simulado que detecta una reescritura.
5. Benchmark inicial publicado en el README: sellos/segundo y tamaño del recibo en bytes.
