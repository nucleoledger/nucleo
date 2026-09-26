# PLAN.md — Fase actual

Estado: **post-lanzamiento de `v0.2.0-alpha`**, publicada como pre-release el
25-sep-2026 (commit `6442b03`) y verificada dos veces: por el dev, con la receta de
`docs/RELEASING.md` desde un directorio limpio (cosign `Verified OK` con la identidad
exacta del tag, sha256 OK, cero ganchos de prueba en el binario), y recompilando el
binario linux/amd64 desde el tag, que coincide byte a byte. `@nucleoledger/verify@0.2.0-alpha.0`
está en npm, publicado desde CI con procedencia. El siguiente sprint lo fija el dev.

El detalle de lo hecho entre `v0.1.0-alpha` y aquí —Sprints 7 a 11: cinco rondas
adversariales, el SDK de PHP, el ensayo de operación, el ejemplo de integración— vive
en `CHANGELOG.md` y en `docs/adr/`, no aquí.

# 🎯 DÓNDE ESTÁ EL PROYECTO

La v1 cumple su criterio de éxito de punta a punta como script
(`scripts/demo-criterio-exito.sh`) y como aplicación (`examples/erp-node`, en CI). Tres
verificadores —Go, TypeScript y PHP escrito desde la especificación— coinciden en
cada mutación del diferencial. Lo que falta sigue sin ser criptografía, y la revisión
externa del 10-sep-2026 lo dijo en una frase que conviene no suavizar:

> Falta quién atestigua, cómo sella el PHP del ERP en la misma transacción, qué
> pasa cuando restauran el backup, qué dice el recibo ante un juez, y una
> auditoría que no sea otro modelo.

De esos cinco frentes, tres están cerrados: el sellado desde PHP (Sprint 8, ADR-021),
el backup restaurado (ensayo de operación del Sprint 10: el rollback detectado ya no
se olvida) y el recibo ante un juez (aviso legal dentro del recibo, destinatario
firmado por ADR-015). Quedan dos: **quién atestigua** y **la auditoría que no sea
otro modelo**.

# 📋 LO QUE QUEDA

El backlog atómico está en `TODO.md`. En resumen:

**Del dev, fuera del código**
- Activar el reporte privado de vulnerabilidades en GitHub.
- El tutorial cronometrado con alguien de fuera del proyecto, sobre el ejemplo Node.
  La parte mecánica está medida (~15 s de clon a recibo verificado); falta la de
  comprensión, que es la mitad de CONCEPTO §18 que no se puede fabricar desde dentro.
- Decidir ADR-012 (VRF), la única decisión abierta.

**De producto**
- **Producto-testigo.** Sin testigos que el emisor no controle, el tiempo demostrable
  no existe para una pyme: testigo mutuo entre instalaciones, o un tercero con
  incentivo (contador, certificadora, colegio de abogados).
- **Identidad de registro y eventos `issued`/`voided`** en el perfil genérico: las
  facturas se anulan y `reconcile` no lo modela. Toca el protocolo; pide ADR.

**Anotado, sin urgencia**
- **cosign 3 en el CI de releases.** Hoy se firma con cosign 2.5.2 para publicar a la
  vez `.sig`/`.pem` y el bundle de Sigstore; cosign 3 ya no produce los primeros sin
  bundle. Pasar a cosign 3 es pasar a publicar solo el bundle: una decisión, no una
  actualización (ver `release.yml` y `docs/RELEASING.md`).
- **La versión de Go de los releases** no está fijada (`go-version: 'stable'`): recibe
  los parches de seguridad sola, a cambio de que la versión se lea del binario y no del
  repositorio para reproducirlo.

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
- **`leaf/v2`**: la firma del bloque dentro de la hoja de Merkle — ADR-014. El emisor
  firma el recibo entero, destinatario incluido — ADR-015.
- La atestación solo cuenta si **verifica**, y la política es la única raíz de
  confianza y un formato de cable — ADR-016, ADR-017, ADR-018.
- Tiempo firmado con resolución de **segundo** — ADR-019.
- Sellado **idempotente y atómico** — ADR-020. SDK de PHP: verificador nativo,
  sellador envoltorio — ADR-021.
- Una comparación que no se puede hacer no es un veredicto — ADR-022. Entropía dentro
  del payload frente a la enumeración de `payload_hash` — ADR-023.
- La salida `--json` es un formato de cable, con **clase de error** ortogonal al código
  de salida — ADR-025, ADR-027. El ejemplo de integración vive en este repositorio y
  usa el SDK publicado — ADR-026.

# ✅ MÓDULOS ESTABLES (NO TOCAR)

- `internal/jcs` — RFC 8785 nativo; pasa los vectores oficiales. Congelado.
- `internal/ledger` — header/hash/firma/cadena y Merkle RFC 6962 con inclusión y
  consistencia. Ampliar, no reescribir.
- `internal/keys` — helpers Ed25519.
- `cmd/nucleo-demo`, `cmd/nucleo-poc*` — pruebas de concepto históricas. Compilan y
  se quedan como referencia de cómo se llegó hasta aquí; **no se editan**. El
  producto es `cmd/nucleo`.

# 🚫 FUERA DE ALCANCE, A PROPÓSITO

Escrito aquí para que no se confunda "no hecho" con "olvidado":

- **Dual-license con texto y precio.** Decisión de negocio, no de ingeniería.
- **Auditoría humana pagada.** Cuando haya ingresos. Hasta entonces el README dice,
  en su primera frase, que no hay auditoría profesional, y eso no se maquilla.
- **HSM.** v1 es software-only; queda documentado como límite, no como pendiente.
