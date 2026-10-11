# PLAN.md — Fase actual

Estado: **`v0.3.0-alpha` publicada y verificada** (2 de octubre de 2026). El tag
`v0.3.0-alpha` (commit `b417cb4`) está firmado con SSH —GitHub lo da por válido,
`security@nucleoledger.com`— y el release, verificado dos veces: por el dev desde un
directorio limpio (bundle de Sigstore `Verified OK` sin avisos, `.sig`/`.pem` `Verified OK`,
sha256 OK, `NOTICE` y `AUTHORS` dentro, cero ganchos de prueba), y recompilando el binario
linux/amd64 desde el tag, que coincide byte a byte (sha256
`189090c88c0bbea8d7f3e17957c7ac8508f9b648325d128d2634e2477dab6212`).
`@nucleoledger/verify@0.3.0-alpha.0` está en npm (`latest` y `alpha`) con procedencia, y el
ejemplo Node ya lo usa. Las notas de `docs/releases/v0.3.0-alpha.md` están aplicadas y el
release está publicado como pre-release.

**`v0.3.1-alpha` publicada y verificada** (10 de octubre de 2026, pre-release): cierra los
tres hallazgos de la revisión del 2026-10-03 sobre ADR-029, con su enmienda —una passphrase
olvidada no es una robada—. Tag `v0.3.1-alpha` (commit `5237867`) firmado con SSH y válido
para GitHub; el release, verificado desde un directorio limpio (bundle y `.sig`/`.pem`
`Verified OK`, sha256 OK, `NOTICE` y `AUTHORS` dentro, cero ganchos de prueba) y
recompilado byte a byte desde el tag con go1.27.2 (sha256
`ebfeb36b7dc471d76c5c815800b9c24b1aad78ee7a0312059c2e59a1201f0d24`); sus notas, aplicadas.
El SDK sigue en 0.3.0-alpha.0.

**`v0.4.0-alpha` preparada, sin etiquetar** (Sprint 18, 10 de octubre de 2026): el testigo de
varios logs con su kit y el testigo mutuo (Sprint 15), el mapa del sistema vigilado por el CI
(Sprint 16), la supresión con su arreglo de `receipt --out` (Sprint 17), la enmienda que
intentó impedir usar la supresión para borrar huellas (Sprint 18) y la que de verdad lo
impide, la autoridad de supresión (Sprint 19, ADR-032). PROTOCOL 0.7-draft. Notas en
`docs/releases/v0.4.0-alpha.md`; la actualización desde v0.3.1-alpha, ensayada con el
binario publicado. El SDK de TypeScript no cambia: sin tag `vsdk`. Falta que el dev etiquete,
publique y que se verifique el release.

El detalle de lo hecho entre `v0.1.0-alpha` y aquí —Sprints 7 a 14: cinco rondas
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
- El tutorial cronometrado con alguien de fuera del proyecto, sobre el ejemplo Node.
  La parte mecánica está medida (~15 s de clon a recibo verificado); falta la de
  comprensión, que es la mitad de CONCEPTO §18 que no se puede fabricar desde dentro.
- Decidir ADR-012 (VRF), la única decisión abierta.

**De producto**
- **Producto-testigo.** Sin testigos que el emisor no controle, el tiempo demostrable
  no existe para una pyme: testigo mutuo entre instalaciones, o un tercero con
  incentivo (contador, certificadora, colegio de abogados). **El software está** desde el
  Sprint 15 —un testigo para varios logs con retirada (ADR-030), el testigo mutuo ensayado
  en el CI, y el kit del operador en `deploy/witness/`—; lo que falta es que lo opere
  alguien de fuera, y eso no lo hace el autor (CONCEPTO §1 y §7).
- **Identidad de registro y eventos `issued`/`voided`** en el perfil genérico: las
  facturas se anulan y `reconcile` no lo modela. Toca el protocolo; pide ADR.

**Anotado, sin urgencia**
- **cosign 3 en el CI de releases.** Hoy se firma con cosign 2.5.2 para publicar a la
  vez `.sig`/`.pem` y el bundle de Sigstore; cosign 3 ya no produce los primeros sin
  bundle. Pasar a cosign 3 es pasar a publicar solo el bundle: una decisión, no una
  actualización (ver `release.yml` y `docs/RELEASING.md`).
- **La versión de Go está fijada** en la directiva `toolchain` de `go.mod` (Sprint 15): los
  parches de Go ya no llegan solos y hay que subirlos a propósito (RELEASING, «La versión
  de Go»).

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
- La alarma de frescura se guarda en el ledger y `seal` sella siempre por omisión — ADR-028.
- Con dos tarjetas, `restore` fija una passphrase nueva y emite tarjetas nuevas, en una
  transacción; el `Sealer` acepta `0640 root:www-data` — ADR-029, y su enmienda: eso es
  para una passphrase olvidada; si se robó, hace falta un log nuevo.
- Un testigo para varios logs, con un fichero de configuración estricto y logs retirados que
  conservan su memoria — ADR-030.
- La supresión tiene comando: `nucleo erase` borra el contenido y sus compromisos, sella un
  evento sin datos personales y `reconcile` la distingue de un faltante — ADR-031, aceptado, y
  su enmienda: cada supresión abre una alarma. Una supresión solo cuenta si la autoriza la
  clave de supresión de la política, que no está en el servidor — ADR-032 (propuesta), que
  sustituye a las dos tarjetas de la enmienda.

# ✅ MÓDULOS ESTABLES (NO TOCAR)

- `internal/jcs` — RFC 8785 nativo; pasa los vectores oficiales. Congelado.
- `internal/ledger` — header/hash/firma/cadena y Merkle RFC 6962 con inclusión y
  consistencia. Ampliar, no reescribir.
- `internal/keys` — helpers Ed25519. **Solo lo usan los históricos** —`cmd/nucleo-demo/` y los
  `cmd/nucleo-poc*/`— y un benchmark de `internal/ledger/`; ningún paquete del producto lo
  importa (comprobado con `go list` en el Sprint 17). Se queda como está, igual que ellos.
- `cmd/nucleo-demo`, `cmd/nucleo-poc*` — pruebas de concepto históricas. Compilan y
  se quedan como referencia de cómo se llegó hasta aquí; **no se editan**. El
  producto es `cmd/nucleo`.

# 🚫 FUERA DE ALCANCE, A PROPÓSITO

Escrito aquí para que no se confunda "no hecho" con "olvidado":

- **Dual-license con texto y precio.** Decisión de negocio, no de ingeniería.
- **Auditoría humana pagada.** Cuando haya ingresos. Hasta entonces el README dice,
  en su primera frase, que no hay auditoría profesional, y eso no se maquilla.
- **HSM.** v1 es software-only; queda documentado como límite, no como pendiente.
