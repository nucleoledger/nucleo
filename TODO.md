# TODO.md — Backlog atómico

Estado: `v0.1.0-alpha` publicada (tag firmado, release verificado con cosign y
procedencia SLSA, `@nucleoledger/verify@0.1.0-alpha.0` en npm). **Sprint 7 en
curso:** cerrar la revisión externa del 10-sep-2026.

El histórico de tareas cumplidas se resume por sprint: el detalle vive en los
commits, en `CHANGELOG.md` y en `docs/adr/`, que es donde hay que buscarlo. Una
lista de 70 casillas marcadas no es memoria del proyecto, es ruido.

## Hecho, por sprint
- [x] **Fase D + Fase 0** — JCS RFC 8785 nativo con vectores oficiales y fuzzing;
      bloque firmado y cadena; Merkle RFC 6962 con inclusión y consistencia;
      checkpoint C2SP; cosignature simulada; recibo tlog-proof; CI en tres SO.
- [x] **Sprint 2** — `internal/store` SQLite append-only; `internal/vault`
      (Argon2id → KEK → DEK, XChaCha20-Poly1305 con AAD no ambiguo); respaldo
      SLIP-0039 con los 45 vectores de Trezor; apertura rápida respaldada por
      checkpoint cosignado (10^5 bloques: 8,66 s → 412 ms) y `VerifyFull`.
- [x] **Sprint 3** — testigo HTTP real completo; reconciliación; detección de
      rollback por memoria del testigo; segunda firma ML-DSA-44 vía extensión
      `0xff`; cerrojo anti-retroceso duradero (`log_state`).
- [x] **Sprint 4** — `cmd/nucleo` con códigos de salida 0/1/2/3; vectores de
      recibo cross-lenguaje; `sdk/ts` con cero dependencias de runtime;
      `web/verify` estático.
- [x] **Sprint 5** — compromisos HMAC con subclave por tenant; perfil Ecuador
      (`sri.factura.v1`, `sas.acta.v1`); el criterio de éxito como script
      ejecutable; tutorial con salidas reales; spike VRF (ADR-012).
- [x] **Sprint 6 + pre-lanzamiento** — README y CHANGELOG; release firmado
      (goreleaser + cosign keyless + procedencia SLSA); los 6 hallazgos de la
      auditoría pre-pública (ADR-013); publicación npm con trusted publishing.

## Tareas del dev (fuera del código)
- [x] Organizaciones `nucleoledger` en GitHub y `@nucleoledger` en npm; dominio; 2FA; LICENSE
- [ ] Configurar el trusted publisher de `@nucleoledger/verify` en npmjs.com
      (Settings → Trusted Publisher → GitHub Actions; pasos exactos en
      `docs/RELEASING.md`; **marcar "allow npm publish"**, no solo staging) —
      verificar: un tag `vsdk-*` publica sin token y el paquete sale con procedencia
- [ ] Crear el buzón `security@nucleoledger.com` o cambiar la dirección en
      `SECURITY.md` — verificar: un correo a esa dirección llega
- [ ] Activar el reporte privado de vulnerabilidades en GitHub — verificar:
      Settings → Security → la opción aparece habilitada
- [ ] Cronometrar el tutorial con alguien de fuera del proyecto — verificar: una
      hora medida, no estimada por quien lo escribió
- [ ] Decidir sobre ADR-012 (VRF), ADR-014 (hoja y firma) y ADR-015 (destinatario)

## Sprint 7 — cerrar la revisión externa
- [x] Ningún binario compilado en el árbol; `.gitignore` con rutas ancladas (P0)
- [x] PLAN/CLAUDE/AGENTS/TODO dicen la verdad del repo (deriva documental)
- [x] README: ML-DSA-44 es firma ADICIONAL del log vía extensión `0xff`; las
      cosignatures de testigo siguen Ed25519 — nada de post-cuántico de punta a punta
- [x] Disclaimer legal en español EN el recibo y en el verificador HTML
- [x] El destinatario del recibo se etiqueta "(anotado por el emisor, no firmado)"
- [x] `docs/adr/ADR-014-hoja-y-firma.md` — spike de decisión, sin implementar
- [x] `docs/adr/ADR-015-destinatario.md` — spike de decisión, sin implementar
- [x] Política *fail-stale*: umbral configurable (72 h por omisión); `status` y
      `seal` avisan por stderr y en `--json`; `verify` lo reporta. Reloj inyectado
- [x] `init --kdf-profile {default,constrained}` con los parámetros persistidos y
      honrados por `Unlock`, y el coste de ambos perfiles MEDIDO
- [x] Fuzzers de todos los formatos de cable: note firmada, checkpoint,
      cosignature, recibo y cuerpo de la petición del testigo

## Siguiente sprint (no empezar sin cerrar el 7)
- [ ] **Sealer PHP.** El mercado es PHP en cPanel y hoy solo hay CLI Go y
      verificador TS. Es el hueco más grande del producto.
- [ ] **Producto-testigo.** Sin testigos que el emisor no controle, el tiempo
      demostrable no existe para una pyme. Testigo mutuo entre instalaciones, o
      un tercero con incentivo (contador, certificadora, colegio de abogados).
- [ ] Identidad de registro estable y eventos `issued`/`voided` en el perfil
      genérico: las facturas se anulan y hoy `reconcile` no lo modela (pide ADR)

## Fuera de alcance hasta nuevo aviso
- **Dual-license con texto y precio** — decisión de negocio del dev, no de ingeniería.
- **Auditoría humana pagada** — cuando haya ingresos. Hasta entonces el README
  dice que no hay auditoría externa y eso no se maquilla.
- **HSM** — v1 es software-only. Documentado como límite, no como pendiente.
