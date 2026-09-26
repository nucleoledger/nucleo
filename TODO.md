# TODO.md — Backlog atómico

Estado: **`v0.2.0-alpha` publicada** como pre-release el 2026-09-25 (commit `6442b03`)
y verificada por el dev con la receta de RELEASING —cosign `Verified OK` con la
identidad exacta del tag, sha256 OK, cero ganchos de prueba en el binario— y aquí
—el binario linux/amd64 se recompila byte a byte desde el tag—.
`@nucleoledger/verify@0.2.0-alpha.0` en npm con procedencia (`latest` y `alpha`).
Lo detallado de los Sprints 7 a 11 vive en `CHANGELOG.md`.

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
- [x] Configurar el trusted publisher de `@nucleoledger/verify` en npmjs.com —
      verificado el 2026-09-25: el tag `vsdk-0.2.0-alpha.0` publicó sin token y
      `npm audit signatures` da «1 package has a verified attestation»
      (publish-npm.yml, commit `669eaf2`)
- [x] Crear el buzón `security@nucleoledger.com` — operativo, confirmado por el dev
      el 2026-09-25
- [x] Publicar `v0.2.0-alpha` y verificarla desde un directorio limpio con la receta
      de RELEASING — hecho por el dev el 2026-09-25 (cosign v3.1.3)
- [ ] Activar el reporte privado de vulnerabilidades en GitHub — verificar:
      Settings → Security → la opción aparece habilitada
- [ ] Cronometrar el tutorial con alguien de fuera del proyecto, sobre el ejemplo
      Node (`examples/erp-node`) — verificar: una hora medida, no estimada por quien
      lo escribió. La parte mecánica ya está medida (de clon a recibo verificado,
      ~15 s en caliente, ~35 s en frío); falta la de comprensión, que es la que
      cierra CONCEPTO §18
- [ ] Decidir sobre ADR-012 (VRF). ADR-014 y ADR-015 están aceptadas e implementadas
      desde el Sprint 7b
- [ ] Decidir si `restore` debe poder fijar una passphrase nueva (re-envolviendo la clave
      de datos). Hoy perder la passphrase deja el vault sin poder sellar aunque se tengan
      las tarjetas —comprobado en el Sprint 12—; tocar eso es criptografía y va con ADR
- [ ] Decidir si `sync` debe aceptar una política con varios testigos y elegir uno por
      nombre. Tras perder un testigo, el cron necesita un fichero de política distinto del
      de los clientes (docs/OPERACION.md §1)

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

## Sprint 12 — que funcione como promete y se opere sin ayuda
- [x] ADR-028: la alarma de frescura durable, `alert status|ack`, `--fail-on-stale` y el hook
      `onStale` en el SDK de PHP y el ejemplo Node — test sin leer stderr
- [x] `docs/OPERACION.md`, cada instrucción comprobada
- [x] Los requisitos del hosting, lo primero del README del SDK de PHP
- [x] Las «auditorías externas» renombradas como lo que fueron: revisiones de un modelo

## Pendiente de producto
- [x] **Sealer PHP** — Sprint 8 (ADR-021): verificador nativo y sellador envoltorio.
- [ ] **Producto-testigo.** Sin testigos que el emisor no controle, el tiempo
      demostrable no existe para una pyme. Testigo mutuo entre instalaciones, o
      un tercero con incentivo (contador, certificadora, colegio de abogados).
- [ ] Identidad de registro estable y eventos `issued`/`voided` en el perfil
      genérico: las facturas se anulan y hoy `reconcile` no lo modela (pide ADR)

## Fuera de alcance hasta nuevo aviso
- **Dual-license con texto y precio** — decisión de negocio del dev, no de ingeniería.
- **Auditoría humana pagada** — cuando haya ingresos. Hasta entonces el README
  dice, en su primera frase, que no hay auditoría profesional, y eso no se maquilla.
- **HSM** — v1 es software-only. Documentado como límite, no como pendiente.
