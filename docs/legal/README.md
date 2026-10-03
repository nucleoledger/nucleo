# Carpeta de titularidad y licencias — índice

**Esto no es texto legal.** Es un índice: dónde está, en este repositorio, cada pieza
que pediría una due diligence o que necesita el abogado para redactar la licencia
comercial y el acuerdo de contribución. No contiene cláusulas, no interpreta ninguna
licencia y no afirma nada jurídico. Donde algo no existe todavía, lo dice.

Estado a 2026-10-02.

---

## Titularidad

| pieza | dónde | qué es |
|---|---|---|
| Autor | [`AUTHORS`](../../AUTHORS) | el autor de todos los commits del historial, con la identidad que usa desde el 2026-10-02; no hay otro autor |
| Aviso de copyright | [`README.md`](../../README.md) (§License), [`NOTICE`](../../NOTICE), los README de `sdk/ts` y `sdk/php`, `author` de `sdk/ts/package.json` | la misma línea en todos: «Copyright (C) 2026 Sergio Iván Ullaguari Alvarado», el nombre legal completo del titular |
| Historial | `git log` | desde el 2026-09-03; cada cambio con su motivo en el mensaje del commit |
| Asistencia de IA | los trailers `Co-Authored-By:` de los commits | la mayoría de los commits nombran un modelo de IA (Claude) como coautor; [`AUTHORS`](../../AUTHORS) lo registra sin interpretarlo |

## Licencias

| pieza | dónde | estado |
|---|---|---|
| Licencia del proyecto | [`LICENSE`](../../LICENSE) | AGPL-3.0-or-later, texto literal |
| Licencia comercial | — | **no existe todavía**; el README dice que hay licencias comerciales disponibles |
| Acuerdo de contribución (CLA) | — | **no existe todavía**; mientras tanto no se aceptan pull requests ([`CONTRIBUTING.md`](../../CONTRIBUTING.md)) |
| Licencias de terceros | [`NOTICE`](../../NOTICE) | inventario de todas las dependencias, publicadas y de desarrollo, con los textos de lo que viaja en el binario y el método para repetirlo |

## Decisiones de diseño

| pieza | dónde |
|---|---|
| Especificación normativa | [`docs/PROTOCOL.md`](../PROTOCOL.md) |
| Decisiones registradas | [`docs/adr/`](../adr/), ADR-001 a ADR-029, con sus enmiendas —los sitios donde una medición contradijo una afirmación anterior y el registro lo dice— |
| Historia de cambios | [`CHANGELOG.md`](../../CHANGELOG.md) |

## Revisiones de seguridad

**No ha habido ninguna auditoría profesional de seguridad.** Lo que hay son revisiones
adversariales hechas por modelos de IA, dentro y fuera del proyecto, y ejercicios propios.

| pieza | dónde |
|---|---|
| Las dos revisiones externas, hechas por modelos | [`docs/revision-externa-modelo-20260913.md`](../revision-externa-modelo-20260913.md), [`docs/revision-externa-modelo-20260919.md`](../revision-externa-modelo-20260919.md) |
| Hallazgos y cómo se cerró cada uno | README, §Security & audits; CHANGELOG, secciones «Security» de los Sprints 7c a 9 |
| Ensayo de operación | [`docs/ensayo-de-operacion-20260923.md`](../ensayo-de-operacion-20260923.md) |
| Informe del ejemplo de integración | [`docs/ejemplo-de-integracion-20260923.md`](../ejemplo-de-integracion-20260923.md) |
| Política de divulgación | [`SECURITY.md`](../../SECURITY.md) |

## Releases: firmados y reproducibles

| pieza | dónde |
|---|---|
| Cómo se publica y cómo se verifica una descarga | [`docs/RELEASING.md`](../RELEASING.md) |
| Releases publicados | GitHub, `v0.1.0-alpha` y `v0.2.0-alpha` (pre-releases) |
| Notas de cada release | [`docs/releases/`](../releases/) |
| Firma de los binarios | `checksums.txt` firmado con cosign en modo keyless desde `release.yml`, más una atestación de procedencia SLSA |
| Reproducibilidad | [`docs/RELEASING.md`](../RELEASING.md), §Compilar desde el código: los binarios linux/amd64 de los dos releases se recompilaron desde su tag y coincidieron byte a byte |
| Paquete de npm | `@nucleoledger/verify@0.2.0-alpha.0`, publicado desde CI con procedencia (`npm audit signatures`) |

## Operación

| pieza | dónde |
|---|---|
| Guía para operar un despliegue | [`docs/OPERACION.md`](../OPERACION.md) |
| Tutorial de integración | [`docs/TUTORIAL-es.md`](../TUTORIAL-es.md) |

---

## Hechos que conviene tener delante

Sin valorarlos: son cosas que están así, y que quien redacte o revise debería conocer.

1. **Ningún commit ni ningún tag está firmado todavía.** Los tags `v0.1.0-alpha`,
   `v0.2.0-alpha` y `vsdk-0.2.0-alpha.0` son tags anotados, sin firma. Lo que está
   firmado son los artefactos de cada release (`checksums.txt`, con cosign keyless) y
   el paquete de npm (procedencia). Desde `v0.3.0-alpha`, [`docs/RELEASING.md`](../RELEASING.md)
   firma el tag con una clave SSH del dev (`git tag -s`).
2. **La mayoría de los commits lleva un `Co-Authored-By:` de un modelo de IA.**
3. **El aviso de copyright lleva el nombre legal completo** («Sergio Iván Ullaguari Alvarado»).
   Desde el 2026-10-02, los commits y los tags van con ese nombre y
   `security@nucleoledger.com`; los anteriores (del 2026-09-03 al 2026-09-28) registran al
   mismo autor como «Sergio U», con un correo personal. La historia no se reescribe, y
   [`AUTHORS`](../../AUTHORS) explica las dos identidades. Los releases `v0.1.0-alpha` y
   `v0.2.0-alpha` y el paquete `@nucleoledger/verify@0.2.0-alpha.0` se publicaron con la
   forma abreviada; `v0.3.0-alpha` lleva en su archivo el `AUTHORS` anterior a este cambio,
   con el correo personal.
4. **Los archivos de `v0.1.0-alpha` y `v0.2.0-alpha` no incluyen `NOTICE`**; los del
   siguiente release sí, junto a `AUTHORS` (`.goreleaser.yaml`, comprobado con un build
   snapshot de las seis plataformas). Es lo que piden, literalmente, las licencias de
   las dependencias que van dentro del binario (sus textos completos están en `NOTICE`):
   - BSD-3-Clause: *«Redistributions in binary form must reproduce the above copyright
     notice, this list of conditions and the following disclaimer in the documentation
     and/or other materials provided with the distribution.»*
   - MIT: *«The above copyright notice and this permission notice shall be included in
     all copies or substantial portions of the Software.»*
5. **Los vectores de prueba RFC 6962** (`testdata/vectors/merkle/rfc6962`) son los
   datos de prueba de Merkle del proyecto Certificate Transparency de Google, hoy en
   `transparency-dev/merkle` (Apache-2.0). De dónde se copiaron al añadirlos no quedó
   registrado; el 2026-09-26 se contrastaron valor a valor contra ese repositorio, en
   un commit fijado, y se recalcularon desde RFC 9162: coinciden todos. El detalle,
   con los sha256, está en [`testdata/vectors/README.md`](../../testdata/vectors/README.md).
   Solo están en el código fuente; no viajan en ningún artefacto publicado.
