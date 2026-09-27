# Carpeta de titularidad y licencias — índice

**Esto no es texto legal.** Es un índice: dónde está, en este repositorio, cada pieza
que pediría una due diligence o que necesita el abogado para redactar la licencia
comercial y el acuerdo de contribución. No contiene cláusulas, no interpreta ninguna
licencia y no afirma nada jurídico. Donde algo no existe todavía, lo dice.

Estado a 2026-09-26.

---

## Titularidad

| pieza | dónde | qué es |
|---|---|---|
| Autor | [`AUTHORS`](../../AUTHORS) | la identidad que firma los 245 commits del historial; no hay otro autor |
| Aviso de copyright | [`README.md`](../../README.md) (§License), [`NOTICE`](../../NOTICE), los README de `sdk/ts` y `sdk/php`, `author` de `sdk/ts/package.json` | la misma línea en todos: «Copyright (C) 2026 Sergio U», el nombre tal como consta en git |
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
| Decisiones registradas | [`docs/adr/`](../adr/), ADR-001 a ADR-028, con sus enmiendas —los sitios donde una medición contradijo una afirmación anterior y el registro lo dice— |
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

1. **Ningún commit ni ningún tag está firmado con GPG.** Los tags `v0.1.0-alpha`,
   `v0.2.0-alpha` y `vsdk-0.2.0-alpha.0` son tags anotados, sin firma. Lo que está
   firmado son los artefactos de cada release (`checksums.txt`, con cosign keyless) y
   el paquete de npm (procedencia).
2. **La mayoría de los commits lleva un `Co-Authored-By:` de un modelo de IA.**
3. **El nombre del aviso de copyright es el que consta en git** («Sergio U»). Si el
   titular legal se escribe de otra forma, hay que cambiarlo en los cinco sitios de la
   tabla de titularidad.
4. **Los archivos del release no incluyen hoy `NOTICE`**: llevan `LICENSE`,
   `README.md`, `CHANGELOG.md` y tres documentos de `docs/`. Lo que dicen, literalmente,
   las licencias de las dependencias que van dentro del binario (sus textos completos
   están en `NOTICE`):
   - BSD-3-Clause: *«Redistributions in binary form must reproduce the above copyright
     notice, this list of conditions and the following disclaimer in the documentation
     and/or other materials provided with the distribution.»*
   - MIT: *«The above copyright notice and this permission notice shall be included in
     all copies or substantial portions of the Software.»*
5. **Los vectores de prueba RFC 6962** (`testdata/vectors/merkle/rfc6962`) no tienen
   registrado el repositorio del que se tomaron. Los de SLIP-0039 sí (el de Trezor).
6. **`SECURITY.md` anuncia el reporte privado de vulnerabilidades de GitHub**, que según
   [`TODO.md`](../../TODO.md) está pendiente de activar. El buzón
   security@nucleoledger.com está operativo.
