# NÚCLEO — Documento de Concepto v1.2 (FINAL, listo para arranque)

*Capa de integridad criptográfica para software · Documento fundacional · 31 de agosto de 2026*

> **Cambios respecto a v1.1:** las cinco cuestiones de protocolo pasan de "abiertas" a **decididas** con investigación fundamentada (§9, matriz de decisiones); adopción del ecosistema **C2SP** como base del protocolo (§5.2); stack verificado pieza por pieza con procedencia (§10); regla de redacción LOPDP (§6.1); hoja de ruta con Fase 0 de prueba de concepto (§17); incertidumbres restantes reducidas a mediciones de laboratorio (§16). Este documento queda congelado hasta el arranque; cualquier cambio posterior será por ADR.

---

## 0. Resumen en un párrafo

Núcleo es una capa de integridad criptográfica de código abierto que cualquier desarrollador integra en su software para que los registros importantes queden sellados en el instante en que ocurren — hasheados, encadenados, firmados y cifrados — de modo que ninguna alteración posterior del pasado sea posible sin dejar evidencia matemática detectable y demostrable. No es blockchain, no es una base de datos nueva ni un servicio en la nube: es un motor local (`nucleod`, en Go) y una familia de clientes delgados que acompañan al sistema que ya existe, reconcilian periódicamente los datos vivos contra lo sellado, y entregan recibos firmados a las partes interesadas que sobreviven aunque el sistema original sea alterado o destruido. Es un **transparency log C2SP-compatible**: sus raíces las cosignan testigos del ecosistema abierto y sus pruebas las lee cualquier verificador estándar. Protege al que tiene la llave o el recibo del que no los tiene. El core es universal (inglés, AGPLv3); los perfiles de dominio lo aterrizan en Ecuador primero (español). El creador no opera infraestructura; el negocio vive de licencias comerciales a quien lo embebe en software cerrado. A quien altere un registro le queda una sola pregunta sin respuesta: *explíqueme por qué el sello no coincide.*

## 1. Problema

Toda organización guarda sus registros en bases de datos que cualquier persona con acceso suficiente puede alterar sin dejar rastro. Los sistemas registran datos pero no pueden **demostrar** que esos datos no cambiaron después. El problema se agrava con la IA generativa, capaz de fabricar documentos y registros indistinguibles de los reales: la pregunta "¿esto es lo que realmente pasó?" ya no se responde mirando el archivo. En Ecuador el diagnóstico existe hace años en la academia (blockchain para notarías, registros, documentos académicos) sin materializarse como herramienta general; las certificadoras locales venden identidad y fecha cierta, no historial íntegro.

## 2. Tesis

La única defensa contra la reescritura del pasado es sellar los registros criptográficamente **en el momento en que ocurren**. Un hash encadenado, firmado y atestiguado no puede fabricarse retroactivamente. Núcleo empaqueta esa capacidad como una librería que cualquier desarrollador usa sin saber criptografía.

## 3. Qué es y qué no es

### 3.1 Cinco capacidades
| Capacidad | Qué hace |
|---|---|
| **Sellar** (`seal`) | Hashea el registro, lo encadena, lo firma con la llave de la organización, lo incorpora al árbol de Merkle |
| **Cifrar** | Datos sensibles cifrados en reposo; el ledger solo expone compromisos no adivinables |
| **Verificar** (`verify`, `exportProof`) | Pruebas exportables (formato tlog-proof) verificables offline por terceros con herramientas públicas |
| **Reconciliar** (`reconcile`) | Compara periódicamente los datos vivos contra lo sellado y reporta qué cambió y desde cuándo |
| **Emitir recibos** (`issueReceipt`) | Comprobantes firmados para partes interesadas, independientes del servidor que los generó |

### 3.2 Qué NO es
Blockchain ni criptomonedas; una base de datos que haya que adoptar; un servicio en la nube; un sustituto del SRI, notarios o firmas acreditadas; una garantía contra quien controla todo — garantiza que nadie altere **sin dejar evidencia**.

### 3.3 Universalidad y foco
El core sella cualquier registro de cualquier sistema en cualquier país; no contiene nada de Ecuador. La **v1 es deliberadamente pequeña** (core + perfil Ecuador + demo del criterio de éxito) por disciplina, no por alcance: cada nuevo ámbito es un perfil sobre el mismo core.

## 4. Actores y casos de uso

**Actor principal:** el desarrollador integrador (la criptografía le es invisible). **Secundarios:** dueño del negocio (estado de integridad), partes interesadas (recibos), auditor/perito (verifica pruebas con herramientas públicas).

| CU | Escenario | Resultado con Núcleo |
|---|---|---|
| CU-1 Fraude interno | Empleado altera una venta meses después | Reconciliación detecta la discrepancia; reporta registro, fecha de sellado y valor original |
| CU-2 Actas SAS | Socio controlador presenta un acta "corregida" | Cada socio conserva su recibo firmado del original |
| CU-3 Custodia contable | Auditoría sobre XML conservados 7 años | Lo conservado se demuestra idéntico a lo emitido |
| CU-4 Software de terceros | ERP/facturación quiere "registros a prueba de alteraciones" | Embebe Núcleo bajo licencia comercial |
| CU-5 Disputa con proveedor | "Tu sistema perdió mis datos" | Se demuestra que la alteración fue posterior al sellado, del lado del cliente |
| CU-6 Catastro/predios | Funcionario altera la ficha de un predio | El software municipal con Núcleo lo detecta; el propietario puede recibir recibo de cada cambio |

## 5. Arquitectura

### 5.1 Componentes
- **`nucleod`** (Go, binario único): ledger append-only (SQLite), llaves, cifrado, Merkle, pruebas, recibos, reconciliación, cliente/servidor de testigos.
- **Clientes por lenguaje** (§11): `seal`, `verify`, `reconcile`, `issueReceipt`, `exportProof`, `status`.
- **Verificador standalone** (CLI + HTML estático): valida un tlog-proof sin `nucleod` y sin confiar en el creador.
- **Perfiles de dominio**: `sri.factura.v1`, `sas.acta.v1`, `catastro.predio.v1`, `notaria.protocolo.v1`, …

### 5.2 Estándares fijados (ACTUALIZADO: base C2SP)
| Aspecto | Decisión |
|---|---|
| **Raíz firmada del log** | **C2SP tlog-checkpoint** (nota firmada: origin, tree size, root hash) |
| **Firma de testigos** | **C2SP tlog-cosignature v1** (timestamped_signature de 72 bytes: u64 timestamp + firma Ed25519) |
| **Protocolo de testigos** | **C2SP tlog-witness** (HTTP síncrono; persistencia atómica del checkpoint antes de responder — previene la carrera de rollback) |
| **Recibo / paquete de prueba** | **C2SP tlog-proof** (checkpoint cosignado + índice + inclusion proof + extra data; verificable offline como "firma transparente") |
| **Almacenamiento del árbol** | **C2SP tlog-tiles** para segmentos archivados; caché de subárboles en SQLite para el segmento activo |
| Merkle y pruebas | RFC 6962 (SHA-256, prefijos 0x00/0x01) / RFC 9162 (inclusión y consistencia §2.1.4) |
| Canonicalización | RFC 8785 (JCS), implementación nativa propia, vectores oficiales como tests |
| Firma del log | Ed25519 (obligatoria para interoperar con testigos públicos) **+ ML-DSA-44 como segunda firma post-cuántica** (`crypto/mldsa`, stdlib Go 1.27; los verificadores ignoran firmas desconocidas, así que añadirla no rompe nada) |
| Compromisos de datos adivinables | **VRF `c2sp.org/vrf-r255`** para lo verificable por terceros; HMAC-SHA-256 con clave para lo interno |
| Cifrado en reposo | XChaCha20-Poly1305 (nonce 24 B aleatorio; AAD = tenant ‖ payload_hash); KEK por Argon2id → DEK aleatoria por bóveda |
| Respaldo de llaves | **SLIP-0039** umbral 2-de-3 (3-de-5 para más socios) protegiendo la KEK; rotación de identidad como bloque especial firmado por la llave saliente |
| Documentos externos (XML SRI, PDF) | Hasheados byte a byte, nunca re-canonicalizados |
| Índices | ≤ 2⁵³ − 1 |
| Almacenamiento | SQLite (Go puro), append-only con triggers anti UPDATE/DELETE, WAL, synchronous=FULL, un solo escritor |

### 5.3 Modelo de confianza en capas (sin infraestructura del creador)
1. **Cadena local sellada** — detecta ediciones.
2. **Recibos firmados (tlog-proof)** a contrapartes — sobreviven a la destrucción del sistema. El QR del recibo lleva **URL a verificador estático + hash** (el proof completo de ~0.9–1.6 KB cabe en QR v40 pero resulta poco legible; medición final en laboratorio).
3. **Testigos mutuos C2SP** — instancias de Núcleo (u otros testigos del ecosistema, p. ej. redes públicas tipo ArmoredWitness) cosignan raíces entre sí; cada testigo guarda O(1) por log vigilado; quórum configurable vía tlog-policy.
4. **TSA RFC 3161 opcional** — freetsa/DigiCert en desarrollo; TSA acreditada por ARCOTEL (Security Data, ANF, BCE/ECIBCE — todas requieren contrato) solo si un caso con valor legal reforzado lo exige.

**Regla de tiempo:** el timestamp local del bloque es **tiempo declarado**; el **tiempo demostrable** es el mínimo de los timestamps de cosignatures de testigos (y tokens TSA si existen). El recibo muestra ambos con etiquetas separadas.

Complemento: **reconciliación programada** — sellar en el punto de creación (misma transacción que crea el registro) y preferir como entrada documentos ya firmados por terceros (XML del SRI) para minimizar la ventana previa al sellado.

## 6. Modelo de amenazas

**Derrota:** empleado que altera registros (reconciliación); administrador que edita el ledger (`verify`); reescritura y refirma total de la cadena (recibos + testigos: la raíz no coincide con la cosignada); documentos fabricados con IA "de época" (no pueden fabricar presencia en una cadena sellada antes); robo de disco/backup (blobs cifrados).

**No derrota (declarado):** el dueño de todo sin recibos emitidos (cada recibo lo reduce); datos falsos desde el origen (se certifica el *cuándo* y el *sin cambios*, no el *es verdad*); compromiso de la máquina antes del sellado (ventana minimizada, no eliminada).

### 6.1 Regla de redacción legal (LOPDP)
El ledger nunca contiene datos personales: solo compromisos no adivinables (VRF/HMAC); los datos viven en blobs cifrados **borrables** (derecho de supresión: se elimina blob + llave; el compromiso residual no es reversible). La documentación dice **"diseñado para alinearse con la LOPDP"** — afirmación técnica demostrable — y no "cumple/certificado", hasta contar con dictamen legal ecuatoriano (mejora futura de credibilidad, no bloqueo). Igual criterio con ISO/IEC 27001 y 27037: alineación declarada y verificable, sin reclamar certificación.

## 7. Modelo de negocio

Core abierto (AGPLv3: credibilidad + distribución; da derecho a reclamar contra quien modifique/redistribuya sin liberar, no contra el uso como proceso aparte — a ese se le ofrece la comercial). **Licencia comercial anual** a quien embebe Núcleo en software propietario (marca registrada, soporte, actualizaciones; el token JWT es constancia, no DRM). Servicios de integración opcionales. **Costo operativo del creador: $0.**

**Competencia:** Ecuador: ninguna. Mundo: immudb (motor propio que exige adoptarse; sin recibos offline a terceros; v1.11 de mayo-2026 añade audit logging), Rekor v2 (supply-chain, infraestructura de Sigstore), OpenTimestamps/SaaS de sellado (dependen de blockchain o servidor del proveedor). **Diferenciadores de Núcleo:** capa que acompaña lo existente; recibos a contrapartes; reconciliación datos vivos vs. sellados; 100% on-premise sin servidor del creador; perfiles de país; C2SP-compatible.

## 8. Idiomas y alcance

Core, API, protocolo y documentación técnica en **inglés**; perfiles, guías, recibos y venta en **español**, Ecuador primero. v1 = core + perfil Ecuador + demo del criterio de éxito.

## 9. Matriz de decisiones (las cinco cuestiones, CERRADAS)

| # | Cuestión | Decisión | Fundamento | Confianza |
|---|---|---|---|---|
| 1 | Recuperación de llaves | SLIP-0039 2-de-3 (o 3-de-5) para la KEK, tarjetas impresas con UX guiada; rotación de identidad como bloque firmado por la llave saliente; si la llave ya no existe: nueva identidad anclada a testigos + acta de socios | Shamir 1979; SLIP-0039 (SatoshiLabs); patrón de círculos rwot8; práctica de Vault | Media-alta (riesgo: usabilidad pyme → UX de respaldo es requisito de v1) |
| 2 | Tiempo declarado vs. demostrable | Dos campos en el recibo; demostrable = mín. timestamps de cosignatures C2SP (y TSA si hay); testigos como fuente primaria gratuita; TSA ARCOTEL solo bajo demanda de caso | tlog-cosignature v1 (timestamp firmado del testigo); Haber & Stornetta 1991; RFC 3161; verificado: ninguna TSA ecuatoriana es abierta sin contrato | Alta |
| 3 | Hashes adivinables / LOPDP | VRF `vrf-r255` para compromisos verificables por terceros; HMAC para lo interno; blobs cifrados borrables; redacción "alineado con LOPDP" | RFC 9381; keyserver de Valsorda (dic-2025); Resolución SPDP-SPD-2025-0030-R; doctrina seudonimización GDPR/AEPD | Media-alta (dictamen legal como mejora futura) |
| 4 | Entornos sin daemon | **CLI invocable como modo primario** (`nucleo seal …`), daemon opcional para VPS, módulo Go importable; SQLite Go puro; API descrita en OpenAPI para clientes delgados (TS→PHP→Python→Java); Wasm pospuesto (Argon2id costoso) | CloudLinux/CageFS/LVE bloquea daemons en shared hosting; patrón restic/age; benchmarks modernc.org/sqlite (1.2–2×, aceptable) | Alta |
| 5 | Crecimiento del ledger | Cierre de períodos (mensual/anual según volumen) con checkpoint atestiguado; segmentos históricos archivados como tiles estáticos; verificación de la cadena de segmentos por pruebas de consistencia RFC 9162 §2.1.4 | Modelo de shards anuales de Rekor v2 (GA oct-2025); tlog-tiles; Tessera | Alta |

**Decisiones de diseño adicionales cerradas:** recibo = tlog-proof con QR URL+hash; formato de intercambio = C2SP nativo (exportación a Sigstore bundle como función futura, no dependencia); conectores de reconciliación por base de datos = v2 / candidata a exclusiva comercial (en v1, `reconcile()` recibe los datos del integrador con contrato simple); red de testigos mutuos = protocolo tlog-witness estándar (interoperable con testigos públicos existentes).

## 10. Stack verificado (procedencia y regla de confianza)

| Capa | Elección | Procedencia |
|---|---|---|
| Lenguaje | **Go 1.27+** (19-ago-2026) | Equipo de Go |
| Notas/checkpoints | `golang.org/x/mod/sumdb/note` | Equipo de Go |
| Log tiles / Merkle | `transparency-dev/tessera` (backend POSIX), `transparency-dev/merkle`, `filippo.io/torchwood` | Google transparency-dev; F. Valsorda (mantenedor cripto de Go) |
| Firma clásica | `crypto/ed25519` | stdlib |
| Firma PQ | `crypto/mldsa` (stdlib 1.27) · fallback `cloudflare/circl` | Equipo de Go · Cloudflare |
| VRF | `filippo.io/mostly-harmless/vrf-r255` | F. Valsorda |
| Shamir/SLIP-0039 | `hashicorp/vault/shamir` + candidato SLIP-0039 (`gavincarr/go-slip39` vs `shurlinet/go-slip39`, este último constante-tiempo pero con código generado por IA revisado — evaluar con rigor extra) | HashiCorp · comunidad (validación propia obligatoria) |
| Cifrado | `x/crypto/chacha20poly1305`, `x/crypto/argon2` | Equipo de Go |
| SQLite | `modernc.org/sqlite` (Go puro) · alt. `ncruces/go-sqlite3` | Comunidad consolidada |
| JCS | Implementación propia (Sprint 1, vectores RFC oficiales en verde) | Propia |

**Regla de confianza:** procedencia de primera línea **y** verificación en casa — versiones fijadas, `govulncheck` en CI, y cada biblioteca validada contra nuestros vectores (`testdata/vectors/`: RFC 8785, RFC 6962/9162, SLIP-0039 oficiales, cosignatures) antes de entrar a la ruta crítica.

## 11. Estrategia multi-lenguaje

Un solo core criptográfico; clientes delgados sobre la API local (OpenAPI). Orden: TypeScript (referencia) → PHP (parque de facturación; usa el modo CLI en shared hosting) → Python → Java/Kotlin → módulo Go nativo → resto generado desde OpenAPI. El verificador de pruebas se reimplementa por lenguaje contra los vectores compartidos.

## 12. Calidad y automatización

Unitario (vectores conocidos, `-race`); fuzzing nativo (JCS y parser de bloques); suite de ataque que ejecuta el modelo de amenazas y exige detección; compatibilidad byte a byte entre lenguajes vía vectores; benchmarks (`sellos/segundo`, tamaño de proof) en CI; matriz Linux/macOS/Windows; releases firmados (goreleaser + cosign); golangci-lint + govulncheck.

## 13. Alternativas consideradas (registro)

Blockchain/tokens (dependencia, desconfianza, costo → testigos y recibos); servicio de anclaje central propio (contradice el modelo → puede reaparecer como servicio de terceros); core en TypeScript (→ Go por binario único y aislamiento cripto); base inmutable completa estilo immudb (exige migrar → acompañar); cgo/N-API (→ API local); formato de prueba propio (→ C2SP); Sigstore bundles como base (→ C2SP nativo, export futuro); Wasm primario (→ pospuesto).

## 14. Riesgos del proyecto

| Riesgo | Mitigación |
|---|---|
| Desarrollador solo, otros proyectos | Documentos congelados + vectores + CI: pausable y retomable; las IAs implementan dentro del contrato |
| Adopción | Criterio de éxito = demo de integración en 1 hora; documentación como producto |
| Bug criptográfico | Vectores compartidos, fuzzing, revisión adversarial pre-release |
| Alcance infinito | v1 pequeña; todo lo demás son perfiles/clientes posteriores |
| Deriva entre IAs | Este documento + PROTOCOL.md + ADRs como fuente de verdad |

## 15. Dimensión académica

Tesis/paper sin desviar el desarrollo (la evaluación del paper = fases E–J). **Contribuciones:** (1) primer transparency log C2SP para registros empresariales on-premise sin infraestructura del proveedor, con recibos y testigos mutuos; (2) reconciliación datos vivos vs. sellados como detector de fraude interno; (3) core universal + perfiles de país + clientes delgados; (4) evaluación contra modelo de amenazas y benchmarks; (5) conciliación inmutabilidad/LOPDP vía compromisos VRF y blobs borrables (contrapunto a las propuestas blockchain ecuatorianas). **Venues:** arXiv (cs.CR) + revista indexada (Uniandes Episteme, Cálamo, Enfoque UTE, Revista Politécnica) o CLEI/TICEC.

## 16. Incertidumbres restantes (ninguna bloquea el arranque)

1. **Medibles solo en laboratorio** (Fase 0): tamaño real del tlog-proof, sellos/segundo, legibilidad de QR, rendimiento SQLite Go puro en hardware de pyme.
2. **Endpoint ICERT-EC** (`tsa.icert.fje.gob.ec:8020`): experimento de 20 minutos con una petición RFC 3161 real, el día que toque la capa TSA.
3. **Dictamen LOPDP** sobre el compromiso VRF residual: mejora futura de credibilidad; mientras tanto rige §6.1.
4. **Selección final SLIP-0039**: la que pase los 45 vectores oficiales en nuestra suite.

## 17. Hoja de ruta (ACTUALIZADA)

| Fase | Contenido | Naturaleza |
|---|---|---|
| **B. Nombre** | Disponibilidad npm/GitHub/dominio; nombre de paquete y binario | Media hora |
| **C. Documentos** | Este documento (inglés para el repo) + PROTOCOL.md congelado + ADRs 001–007 (C2SP, tiempo, VRF, SLIP-0039, CLI-primario, segmentos, ML-DSA-44) + OpenAPI | Papel |
| **D. Laboratorio** | Monorepo Go 1.27, Taskfile, lint, fuzzing, `testdata/vectors/`, CI multiplataforma, releases firmados | Configuración |
| **E. Fase 0 — Prueba de concepto** | Log tlog-tiles (Tessera POSIX + Torchwood) sobre el core del Sprint 1; checkpoint Ed25519; tlog-proof como recibo; verificación offline con tlog-policy de 1 log + 1 testigo simulado. **Resuelve las incertidumbres medibles** | Construcción corta |
| **F. Sprint 2** | `store` (append-only + caché de subárboles) + `vault` (KEK/DEK, SLIP-0039) + recibos | Construcción |
| **G. Sprint 3** | Testigos mutuos (tlog-witness real, quórum 2) + regla de tiempo + reconciliación + consistencia entre segmentos + ML-DSA-44 adicional | Construcción |
| **H. Sprint 4** | CLI primario + daemon opcional + cliente TS + verificador standalone (CLI y HTML estático con QR) | Construcción |
| **I. Sprint 5** | Perfil Ecuador (VRF en campos sensibles), documentación completa, sitio, licenciamiento, demo del criterio de éxito | Producto |
| **J. Clientes** | PHP → Python → Java | Expansión |
| **K. Piloto** | Mini sistema con Núcleo integrado (VPS propio, demostrativo) | Validación |
| **L. Publicación** | Preprint + artículo con la evaluación de E–K | Académico |

## 18. Criterio de éxito de la v1

Un desarrollador cualquiera, sin saber criptografía, integra Núcleo en menos de una hora siguiendo la documentación; sella registros; altera uno a propósito en su base; la reconciliación se lo detecta y se lo explica; y un recibo emitido se verifica en el verificador estático desde un teléfono. Si esa demo funciona de punta a punta, el producto existe.

## 19. Protocolo de arranque

El proyecto permanece en análisis hasta la palabra **"comenzamos"**. A partir de esa señal se ejecuta §17 en orden estricto (B → C → D → E → …), sin saltar fases y sin construir nada cuyo formato no esté congelado en PROTOCOL.md.

---

*Contrato de visión del proyecto. Toda decisión posterior debe ser coherente con este documento o modificarlo explícitamente mediante ADR.*
