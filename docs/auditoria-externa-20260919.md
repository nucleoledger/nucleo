# Auditoría externa técnica — 2026-09-19

Revisión independiente de seguridad sobre `github.com/nucleoledger/nucleo`, `PROTOCOL.md` 0.5-draft y ADR-014 a ADR-024.

Commit revisado localmente: `ffd5cf19a97b134c71bacc3c5270ab7bca3b7d0a`.

Alcance pedido: no generar entradas manipuladas nuevas; ejecutar la maquinaria que el repositorio ya trae y evaluar por lectura. El árbol local no estaba limpio al inicio porque otra sesión tenía `sdk/ts/package.json` modificado; este informe no toca ese fichero.

## Resumen ejecutivo

La revisión encontró un hallazgo alto en el SDK PHP: el sellador acepta una política en el constructor, pero no la pasa al binario `nucleo` como `--policy-file`. Eso degrada `seal` y `status` a modo sin política aunque el integrador crea haber configurado una raíz de confianza externa.

El verificador nativo de PHP resistió la revisión estática en los puntos críticos: política parseada sin `json_decode`, signed-note con gramática propia, base64/hex canónicos, enteros sin conversión a float, firma de bloque, firma de recibo, checkpoint, cosignatures y Merkle. La limitación de esta máquina es que no hay `php` instalado, así que no pude ejecutar la suite PHP ni el diferencial de tres verificadores localmente.

ADR-020, ADR-022 y ADR-023 están respaldados por código y tests en los caminos revisados. Las enmiendas documentales principales del README/PROTOCOL sobre anti-circularidad, privacidad del `payload_hash`, ML-DSA parcial, recibos de unos 5 KiB, atestación verificada y política como raíz de confianza son ahora sustancialmente ciertas. Queda una afirmación demasiado amplia: README dice que el perfil Ecuador incluye `sas.acta.v1` dentro de “What works today”, pero la CLI `seal --profile` solo expone `ecuador.sri.factura`.

## Pruebas ejecutadas

```text
go test ./... -race
```

Resultado: pasa. Paquetes Go principales en verde, incluyendo `cmd/nucleo`, `internal/store`, `internal/receipt`, `internal/proof`, `internal/logsync`, `internal/witness`, `internal/vault`, `profiles/ecuador`.

```text
npm test
```

Directorio: `sdk/ts`.

Resultado: pasa. `8` ficheros, `197` tests, Vitest `2.92s`.

```text
php sdk/php/test/run.php
```

Resultado: no ejecutado por entorno, falla con `php: command not found`.

```text
env NUCLEO_DIFERENCIAL_OUT=/tmp/opencode/nucleo-diff-20260919.json go test ./internal/receipt -run '^TestDiferencialGeneraCatalogo$' -count=1
node sdk/ts/scripts/diferencial.mjs /tmp/opencode/nucleo-diff-20260919.json
```

Resultado: pasa para Go y TypeScript; PHP no se comprobó por ausencia de intérprete.

Cifras reproducidas:

- Catálogo de políticas: `9.929`; Go acepta `2.569`, TS acepta `2.569`.
- Catálogo de bytes de recibo: `3.166`.
- Catálogo de recibos re-firmados por el emisor: `148`.
- Mutaciones de recibo: `3.314`; Go acepta `56`, TS acepta `56`.
- Divergencias de dictamen Go/TS: `0`.
- Excepciones TS: `0`.
- PHP: `NO SE COMPROBÓ: no hay PHP ejecutable (php)`.

```text
python3 testdata/vectors/receipt/generar.py --check
```

Resultado: pasa. `18 vectores coinciden con el oráculo`.

```text
python3 testdata/vectors/policy/generar.py --check
```

Resultado: pasa. `64 vectores; 11 válidos`.

```text
./scripts/demo-criterio-exito.sh /tmp/opencode/nucleo-demo-20260919
```

Resultado: pasa. Los 7 pasos del criterio de éxito de v1 terminan en verde.

## Hallazgos

### Alta — PHP Sealer recibe `policyFile`, pero nunca usa `--policy-file`

Archivos:

- `sdk/php/src/Sealer.php:26`
- `sdk/php/src/Sealer.php:40-47`
- `sdk/php/src/Sealer.php:65-74`
- `sdk/php/src/Sealer.php:107-110`
- `sdk/php/src/Sealer.php:121-125`
- `cmd/nucleo/seal.go:32`
- `cmd/nucleo/seal.go:80-85`

`Sealer` almacena `private ?string $policyFile`, el constructor lo acepta y lo guarda, pero `seal()` arma los argumentos sin `--policy-file`, y `status()` llama solo a `status`. `run()` antepone `[$binary, '--dir', $dir, '--json']` y ejecuta exactamente lo que recibió.

Impacto: un ERP puede configurar el wrapper con una política creyendo que `seal` y `status` abren el ledger bajo la política externa de ADR-017, pero el binario se ejecuta sin ella. El resultado operativo es más débil: atestación/frescura/identidad no se verifican contra esa política y pueden salir como no verificadas o degradadas. Lo grave no es que el CLI falle abierto: el CLI necesita `--policy-file` explícito. Lo grave es que el wrapper ofrece un parámetro que aparenta hacerlo y no lo hace.

Prueba automatizada faltante:

- Test PHP con binario falso que capture argv y demuestre que `new Sealer(..., $policyFile)->seal()` incluye `--policy-file <path>`.
- Test equivalente para `status()`.
- Test end-to-end con `NUCLEO_BIN` donde `SealResult::$attested` o `raw['attestation']` cambie al suministrar política válida.

### Media — `SealResult::fromJSON()` acepta basura o esquemas rotos por casts laxos

Archivos:

- `sdk/php/src/SealResult.php:25-37`
- `sdk/php/src/Sealer.php:169-180`

`SealResult::fromJSON()` convierte campos con `(int)`, `(string)`, `(bool)` y defaults silenciosos. Si falta `index`, queda `-1`; si falta `encrypted`, `attested` o `freshness.stale`, quedan `false`; `duplicate_of` se procesa con `array_map('intval', ...)`.

Impacto: no rompe criptografía ni el ledger. Sí afecta automatización: un binario equivocado, antiguo, comprometido o una salida truncada podría producir un objeto PHP aparentemente utilizable. En un producto de integridad, el wrapper debe fallar cerrado ante un contrato JSON inesperado.

Prueba automatizada faltante:

- `SealResult::fromJSON()` debe rechazar campos obligatorios ausentes.
- Debe rechazar tipos incorrectos: `index` no entero, hashes no hex de 64, booleanos no booleanos, `duplicate_of` no array de enteros, `freshness` no objeto.
- Binario falso que devuelva `{"ok":true}` debe provocar excepción, no `SealResult` con defaults.

### Baja — README sobreexpone `sas.acta.v1` como “works today” en la CLI

Archivos:

- `README.md:69`
- `profiles/ecuador/tipos.go:141-186`
- `cmd/nucleo/profile.go:21-32`

README dice en “What works today” que el perfil Ecuador incluye `sri.factura.v1` y `sas.acta.v1`. El paquete `profiles/ecuador` sí define `TipoActa`, `Acta` y `ParseActa`, con tests, pero la CLI `seal --profile` solo reconoce `ecuador.sri.factura`; cualquier otro perfil cae en `perfil desconocido ... los disponibles son: ecuador.sri.factura`.

Impacto: deriva documental/producto, no vulnerabilidad criptográfica. Un integrador leyendo README puede creer que `seal --profile ecuador.sas.acta` existe hoy. Si la intención es “el paquete lo modela, pero la CLI todavía no lo expone”, README debe decirlo así.

Prueba automatizada faltante:

- Test CLI que fije la lista de perfiles expuestos y, si se decide exponer actas, test de `seal --profile ecuador.sas.acta` con JSON válido.

## Áreas que resistieron la revisión

### Verificador nativo PHP

Archivos principales: `sdk/php/src/Policy.php`, `sdk/php/src/Note.php`, `sdk/php/src/Bytes.php`, `sdk/php/src/Receipt.php`, `sdk/php/src/Verifier.php`, `sdk/php/src/Jcs.php`.

No encontré una aceptación más laxa que Go/TS por lectura en los puntos revisados:

- Política §3.2: no usa `json_decode` para el formato de cable; rechaza BOM, UTF-8 inválido, miembros duplicados tras unescape, variantes de mayúsculas, `null`, arrays donde no toca, quorum con fracción/exponente/cero y claves hex no canónicas.
- Signed-note §3.3: separa por el último `\n\n`, exige bloque de firmas no vacío terminado en LF, prefijo `— `, nombre sin `+` ni Unicode White_Space normativo, base64 canónico y máximo 100 firmas.
- Enteros: lee índices y tamaños con literales decimales canónicos y rechaza lo que no cabe en `int` de PHP, en vez de redondear a float.
- `__proto__` y mapas especiales: PHP representa witnesses como lista de pares, no como mapa asociativo de resultado.
- Firmas y Merkle: verifica firma de bloque, firma del recibo, firma del log, cosignatures conocidas, quórum por testigo único, tiempo más antiguo y prueba de inclusión con `leaf/v2`.

Limitación: esta conclusión es lectura estática más los vectores/diferencial Go/TS ejecutados. No pude ejecutar el PHP localmente.

### Sellador PHP envoltorio del binario

Lo sano: usa `proc_open()` con comando en array, no shell; la passphrase va por fichero, no por argv ni entorno; cierra stdin; comprueba `proc_open`, binario, directorio y permisos POSIX; el timeout advierte correctamente que el registro puede haberse escrito y recomienda reintentar con la misma clave de idempotencia.

Lo no sano es el hallazgo alto: omite `--policy-file` pese a almacenar la ruta.

### ADR-020 — idempotencia y atomicidad

Archivos: `cmd/nucleo/seal.go:102-115`, `cmd/nucleo/seal.go:148-190`, `internal/store/record.go:21-87`, `cmd/nucleo/idempotency.go:70-110`, `cmd/nucleo/reseal.go:25-59`, `cmd/nucleo/reseal.go:129-203`, `internal/store/record_test.go:36-92`, `cmd/nucleo/idempotency_test.go:36-342`.

Conclusión: la decisión está implementada. `AppendRecord` escribe blob, validación de encadenamiento, bloque, metadatos y `log_state` en una única transacción. Las pruebas cubren “todo o nada”, reintento tras fallo, duplicados, contenido de otro tenant, idempotencia por clave, manipulación de `log_state` y ausencia de jerga SQLite en errores de usuario.

La clave de idempotencia está acotada por tenant con `sha256(tenant || 0x00 || key)`, y el reintento no confía solo en `log_state`: lee el bloque apuntado y compara `payload_hash`, tenant y tipo.

No encontré una frontera de muerte donde quede bloque sin blob, blob huérfano nuevo, compromisos sin bloque o clave de idempotencia sin bloque en el camino actual.

### ADR-022 — identidad con metadatos ausentes

Archivos: `internal/store/integrity.go:471-505`, `internal/store/h7_test.go:19-114`.

Conclusión: el fallo original está cerrado. Con política que afirma `origin` o `logKey`, faltar `log/origin/v1` o `log/pubkey/v1` en `vault_meta` produce `ErrIdentityUnknown` dentro de error de integridad. La política que no afirma identidad sigue sin comparar nada, lo cual está documentado como comportamiento deliberado.

### ADR-023 — privacidad del `payload_hash`

Archivos: `docs/PROTOCOL.md:283-309`, `README.md:129-131`, `profiles/ecuador/tipos.go:117-137`, `profiles/ecuador/tipos.go:163-185`, `cmd/nucleo/profile.go:48-82`.

Conclusión: la documentación ya no afirma que el ledger o los recibos oculten un payload enumerable. PROTOCOL y README dicen explícitamente que `payload_hash` confirma una conjetura del documento completo y que los compromisos por campo no arreglan ese caso.

En el perfil de factura, los campos de baja entropía o personales (`identificacion_comprador`, `razon_social_comprador`, `importe_total`) van como compromisos HMAC y no como hashes desnudos. `sas.acta.v1` modela socios como compromisos, pero no está expuesto por la CLI hoy.

No encontré código que añada entropía automáticamente al payload, y eso coincide con ADR-023: Núcleo no debe sellar bytes distintos de los entregados por el integrador.

## Afirmaciones publicadas revisadas

Las siguientes enmiendas parecen ahora ciertas respecto del código revisado:

- El recibo ronda 5 KiB, no 1 KiB: README lo corrige y explica que 1.124 bytes era solo la sección `tlog-proof`.
- ML-DSA-44 está descrita como firma adicional del checkpoint del log, no como post-cuántico end-to-end.
- “Every golden value” está enmendado: README reconoce el problema histórico de los recibos y apunta al oráculo Python; el `--check` de recibos pasa con 18 vectores.
- La privacidad está matizada: `payload_hash` público confirma documentos enumerables y esto está en README y PROTOCOL.
- La atestación solo cuenta si se verifica con política externa; sin política se reporta como no verificada y no activa el fast path.
- La frescura sin política queda etiquetada como registro local no verificado.

Afirmación aún demasiado amplia:

- `README.md:69` presenta `sas.acta.v1` junto a `sri.factura.v1` en “What works today”. Como biblioteca de perfil existe; como perfil CLI no.

## Cobertura faltante recomendada

1. Test de argv del `Sealer` PHP, incluyendo `--policy-file` en `seal()` y `status()`.
2. Test de contrato estricto para `SealResult::fromJSON()`.
3. Suite PHP en entorno local/CI con `NUCLEO_BIN` para cubrir sellado real desde PHP, no solo vectores de verificación.
4. Diferencial con PHP exigido (`NUCLEO_DIFERENCIAL_EXIGE_PHP=1`) en toda máquina que pretenda reproducir la afirmación de tres verificadores.
5. Test o documentación explícita sobre `sas.acta.v1`: exponerlo en CLI o dejar claro que es modelo de paquete todavía no cableado a `seal --profile`.

## Veredicto

El árbol actual está bastante más maduro que el auditado el 2026-09-13. Las correcciones de H7/H8/H10 están respaldadas por código, tests y texto normativo. El punto débil nuevo está donde era esperable: el SDK PHP, por ser el más joven y por envolver un binario externo.

Prioridad de corrección antes de auditoría profesional pagada: arreglar `Sealer::$policyFile` y endurecer `SealResult`. Después, ejecutar la suite PHP y el diferencial de tres verificadores en un entorno con `php` y `ext-sodium`.
