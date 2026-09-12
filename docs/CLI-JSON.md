# El contrato de `--json`

`nucleo --json <subcomando>` escribe en **stdout** exactamente un objeto JSON,
indentado, y nada más. Todo lo que es para personas —avisos, explicaciones, el
snippet de la política— va por **stderr** o se omite. Este documento es el
contrato de ese objeto: qué campos hay, qué significan y cuáles no van a cambiar
sin aviso en el CHANGELOG.

Lo que sigue se comprobó contra la CLI del commit que lo acompaña. Los tests de
`cmd/nucleo` (`freshness_test.go`, `policy_test.go`, `stale_test.go`, `cli_test.go`)
afirman cada campo aquí descrito; si esto y el binario discrepan, es un bug.

## Convenciones

- **`ok`** (bool) va en todos los objetos. `true` cuando el subcomando hizo su
  trabajo. En un error, el objeto es `{"ok": false, "error": "...", "exit_code": N}`
  y el código de salida del proceso es `N`: `1` uso, `2` verificación/integridad,
  `3` sincronización fallida. `reconcile` con hallazgos emite su informe completo
  con `ok: false` y sale con `2`.
- **Los avisos de frescura salen por stderr también con `--json`.** Es deliberado:
  un cron con stdout a un fichero y stderr al correo hace sonar la alarma sin
  programar nada. El mismo veredicto está en `freshness` para quien parsea.
- **Claves en hex minúscula**, 64 caracteres (Ed25519, 32 bytes). Hashes SHA-256
  en hex, 64 caracteres. Instantes en RFC 3339, UTC.
- **Estabilidad.** Los campos documentados aquí no se renombran ni cambian de
  tipo sin una entrada en el CHANGELOG. Pueden **añadirse** campos; quien parsea
  debe ignorar los que no conoce. Los códigos de salida no cambian.

## Objetos compartidos

### `signer` — el firmante de los bloques (ADR-017)

```json
"signer": {"state": "verified", "verified": true, "pubkey": "9ad2…f004"}
```

| campo | tipo | significado |
|---|---|---|
| `state` | `"none"` \| `"unverified"` \| `"verified"` | `none`: no hay bloques. `unverified`: una sola clave firma toda la cadena (la continuidad se comprueba siempre), pero nadie aportó `signerKey` para decir cuál tenía que ser. `verified`: es la de la política. |
| `verified` | bool | `state == "verified"`. |
| `pubkey` | hex | La clave que firma la cadena (la del bloque 0). Vacía sin bloques. |

Una cadena reescrita **entera** por otra clave es autoconsistente: solo la
política la distingue. Sin `signerKey`, `unverified` es lo honesto.

### `attestation` / `attested` / `attested_size` — qué respalda la historia (ADR-016)

| campo | tipo | significado |
|---|---|---|
| `attestation` | `"none"` \| `"unverified"` \| `"verified"` | `none`: ningún checkpoint cosignado. `unverified`: hay uno con la firma del log correcta, pero no se aportó política de testigos o la cosignature no verifica bajo ella. `verified`: la cosignature verificó contra la clave del testigo de la política. |
| `attested` | bool | `attestation == "verified"`. Solo entonces hubo atajo en la apertura. |
| `attested_size` | entero | Bloques que cubre el checkpoint considerado. Con `unverified` es lo que el checkpoint **afirma**, no lo comprobado. |

### `freshness` — hace cuánto vio un tercero esta historia

```json
"freshness": {
  "stale": false, "threshold_hours": 72, "attested_ever": true,
  "verified": true, "source": "attestation",
  "attested_at": "2026-09-12T18:20:07Z", "attested_size": 3,
  "witness": "witness.nucleoledger.com/w1", "age_hours": 0.02
}
```

| campo | tipo | significado |
|---|---|---|
| `stale` | bool | La última atestación es más vieja que el umbral, o nunca hubo. `false` en un ledger vacío. |
| `threshold_hours` | número | `--stale-after`, por omisión 72. |
| `attested_ever` | bool | Hay alguna fecha que juzgar: atestación verificada o registro local. |
| `verified` | bool | **De dónde sale la fecha.** `true`: de la cosignature que la apertura acaba de verificar bajo la política. `false`: del registro local que dejó el último `sync` en `log_state` — lo escribe quien tenga la base, y la segunda auditoría adversarial lo escribió con un testigo inventado. |
| `source` | `"attestation"` \| `"local_record"` \| `"none"` | Lo mismo, con nombre. |
| `attested_at` | RFC 3339 | El instante que afirmó el testigo (nunca el reloj local). |
| `attested_size` | entero | Bloques cubiertos por esa atestación. |
| `witness` | string | Testigo(s) de esa atestación, separados por `", "` si son varios. |
| `age_hours` | número | `ahora − attested_at`; `0` si está en el futuro. |
| `recorded_at` | RFC 3339 | Solo con `source: "local_record"`: cuándo se escribió el registro, según el reloj local. |
| `clock_skew` | bool | Presente y `true` si `attested_at` está en el futuro: un reloj mal puesto, no un ataque. |

**La frescura está subordinada a la atestación.** Un cron que mire `stale`
sin mirar `verified` se está fiando de este disco. Con `--policy-file` la fecha
sale de la cosignature y el registro local ni se lee.

### `policy` — la política lista para guardar (ADR-017 c)

El mismo formato que consumen `--policy-file`, el SDK de TypeScript y la
página web:

```json
"policy": {
  "origin": "nucleoledger.com/mi-empresa",
  "logKey": "9ad2…f004",
  "signerKey": "5e1c…a2b7",
  "witnesses": {"witness.nucleoledger.com/w1": "2f7a…9c31"},
  "quorum": 1
}
```

## Por subcomando

### `init`

| campo | tipo |
|---|---|
| `origin`, `dir` | string |
| `tenant_pubkey`, `log_pubkey` | hex |
| `shares` | array de mnemónicos SLIP-0039 (**secretos**: no van a un log) |
| `threshold` | entero |
| `kdf` | `{profile, memory_mib, iterations, parallelism}` |

### `status`

| campo | tipo |
|---|---|
| `dir`, `origin` | string |
| `leaf_rule` | `"leaf/v1"` \| `"leaf/v2"` (PROTOCOL §2.1) |
| `log_pubkey` | hex — la clave del log que **declara el fichero**; compárala con tu política, no la copies de aquí |
| `signer_pubkey` | hex — la del firmante de bloques (de la cadena si hay bloques, de `vault_meta` si no) |
| `tree_size` | entero |
| `root` | hex — raíz de Merkle actual |
| `attestation`, `attested`, `attested_size` | ver arriba |
| `signer` | objeto, ver arriba |
| `freshness` | objeto, ver arriba |

### `verify`

Como `status` menos la identidad, más `mode`: `"apertura"` (verificación de la
apertura, con atajo solo si `attested`) o `"exhaustiva"` (`--full`: todas las
firmas recomputadas). Campos: `mode`, `tree_size`, `attestation`, `attested`,
`attested_size`, `signer`, `freshness`. Sale con `2` si la integridad falla; la
frescura **no** cambia el código.

### `seal`

| campo | tipo |
|---|---|
| `index` | entero — el bloque recién sellado |
| `hash` | hex — hash del bloque |
| `payload_hash` | hex — SHA-256 del contenido |
| `encrypted` | bool — `false` con `--clear` (solo queda el hash) |
| `profile`, `metadata`, `commitments` | solo con perfil (`sri.factura.v1`, `sas.acta.v1`) |
| `attestation`, `attested`, `attested_size`, `signer`, `freshness` | **el estado de la historia sobre la que se acaba de escribir**, con la misma semántica que `status`. El bloque recién sellado **no** está cubierto por la atestación: lo cubrirá el próximo `sync`. |

### `receipt`

| campo | tipo |
|---|---|
| `block` | entero |
| `recipient` | string — a quién se entrega (etiqueta; no prueba entrega, ADR-015) |
| `bytes` | entero |
| `receipt` | string — el recibo entero, tal cual se escribió |
| `out` | string — ruta escrita, o vacío |
| `cosigners` | array de nombres de testigo cuya cosignature verificó |
| `provable_time` | RFC 3339 — tiempo demostrable (ADR-002), o vacío si no hay cosignature aceptada |

### `reconcile`

El informe de `internal/reconcile` más el estado de la historia:

| campo | tipo |
|---|---|
| `tree_size`, `checked`, `verified` | enteros — bloques, registros comparados, coincidentes |
| `findings` | array de `{status, index, sealed_hash, current_hash, sealed_at, tenant, type}`; `status` es `"discrepancia"` (el vivo cambió), `"faltante"` (el vivo ya no lo tiene) o `"no sellado"` (el vivo tiene algo que el ledger no); `sealed_at` es el tiempo **declarado** del bloque |
| `full_verify` | `{run, ok, error}` solo con `--full` |
| `attestation`, `attested`, `attested_size`, `signer`, `freshness` | misma semántica que `status`: un cotejo que coincide sobre una historia sin atestiguar coincide con un ledger que podría estar truncado |
| `ok` | `true` sin hallazgos (y `full_verify.ok` si se pidió); con `false` el código de salida es `2` |

### `sync`

| campo | tipo |
|---|---|
| `origin` | string |
| `local_size`, `witness_size` | enteros — bloques aquí y bloques que el testigo había cosignado |
| `attested` | bool — la cosignature del testigo verificó |
| `attested_at` | RFC 3339 — el instante que afirmó el testigo |
| `first_time` | bool — era el primer checkpoint de este log para ese testigo |
| `policy` | objeto, ver arriba — lo que hace falta para volver a abrir con todo verificado |

Con rollback detectado: `{"ok": false, "rollback": true, "local_size": N,
"witness_size": M}` y código `2`. Sin poder llegar al testigo: error con código `3`.

### `witness key`

`{"public_key": hex, "created": bool}`.

### `backup` / `restore`

`backup`: `{"shares": [...], "threshold": N}` (los mnemónicos son secretos).
`restore`: `{"restored": true, "vault_id": "...", "shares": N}` — `restored` solo
es `true` si la clave reconstruida desenvolvió la clave de datos de **este**
vault.
