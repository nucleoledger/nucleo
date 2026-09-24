# El contrato de `--json`

`nucleo --json <subcomando>` escribe en **stdout** exactamente un objeto JSON,
indentado, y nada más. Todo lo que es para personas —avisos, explicaciones, el
snippet de la política— va por **stderr** o se omite. Este documento es el
contrato de ese objeto: qué campos hay, qué significan y cuáles no van a cambiar
sin aviso en el CHANGELOG.

Lo que sigue se comprobó contra la CLI del commit que lo acompaña. Los tests de
`cmd/nucleo` (`freshness_test.go`, `policy_test.go`, `stale_test.go`, `cli_test.go`)
afirman cada campo aquí descrito; si esto y el binario discrepan, es un bug.

**Este documento es NORMATIVO** desde [ADR-025](adr/ADR-025-json-como-formato-de-cable.md).
La salida `--json` es un formato de cable: la consumen el SDK de PHP, los crons y
cualquier ERP, así que recibe el mismo trato que la política (ADR-018) —gramática escrita,
consumidor estricto, vectores compartidos—:

- **Vectores**: `testdata/vectors/cli-json/`. Los `valido-*` los emite la CLI de verdad
  (`cmd/nucleo/clijson_vectors_test.go`, que además falla si la salida de hoy deja de
  coincidir con el vector); los `invalido-*` están escritos a mano y son lo que la CLI
  nunca produce.
- **Consumidor de referencia**: `Nucleo\Contract` en `sdk/php/src/Contract.php`, con su
  suite en `sdk/php/test/contrato.php`.
- **Quien parsea falla CERRADO**: un campo obligatorio ausente o con otro tipo es un
  error, no un valor por omisión. Un `-1` por un índice que no vino, o un `false` por una
  atestación que nadie afirmó, es cómo un binario antiguo o una salida truncada acaban
  pareciendo un sellado correcto.

## Convenciones

- **`ok`** (bool) va en todos los objetos. `true` cuando el subcomando hizo su
  trabajo. En un error, el objeto es
  `{"ok": false, "error": "...", "exit_code": N, "error_class": "..."}`
  y el código de salida del proceso es `N`: `1` uso, `2` verificación/integridad,
  `3` sincronización fallida. `reconcile` con hallazgos emite su informe completo
  con `ok: false` y sale con `2`; ese informe **no es un objeto de error** y no
  trae `error` ni `exit_code` ni `error_class`, así que un consumidor tiene que
  mirar el código del PROCESO antes de buscar un objeto de error.
- **`error_class`** (string) dice QUÉ CLASE de problema es, que es lo que el
  código de salida no puede decir (ADR-027). Conjunto cerrado:

  | valor | qué afirma | qué hace un programa |
  |---|---|---|
  | `usage` | lo que se pidió no se puede pedir así | no reintentar; cambiar la llamada o la entrada |
  | `transient` | se resuelve sola o con un reintento (el testigo no contesta, el ledger está tomado, el bloque no está cubierto todavía) | reintentar luego, con la misma `--idempotency-key` si hubo escritura |
  | `environment` | el despliegue está roto y lo arregla una persona (permisos, disco, un fichero que falta, un testigo cuya clave no es la de la política) | avisar a quien opera; reintentar da lo mismo |
  | `integrity` | la verificación falló: alteración, discrepancia, retroceso | incidente: no reintentar, no borrar, preservar |

  Es **ortogonal al código**: un `1` puede ser `usage` o `transient` —pedir el
  recibo de un bloque que ningún testigo cubrió no tiene nada de malo, solo es
  pronto—, y un `3` puede ser `transient` (no se llega al testigo) o
  `environment` (se llega y su clave no es la de la política, que no se arregla
  reintentando). El `2` es siempre `integrity`.

  Quien parsea lo lee como **opcional**: un binario anterior a septiembre de 2026
  no lo trae, y entonces se deduce del código (`1 → usage`, `2 → integrity`,
  `3 → transient`), que es el comportamiento de siempre. Si está y no es una de
  las cuatro cadenas, es un error de contrato: un valor que no se entiende no se
  interpreta a la baja.

  **No sale en la salida para personas**, a propósito: ahí el mensaje ya dice qué
  hacer, en español.
- **Los avisos de frescura salen por stderr también con `--json`.** Es deliberado:
  un cron con stdout a un fichero y stderr al correo hace sonar la alarma sin
  programar nada. El mismo veredicto está en `freshness` para quien parsea.
- **Claves en hex minúscula**, 64 caracteres (Ed25519, 32 bytes). Hashes SHA-256
  en hex, 64 caracteres. Instantes en RFC 3339, UTC.
- **Estabilidad.** Los campos documentados aquí no se renombran ni cambian de
  tipo sin una entrada en el CHANGELOG. Pueden **añadirse** campos; quien parsea
  debe ignorar los que no conoce. Los códigos de salida no cambian.
- **Los booleanos son booleanos y los enteros enteros.** La CLI emite JSON canónico:
  nunca `"0"` por un entero ni `"true"` por un booleano, así que un consumidor estricto
  no tiene nada que tolerar. Los hashes y las claves van en hex **minúsculo** de 64
  caracteres, y un consumidor puede rechazar cualquier otra grafía.
- **Los campos que se contradicen no existen.** `attested` es exactamente
  `attestation == "verified"`, y `signer.verified` es exactamente
  `signer.state == "verified"`. Un consumidor puede —y debe— rechazar una salida donde no
  cuadren: no hay nada que interpretar ahí.

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
| `attested_head` | bool | `attested` **y** la atestación cubre el último bloque. Es la pregunta que hace un monitor de verdad: ¿está respaldado lo que hay AHORA? Con el cron roto tres días, `attested` seguía siendo `true` mientras 120 bloques no los respaldaba nadie más que el disco (ensayo de operación del Sprint 10). |
| `attested_size` | entero | Bloques que cubre el checkpoint considerado. Con `unverified` es lo que el checkpoint **afirma**, no lo comprobado. |

En `seal`, `attested_head` se juzga **después** de escribir el bloque, así que es `false`
en cuanto se sella: el bloque nuevo todavía no lo ha visto ningún testigo. En la salida
humana, una atestación que no llega a la cabeza sale con `◐` y con los bloques que faltan,
no con `✔`.

### `rollback` — un testigo recuerda más historia de la que hay aquí

Presente **solo** si consta un rollback detectado; ausente lo demás del tiempo. Lo
escribe `sync` cuando un testigo dice haber cosignado un árbol mayor que el local, y lo
borra `sync` cuando una sincronización vuelve a cuadrar. Ninguna otra cosa lo apaga.

| campo | tipo |
|---|---|
| `at` | RFC 3339 — cuándo se detectó |
| `local_size` | entero — bloques que había en disco entonces |
| `witness_size` | entero — bloques que el testigo dijo haber cosignado |
| `witness` | string — quién lo dijo |

Aparece en `status`, `verify`, `seal` y `reconcile`. **`verify` sale con `2`** mientras
conste: un rollback registrado no dice "hace tiempo que nadie lo ve", dice "esto no es la
historia que un tercero atestiguó". `status` y `seal` siguen saliendo con `0` —informar y
sellar es lo que se les pidió— pero lo dicen por stderr en cada invocación.

Existe por el ensayo de operación del Sprint 10: se restauró un respaldo de hacía una
semana, `sync` lo cazó con código 2… y el siguiente `status` decía "✔ historia atestiguada
hasta 1322 de 1322 bloques". El primer sitio donde mira quien acaba de restaurar decía que
todo estaba bien.

### `freshness` — hace cuánto vio un tercero esta historia

```json
"freshness": {
  "stale": false, "threshold_hours": 72, "attested_ever": true, "policy": true,
  "verified": true, "source": "attestation",
  "attested_at": "2026-09-12T18:20:07Z", "attested_size": 3,
  "witness": "witness.nucleoledger.com/w1", "age_hours": 0.02
}
```

| campo | tipo | significado |
|---|---|---|
| `stale` | bool | La última atestación es más vieja que el umbral, o nunca hubo. `false` en un ledger vacío. |
| `threshold_hours` | número | `--stale-after`, por omisión 72. |
| `attested_ever` | bool | `true` **solo** si la fecha sale de una atestación verificada (`source: "attestation"`). Hasta el Sprint 7e también era `true` con el registro local, y un INSERT forjado lo ponía a `true` (tercera auditoría, BAJO #9). Para saber si hay *alguna* fecha, mira `source != "none"`. |
| `verified` | bool | **De dónde sale la fecha.** `true`: de la cosignature que la apertura acaba de verificar bajo la política. `false`: del registro local que dejó el último `sync` en `log_state` — lo escribe quien tenga la base, y la segunda auditoría adversarial lo escribió con un testigo inventado. |
| `source` | `"attestation"` \| `"local_record"` \| `"none"` | Lo mismo, con nombre. Con `policy: true` solo puede ser `"attestation"` o `"none"`. |
| `policy` | bool | Se abrió con política (`--policy-file` o banderas sueltas). Con política, el registro local **nunca** alimenta la frescura. |
| `attested_at` | RFC 3339 | El instante que afirmó el testigo (nunca el reloj local). Es el del **último contacto** verificado: la cosignature más reciente que verifica bajo la política y cubre el árbol actual. |
| `first_attested_at` | RFC 3339 | Solo cuando difiere de `attested_at`: **desde cuándo consta** la historia, el instante de la primera cosignature del checkpoint guardado. Con el log parado y el cron vivo, `attested_at` avanza y este no. Son dos preguntas distintas (H6 de la cuarta auditoría). |
| `attested_size` | entero | Bloques cubiertos por esa atestación. |
| `witness` | string | Testigo(s) de esa atestación, separados por `", "` si son varios. |
| `age_hours` | número | `ahora − attested_at`; `0` si está en el futuro. |
| `recorded_at` | RFC 3339 | Solo con `source: "local_record"`: cuándo se escribió el registro, según el reloj local. |
| `clock_skew` | bool | Presente y `true` si `attested_at` está en el futuro: un reloj mal puesto, no un ataque. |

La frescura mide el **último contacto verificado**, que no es lo mismo que "la última vez
que un tercero vio esta historia": mientras el log no crezca, una respuesta reproducida
por la red trae una cosignature real y vieja, y esa es la fecha que se ve (H2 de la cuarta
auditoría; `sync` avisa y publica `replay_suspect` cuando lo que recibe ya nace viejo).
El umbral de ese aviso **no** es el de frescura: un testigo vivo firma en el momento, así
que lo que vuelve de un POST tiene segundos, y lo único que justifica una diferencia es el
desfase de reloj entre las dos máquinas. Son **15 minutos**, o el umbral de frescura si
`--stale-after` lo deja más corto.
Lo que la fecha afirma con certeza es que un testigo firmó ESA raíz en ESE instante. El
tiempo demostrable de un recibo sigue siendo el **mínimo** de las cosignatures, que es la
mejor prueba de antigüedad. Un log parado
con el cron vivo tiene las dos fechas separadas, y el JSON las publica por separado.

**La frescura está subordinada a la atestación.** Un cron que mire `stale`
sin mirar `verified` se está fiando de este disco.

> **Enmendado el 2026-09-13 tras la tercera auditoría adversarial.** Este párrafo
> terminaba con *"Con `--policy-file` la fecha sale de la cosignature y el registro
> local ni se lee."* **No era verdad.** Solo lo era cuando la atestación verificaba:
> si no —checkpoints borrados, o cosignatures que la política no acepta—, la
> frescura caía al registro local aunque se hubiera aportado la política, y la
> auditoría borró los checkpoints, insertó un registro fresco y silenció la alarma
> de `status`, `seal` y `verify`. Desde el Sprint 7e, **con política, o la fecha
> sale de una atestación que verifica bajo ella, o no hay fecha**: `stale: true`,
> `source: "none"`, `policy: true` y aviso por stderr.

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

Con `--json` hay que pasar `--assume-confirmed` explícitamente: no hay terminal en
la que teclear la palabra de la tarjeta, y hasta el Sprint 7e `--json` se saltaba la
confirmación en silencio. Sin la bandera, error de uso antes de crear nada.

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
| `encrypted` | bool — `false` con `--no-encrypt` (solo queda el hash) |
| `idempotent` | bool — `true` solo cuando `seal` **no escribió nada** porque la clave de idempotencia ya estaba (ADR-020 §D) |
| `idempotency_key` | string — solo si se pasó `--idempotency-key` |
| `duplicate_of` | lista de enteros — bloques que ya sellaban ESTE contenido. Ausente si no hay ninguno |
| `profile`, `metadata`, `commitments` | solo con perfil (`sri.factura.v1`, `sas.acta.v1`) |
| `attestation`, `attested`, `attested_size`, `signer`, `freshness` | **el estado de la historia sobre la que se acaba de escribir**, con la misma semántica que `status`. El bloque recién sellado **no** está cubierto por la atestación: lo cubrirá el próximo `sync`. |

Sellar el mismo contenido dos veces produce un **bloque nuevo**: el ledger registra
hechos de sellado, no documentos (ADR-020 §A). `duplicate_of` es lo que permite verlo
sin adivinar. Para que un reintento no duplique nada está `--idempotency-key`: con la
misma clave y el mismo documento, la salida es la del sellado original con
`"idempotent": true`, y el ledger no crece; con la misma clave y otro documento, es
error de uso. Un reintento idempotente trae **los mismos campos** que un sellado normal,
`freshness` incluida: el integrador no tiene dos formas que distinguir.

> **Enmendado el 2026-09-17.** Esta tabla decía `--clear`, una bandera que no existe;
> la de `seal` es `--no-encrypt`.

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
| `findings` | array —**siempre array**, vacío cuando el cotejo cuadra— de `{status, index, sealed_hash, current_hash, sealed_at, tenant, type}`; `status` es `"discrepancia"` (el vivo cambió), `"faltante"` (el vivo ya no lo tiene) o `"no sellado"` (el vivo tiene algo que el ledger no); `sealed_at` es el tiempo **declarado** del bloque |
| `full_verify` | `{run, ok, error}`. **`--full` vale `true` por omisión en `reconcile`**: el cotejo recomprueba todas las firmas históricas salvo que se pase `--full=false`, y entonces el campo no sale |
| `attestation`, `attested`, `attested_size`, `signer`, `freshness` | misma semántica que `status`: un cotejo que coincide sobre una historia sin atestiguar coincide con un ledger que podría estar truncado |
| `ok` | `true` sin hallazgos (y `full_verify.ok` si se pidió); con `false` el código de salida es `2` |

### `sync`

| campo | tipo |
|---|---|
| `origin` | string |
| `local_size`, `witness_size` | enteros — bloques aquí y bloques que el testigo había cosignado |
| `attested` | bool — la cosignature del testigo verificó |
| `attested_at` | RFC 3339 — el instante que afirmó el testigo |
| `replay_suspect` | bool — la cosignature recibida ya nacía vieja (ver `freshness` arriba) |
| `first_time` | bool — era el primer checkpoint de este log para ese testigo |
| `policy` | objeto, ver arriba — lo que hace falta para volver a abrir con todo verificado |

Con rollback detectado: `{"ok": false, "rollback": true, "local_size": N,
"witness_size": M}` y código `2`. Sin poder llegar al testigo: error con código `3`.

### `help`

`{"ok": true, "usage": "<el texto de la ayuda>"}`.

### `witness key`

`{"public_key": hex, "created": bool}`.

### `backup` / `restore`

`backup`: `{"shares": [...], "threshold": N}` (los mnemónicos son secretos).
`restore`: `{"restored": true, "vault_id": "...", "shares": N}` — `restored` solo
es `true` si la clave reconstruida desenvolvió la clave de datos de **este**
vault.
