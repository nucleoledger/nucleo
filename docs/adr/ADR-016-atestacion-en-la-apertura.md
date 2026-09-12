# ADR-016-atestacion-en-la-apertura

**Estado:** ACEPTADA el 2026-09-12 por el dev · implementada en el Sprint 7c · **Fecha:** 2026-09-12 · **Fuentes:** auditoría adversarial 2026-09-12 (hallazgo CRÍTICO), ADR-009 y sus enmiendas, ADR-011, ADR-014, `internal/store/integrity.go`, `internal/proof`

## El hallazgo

La auditoría adversarial del 12-sep-2026 ejecutó esto contra el código de
PROTOCOL 0.2-draft, **sin claves, sin testigo y sin emisor deshonesto**:

1. Escritura en `nucleo.db`; `DROP TRIGGER`.
2. Reescribir `header_json` del bloque 1 y recalcular `hash = SHA-256(header_json)`,
   que es lo único que la apertura comprobaba siempre. La firma se deja intacta y ya
   no corresponde: nadie la mira.
3. Recalcular la raíz sobre las hojas adulteradas.
4. `INSERT` de una nota de checkpoint con esa raíz y una línea de firma de 76 bytes
   inventados, para que `IsCosigned` —que mide longitud— diga que sí.

```
Open devolvió: Attested=true AttestedSize=5 TreeSize=5
payload_hash del bloque 1: era 2e6709af…  ahora dead09af…
```

`status` habría impreso `✔ historia atestiguada hasta 5 de 5 bloques`.

La causa: **la firma del log sobre el checkpoint almacenado no se verificaba en
ningún punto del camino de apertura.** `checkpoint.Verify` se llamaba en dos sitios
—recibos y servidor del testigo— y nunca desde `store`. El atajo de ADR-009 ("por
debajo del último checkpoint cosignado no se recomputan firmas") tomaba como
frontera una nota que cualquiera con escritura en la base podía fabricar. El
atacante no se saltaba la defensa: **escribía él mismo la línea que decía dónde
terminaba la defensa.**

Y eso falsifica dos frases que el proyecto había publicado el día anterior:
PROTOCOL §2.1, *"la misma comprobación que ya se hace al abrir cubre las firmas"*,
y el CHANGELOG, *"el hueco exige un emisor deshonesto desde el principio, no un
atacante que entra después"*. leaf/v2 subía el listón solo frente a un adversario
que pudiera escribir en `blocks` pero no en `checkpoints`. Ningún adversario real
respeta esa división.

## Decisión

**"Atestiguado" pasa a significar VERIFICADO, y verificado significa lo mismo que
en un recibo.** Un checkpoint almacenado solo cuenta como atestación si:

- **(a)** su firma de log verifica contra la clave pública del log guardada en
  `vault_meta`, y
- **(b)** sus cosignatures verifican bajo una **política de testigos que aporta
  quien abre** —nombres y claves públicas, con quórum—, con la misma maquinaria
  que ya usa `internal/proof` para los recibos.

Sin política, la apertura **no reporta atestiguado**. Reporta un estado distinto
y honesto: *"checkpoint presente, no verificado"*. Y sin atestación verificada
**no hay atajo**: se recomputan todas las firmas Ed25519, como en un ledger sin
checkpoints.

El estado de la apertura deja de ser un booleano y pasa a ser uno de tres:

| estado | qué significa | ¿atajo? |
|---|---|---|
| `Ninguna` | no hay ningún checkpoint cosignado guardado | no |
| `SinVerificar` | hay un checkpoint con forma de cosignado, su firma de log verifica, pero no se aportó política de testigos | no |
| `Verificada` | firma de log **y** cosignatures verificadas bajo la política | sí |

Un checkpoint almacenado cuya firma de log **no** verifica no cae en
`SinVerificar`: **es un error de integridad y la apertura falla.** La rotación de
la clave del log no está implementada (ADR-016 lo hereda de `internal/identity`,
que no tiene `Rotate`), así que hoy una firma de log que no verifica solo tiene
una lectura: alguien escribió en la base.

## Por qué `vault_meta` sola no basta

La verificación (a) usa una clave que vive en **el mismo fichero que el adversario
escribe.** Un atacante que fabrica un checkpoint puede, con un `UPDATE` más,
sustituir `log/pubkey/v1` por su propia clave y firmar la nota falsa con ella. La
comprobación (a) sola sube el listón exactamente en una sentencia SQL.

Lo que (a) SÍ compra es que el ataque deje de ser silencioso hacia fuera. Una
clave de log sustituida delata al atacante en tres sitios que él **no** controla:

1. **Los recibos ya emitidos.** Cada uno lleva un checkpoint firmado con la clave
   real, y la política de cada contraparte fija esa clave. Cualquier checkpoint
   nuevo firmado con la clave sustituida es rechazado por todo verificador externo,
   y el emisor no puede volver a emitir recibos que verifiquen con la política que
   sus clientes ya tienen.
2. **El testigo.** Su estado guarda la clave del log (`AddLog`), así que el
   siguiente `sync` falla: el testigo rehúsa cosignar un checkpoint firmado con otra
   clave, y `sync` sale con código 3.
3. **Quien anotó la clave.** `status --json` la publica desde el primer día para
   configurar testigos y políticas; cualquiera que la haya copiado la compara.

Localmente, nada delata la sustitución. Por eso (a) es necesaria pero no
suficiente, y por eso la decisión exige (b): **solo una clave que viene de fuera
del fichero convierte "atestiguado" en una afirmación sobre el mundo y no sobre el
fichero.** Es la misma razón por la que el recibo exige una política: sin ella, el
tiempo demostrable no existe (ADR-002, ADR-011).

## El precio, medido

Sin política no hay atajo, y el atajo era el único motivo de la enmienda de
ADR-009. Con 10⁵ bloques:

- apertura con atestación verificada: **455 ms** (leaf/v2, sprint 7b);
- apertura sin ella, recomputando todas las firmas: **~8 s** (8,04 s medidos en el
  sprint 2 bajo leaf/v1; el coste es Ed25519, no la hoja).

Un `seal` en un cron sin banderas de testigo paga esos 8 s en un ledger de 10⁵
bloques. Para una pyme con miles de bloques son décimas de segundo. Se acepta: la
alternativa es que `status` mienta, y se pagó por descubrirlo con una auditoría.

## Qué cambia para quien usa la CLI

- `sync` y `receipt` ya reciben `--witness-name` y `--witness-key`: abren con
  política y ven la atestación verificada sin cambiar nada.
- `status`, `verify`, `seal` y `reconcile` ganan las mismas dos banderas,
  opcionales. Sin ellas, la salida dice *"checkpoint presente, no verificado"* en
  lugar de *"historia atestiguada"*, y en `--json` el campo `attestation` toma uno
  de los tres valores.
- Ningún comando falla por falta de política. Lo que cambia es lo que se afirma.

## Lo que este ADR no arregla

Un adversario que además **controle el testigo** que la política acepta sigue
pudiendo hacer cosignar basura. Eso es el hueco documentado de ADR-014 y no cambia:
la defensa contra él es un testigo que el emisor no controla, y sigue siendo
producto pendiente (sealer y producto-testigo, siguiente sprint).

## Test de regresión

El exploit de la auditoría, tal cual se ejecutó —`DROP TRIGGER`, reescritura del
bloque, nota falsa—, queda como test en `internal/store`. Afirma que `Open` **no**
reporta atestación verificada bajo ninguna de las tres formas de abrir: sin
política, con política cuyo testigo no firmó la nota, y con política que sí
correspondería al testigo real.
