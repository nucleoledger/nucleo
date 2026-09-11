# ADR-015-destinatario

**Estado:** ACEPTADA el 2026-09-10 por el dev · implementada en el Sprint 7b, después de ADR-014 y apoyada en él · **Fecha:** 2026-09-10 · **Fuentes:** revisión externa 2026-09-10 (hallazgo 5), PROTOCOL.md §3-§4, ADR-002, `internal/receipt`, `internal/identity`

La revisión externa del 10-sep-2026 señaló que el destinatario del recibo no está
cubierto por ninguna firma y que, pese a eso, va a acabar impreso en el pie de un
PDF junto al nombre del cliente, donde se leerá como prueba de emisión a esa
persona. El límite ya estaba documentado —README, CHANGELOG y
`TestRecipientIsNotCoveredBySignatures`— pero documentado no es lo mismo que
dicho donde alguien lo va a leer.

**Lo mínimo honesto ya está implementado** (commit de este sprint): la línea del
destinatario lleva la etiqueta `(anotado por el emisor, no firmado)`, en la misma
línea que el nombre, y viaja dentro del texto que `Parse` compara byte a byte, así
que no se puede quitar sin invalidar el recibo. Eso no añade garantías: deja de
insinuarlas.

Este ADR evaluó la **opción completa** —que el emisor firme el recibo entero,
destinatario incluido— y el dev la **aprobó el 2026-09-10**, con la condición que
este ADR pedía: después de ADR-014 y apoyada en él.

## Decisión, y por qué la recomendación cambió de "todavía no" a "sí"

La recomendación original era "hacerlo, pero no antes de resolver la distribución de
la clave", porque una firma del emisor no vale nada si quien recibe el recibo no sabe
qué clave esperar. **ADR-014 resolvió eso sin proponérselo.**

La clave que firma el recibo es la MISMA que firma los bloques, y su pública —
`signer_pubkey` — vive dentro del header. Desde `leaf/v2` el header entra en la hoja
de Merkle, y la hoja está bajo una raíz que los testigos cosignan. Es decir: la clave
con la que hay que verificar la firma del emisor viene **clavada por la misma
atestación que clava todo lo demás**.

Eso elimina la parte cara de este ADR. No hay directorio de claves, no hay
`.well-known`, no hay intercambio fuera de banda: la contraparte verifica con lo que
ya tiene en el recibo y en su política. Es exactamente la restricción que el dev puso
—«cero PKI nueva»— y resulta que era alcanzable.

De las tres opciones de clave que este ADR analizaba, se adopta la **(b), la clave del
tenant**, y no la (c) que se recomendaba en abstracto. El motivo es ese mismo: una
cuarta semilla habría sido más limpia conceptualmente y habría exigido distribuir una
clave más, que es justo el problema que la (b) no tiene. La limitación de la (b) queda
escrita: si algún día la clave del tenant se rota por motivos del ledger, los recibos
emitidos antes dejan de verificar contra la clave publicada.

### Formato adoptado

```
— <tenant> <base64(firma de 64 bytes)>
receipt_sig = Ed25519( tenant_sk, SHA-256( recibo SIN su línea de firma ) )
```

Cubre el recibo ENTERO y no solo el destinatario, por la razón que este ADR ya
anticipaba: firmar la línea del destinatario por separado permitiría recombinar una
línea firmada con otra prueba. Está en PROTOCOL.md §3.1 como texto normativo.

La etiqueta `(anotado por el emisor, no firmado)` **muere** y la reemplaza
`(firmado por el emisor)`. Las dos dicen la verdad en su momento; la segunda es la
que ahora corresponde.

### El precio, dicho claro

`nucleo receipt` pasa a **exigir la passphrase**: la clave del emisor vive cifrada en
el vault y antes este comando solo leía. Para un cron que emite recibos, eso es un
`--passphrase-file` más. Se compra con ello que la línea del destinatario deje de ser
reescribible por cualquiera que tenga el fichero.

## Qué problema resuelve de verdad, y cuál no

Conviene ser exacto, porque aquí es fácil prometer de más.

| amenaza | ¿la cierra una firma del emisor? |
|---|---|
| Un tercero que tiene el recibo le cambia el destinatario y lo reenvía | **Sí.** Es el caso real: hoy `Parse` acepta el recibo redirigido, y hay un test que lo deja escrito. |
| El destinatario altera su propia copia para que parezca dirigida a otro | **Sí.** |
| Alguien fabrica un recibo entero con una prueba robada de otro recibo | **Sí**, si el verificador exige la firma del emisor. |
| El emisor emite dos recibos del mismo registro a dos destinatarios distintos | **No.** El emisor puede hacerlo siempre; firmarlos no lo impide, solo lo deja firmado. |
| El emisor miente sobre a quién entregó | **No.** Un recibo no demuestra entrega, y nada en este ADR cambia eso. |

Es decir: la firma mueve el destinatario de *"lo afirma cualquiera que tenga el
fichero"* a *"lo afirma el emisor, y no se puede alterar sin que se note"*. No lo
mueve a *"es cierto"*.

## Qué clave

`internal/identity` guarda hoy tres: `Tenant` (firma los bloques), `Log` (firma
los checkpoints) y `LogPQSeed` (la segunda firma ML-DSA-44). Tres opciones:

**(a) Reusar la clave del log.** Descartada. El log firma afirmaciones sobre el
árbol; un recibo es una afirmación sobre una entrega. Mezclarlas significa que
quien pueda emitir recibos puede firmar checkpoints, y a la inversa: una de las
dos capacidades pasa a implicar la otra sin que nadie lo haya decidido.

**(b) Reusar la clave del tenant.** Defendible: ya firma los bloques, es "la
identidad del emisor" en el sentido que importa, y no hay cambio de formato en el
vault. Inconveniente: un recibo firmado con ella es indistinguible —por tipo de
clave— de un bloque, y si algún día la rotación de la clave del tenant se hace
por motivos del ledger, todos los recibos emitidos antes dejan de verificar contra
la clave publicada.

**(c) Una cuarta semilla, `IssuerSeed`.** La más limpia conceptualmente y la más
cara: `stored` en `internal/identity/identity.go` gana un campo, lo que cambia el
formato de `vault_meta` y obliga a una migración de los vaults existentes (hoy:
los de desarrollo; mañana: los de alguien). Rotable por separado, lo que es justo
la propiedad que uno quiere aquí.

**Recomendación: (c)**, y hacerla coincidir con cualquier otra migración de vault
pendiente. Si se decide no migrar, (b) es aceptable con la limitación escrita.

## Qué formato

El recibo tiene dos partes: texto legible derivado, y parte de máquina
(`header` canónico + `c2sp.org/tlog-proof`). La firma del emisor debe cubrir
**todos los bytes del recibo salvo ella misma**, no solo el destinatario: firmar
el destinatario a secas dejaría recombinar una línea firmada con otra prueba.

Forma propuesta, coherente con lo que el proyecto ya usa:

```
… parte de máquina …
— <origin del emisor> <base64( keyHash[0:4] ‖ Ed25519(SHA-256(bytes anteriores)) )>
```

Es la convención de `signed-note` que ya se usa en los checkpoints, con la misma
propiedad que la hace barata: **un verificador que no conozca la clave del emisor
ignora la línea**, igual que hoy ignora la firma ML-DSA-44 del log. Eso permite
desplegarlo sin romper a los verificadores viejos... y es exactamente por lo que
hay que decidir algo incómodo: si ignorar la línea es válido, la firma no protege
a quien no la comprueba. Habría que **exigirla** cuando la política la traiga, y
que `verifyReceipt` devuelva un campo nuevo distinguiendo "firmada por el emisor
que esperaba" de "sin firma de emisor".

La alternativa de comprometer el destinatario **dentro del bloque**, al sellar,
queda descartada por una razón de producto, no de criptografía: el destinatario
casi nunca se conoce en el momento del sellado, y un mismo registro puede
generar recibos para varias contrapartes. Forzarlo al sellado convertiría el
recibo en algo que hay que decidir antes de tener el dato.

## Qué rompe

- **`internal/receipt`**: `Format`/`Parse` y una clave nueva que pasar a `Issue`.
- **`proof.Parse`** tiene que tolerar la línea extra sin confundirla con una
  cosignature.
- **Los tres vectores golden** y, con ellos, el verificador de TypeScript:
  `Policy` gana la clave del emisor y `VerifyResult` un campo más. Harían falta
  casos nuevos: firma válida, firma de otra clave, firma ausente con política que
  la exige, firma ausente con política que no.
- **`web/verify`**: un campo más en la política que el usuario pega.
- **CLI**: `status --json` debe publicar la clave pública de emisión; sin eso, la
  contraparte no tiene con qué verificar.
- **PROTOCOL.md**: texto normativo sobre qué afirma y qué no la firma del emisor.
- **`nucleo.org/receipt@v1`**: si la línea es ignorable, el magic puede quedarse;
  si se exige, es `@v2`. Esa decisión es la misma que la de arriba.

## El problema que ninguna firma resuelve

**Distribución de la clave.** Una firma del emisor solo vale si quien recibe el
recibo sabe qué clave esperar. Hoy la contraparte de una pyme recibe un PDF por
correo: si la clave del emisor viaja en el mismo PDF, quien falsifique el recibo
falsifica también la clave. Hace falta que la clave de emisión esté publicada
donde el emisor no la pueda cambiar a conveniencia —en el `origin` del log, en un
`.well-known`, o en el propio checkpoint cosignado por testigos—.

Sin eso, la firma del emisor es decoración verificable por nadie. **Esa es la
parte cara de este ADR, y no es criptografía: es PKI social**, el mismo problema
que la revisión externa señaló en el dominio como `origin`.

## Recomendación

**Hacerlo, con dos condiciones**, y no antes:

1. **Junto a ADR-014.** Si se acepta cambiar la hoja de Merkle, ese cambio rompe
   todos los vectores y recibos de todas formas. Dos roturas de formato en dos
   sprints consecutivos es el doble de migración y el doble de versiones de
   verificador conviviendo. Una sola.
2. **Con la clave de emisión publicada** en el mismo cambio. Firmar sin resolver
   la distribución produce una propiedad que solo se puede comprobar en el
   laboratorio.

Mientras tanto, la etiqueta es suficiente y es honesta: el recibo enseña el nombre
y dice, en la misma línea, exactamente lo que ese nombre vale.

## Plan de ejecución, si el dev dice sí

1. `IssuerSeed` en `internal/identity` + migración de `vault_meta` (misma migración
   que ADR-014 si se acepta).
2. `status --json` publica `issuer_pubkey`; `docs/RELEASING.md` y el tutorial
   explican dónde publicarla.
3. Vectores golden NUEVOS primero, calculados fuera del código (python + la
   librería de referencia Ed25519), según la regla anti-circularidad.
4. `internal/receipt`: firmar y verificar, con la política decidiendo si la firma
   es obligatoria.
5. `sdk/ts`: `Policy.issuerKey`, `VerifyResult.issuerVerified`, y los cuatro casos
   de test.
6. PROTOCOL.md y bump del magic si la firma pasa a ser obligatoria.
7. `web/verify` y el tutorial, con salidas reales.
