# ADR-029-restore-fija-passphrase-nueva

**Estado:** ACEPTADA el 2026-09-28 por el dev (Sprint 14) · **Fecha:** 2026-09-28 · **Fuentes:** PROTOCOL.md §6 (jerarquía de claves y respaldo), ADR-004 y ADR-010 (SLIP-0039), ADR-009 y su enmienda (`vault_meta` mutable por diseño), ADR-021 (el `Sealer` de PHP), `docs/OPERACION.md` §3, decisión pendiente del Sprint 12 en `TODO.md`

## El problema

Las tarjetas SLIP-0039 respaldan la **KEK**, y la KEK sale de la passphrase con
Argon2id. Hasta ahora, `restore` reconstruía la KEK con dos tarjetas y comprobaba que
desenvolvía la DEK de **este** vault… y ahí terminaba. Para sellar hace falta abrir el
vault, abrirlo exige la passphrase, y la passphrase era justo lo que se había perdido.
El Sprint 12 lo comprobó con el binario publicado: tras un `restore` correcto, una
passphrase nueva seguía diciendo «la passphrase no es la de este vault».

Resultado: las tarjetas demostraban que se tenía la clave, pero no servían para lo único
que se espera de un respaldo. Y «olvidé la contraseña» es el fallo más común en la vida
real, muy por delante de un disco roto o un robo.

## Decisión

### A. `restore` puede fijar una passphrase nueva

```
nucleo restore --shares-file TARJETAS --new-passphrase-file NUEVA
nucleo restore --new-passphrase            # la pide por terminal, dos veces
```

Sin `--new-passphrase` ni `--new-passphrase-file`, `restore` hace lo de siempre:
comprobar que las tarjetas son de este vault, sin cambiar nada.

El cambio, paso a paso:

1. Las tarjetas reconstruyen la KEK vieja (`RestoreKEK`).
2. Con ella se desenvuelve la DEK de este vault. Es lo que prueba que las tarjetas son
   **de este vault** y no un respaldo cualquiera: el envoltorio es autenticado y su AAD
   lleva el identificador del vault.
3. Se deriva una KEK nueva de la passphrase nueva con Argon2id, con **los mismos
   parámetros guardados** —tiempo, memoria, hilos, longitud— y un **salt nuevo**. Un
   vault creado con el perfil `constrained` sigue en `constrained`: la passphrase cambia,
   el coste no.
4. La misma DEK se vuelve a envolver bajo la KEK nueva, y se comprueba que se
   desenvuelve con ella antes de seguir.
5. Se emiten las tarjetas nuevas (§B).
6. Parámetros y DEK envuelta se sustituyen **en una sola transacción** (§C).

La DEK **no cambia**. Todo lo cifrado bajo ella —la identidad del log y del firmante,
los blobs, las subclaves de compromiso— sigue igual: no hay nada que volver a cifrar y
la cadena no se toca. Es un cambio de cerradura, no de lo que hay dentro. Tampoco cambia
el protocolo: la jerarquía de PROTOCOL.md §6 —passphrase → Argon2id → KEK → DEK— es la
misma, con otro salt y otra passphrase.

### B. Las tarjetas viejas quedan sin valor, y se emiten nuevas en el mismo acto

Las tarjetas son la KEK. Con una KEK nueva, las viejas ya no desenvuelven nada en este
vault. Por eso `restore` **emite las tarjetas nuevas en el mismo acto**, con la misma
confirmación tecleada que `init` (ADR-004): no hay un momento en el que el vault quede
con passphrase nueva y sin respaldo por decisión del programa.

El orden es deliberado: las tarjetas nuevas se enseñan y se confirman **antes** de
escribir nada. Si la palabra tecleada no coincide, o quien la teclea se arrepiente,
`restore` sale **sin haber cambiado nada**: siguen valiendo las tarjetas viejas, y las de
la pantalla no sirven. La pantalla lo dice encima de las tarjetas: valen desde que
aparezca «✔ passphrase nueva fijada», no antes.

Con `--json` no hay a quién pedirle la palabra: hace falta `--assume-confirmed`, como en
`init`, y las tarjetas salen en el JSON.

Lo que se dice sin ambigüedad, en la salida de `restore`: **las tarjetas anteriores ya no
sirven para este vault; destrúyelas**. Y un matiz que no se puede esconder: una **copia
del fichero del ledger** hecha antes del cambio lleva dentro la DEK envuelta con la KEK
vieja, así que esa copia **sí** se abre con las tarjetas viejas. Quien destruya las
tarjetas viejas cierra esa puerta; quien las guarde, la deja abierta mientras existan
copias antiguas.

Un `restore` con tarjetas que dejaron de valer lo dice: *«NO es la clave de este vault,
o son tarjetas de antes de un cambio de passphrase: esas quedaron sin valor»*.

### C. Atomicidad: el vault nunca queda sin ninguna forma de abrirse

Las dos filas que cambian —`vault/params/v1` (el salt) y `vault/dek/v1` (la DEK
envuelta)— van juntas o no van. Se escriben en **una transacción de SQLite** (WAL con
`synchronous=FULL`, PROTOCOL.md §8), y la transacción **comprueba antes** que las dos
siguen siendo las que se leyeron: si otro proceso cambió la passphrase entre medias, no
se pisa su cambio y `restore` sale con error.

Así, en cualquier instante el vault está en uno de dos estados, y en los dos se abre:

| si el proceso muere… | estado | se abre con |
|---|---|---|
| antes de la transacción (tarjetas leídas, tarjetas nuevas en pantalla, confirmación hecha) | **viejo** | la passphrase vieja y las tarjetas viejas |
| dentro de la transacción, entre las dos escrituras | **viejo** (SQLite deshace lo no confirmado) | ídem |
| después del `COMMIT`, antes del mensaje final | **nuevo** | la passphrase nueva (y las tarjetas nuevas, si llegaron a verse) |

Nunca hay un estado mixto —salt nuevo con DEK vieja— en el que ni una passphrase ni
unas tarjetas abran. Si muere después del `COMMIT` sin que las tarjetas nuevas se
hayan visto (con `--json`, se escriben al final), el vault se abre con la passphrase
nueva, que quien la fijó tiene, y `nucleo backup` emite tarjetas nuevas.

Se prueba **matando el proceso** —`os.Exit`, sin que corra ningún `defer`— en cada una
de esas fronteras, y comprobando después con qué se abre el vault.

### D. La passphrase en `0640 root:www-data`: se acepta

La configuración habitual en un VPS es que el fichero de passphrase sea de `root`, con el
grupo del proceso web y solo lectura para él: `0640 root:www-data`. El proceso web lo lee
pero no puede modificarlo, y si el directorio es de `root`, tampoco borrarlo. Es **más**
seguro que `0600 www-data:www-data`, donde una aplicación comprometida puede reescribir o
borrar la passphrase de la que depende el sellado.

Hasta ahora el `Sealer` de PHP la rechazaba (`$modo & 0077`), y `docs/OPERACION.md` tuvo
que decir que «la receta habitual no funciona con el SDK». Desde este ADR, el `Sealer`
acepta el grupo **con solo lectura** y sigue rechazando todo lo demás: escritura o
ejecución para el grupo, y cualquier permiso para otros (`$modo & 0037`).

Lo que este ADR no cambia: la CLI no comprueba los permisos del fichero de passphrase,
ni antes ni ahora. Quien la invoca a mano ya tiene la passphrase; el punto automatizado
donde un permiso mal puesto pasa desapercibido es el `Sealer`, y ahí está la
comprobación.

## Consecuencias

- Perder la passphrase deja de ser perder el vault, **si** se conservan dos tarjetas.
  `docs/OPERACION.md` §3 y el tutorial cambian en ese sentido.
- Quien reúna dos tarjetas puede fijar una passphrase nueva y sellar. Ya podía
  desenvolver la DEK —y con ella descifrar los blobs y la identidad— así que el umbral de
  confianza de las tarjetas no cambia: ya eran la clave entera.
- Cambiar la passphrase por gusto, teniéndola, es el mismo camino: `backup` para sacar
  tarjetas si no se tienen, y `restore --new-passphrase-file`.
- `backup` no cambia: con la misma KEK, sus tarjetas nuevas conviven con las viejas, y lo
  sigue diciendo.
