# ADR-029-restore-fija-passphrase-nueva

**Estado:** ACEPTADA el 2026-09-28 por el dev (Sprint 14), **ENMENDADA el 2026-10-07** (ver al final: una passphrase olvidada no es una robada) · **Fecha:** 2026-09-28 · **Fuentes:** [revisión de v0.3.0-alpha del 2026-10-03](../revision-externa-modelo-20261003.md) (la enmienda), PROTOCOL.md §6 (jerarquía de claves y respaldo), ADR-004 y ADR-010 (SLIP-0039), ADR-009 y su enmienda (`vault_meta` mutable por diseño), ADR-021 (el `Sealer` de PHP), `docs/OPERACION.md` §3, decisión pendiente del Sprint 12 en `TODO.md`

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
  tarjetas si no se tienen, y `restore --new-passphrase-file`. **Pero no si la cambias
  porque te la han robado**: eso no se arregla cambiándola (enmienda de abajo, §F).
- `backup` no cambia: con la misma KEK, sus tarjetas nuevas conviven con las viejas, y lo
  sigue diciendo.

## Enmienda 2026-10-07 — una passphrase olvidada no es una passphrase robada

La [revisión del 2026-10-03](../revision-externa-modelo-20261003.md), hecha por un modelo
sobre el tag `v0.3.0-alpha`, no encontró un orden de operaciones que deje el vault sin
forma de abrirse. Encontró tres cosas de borde, y la primera destapa una que no lo es.

### E. Un `seal` ya desbloqueado termina después del cambio, y se deja

El hallazgo (MEDIA): un `seal` que desbloqueó el vault con la passphrase vieja **antes**
del `COMMIT` de `restore` puede escribir su bloque **después**. Comprobado con un test que
detiene el `seal` justo después de desbloquear (gancho `NUCLEO_TEST_PAUSE_AT`, solo en
binarios de pruebas), ejecuta `restore` entero y lo deja seguir: el `seal` termina, su
bloque es válido —`verify --full` en verde— y un `seal` nuevo con la passphrase vieja falla.

**Se deja así, y no se bloquea.** El cambio invalida las **aperturas nuevas**, no las que
ya estaban hechas. Un bloqueo que excluyera a los sellados en curso no compraría nada:

- La DEK y las claves de firma **no cambian** con el cambio de passphrase. Lo que ese
  `seal` firma es exactamente tan válido como antes, y la cadena lo acepta por eso.
- Quien desbloqueó con la passphrase vieja era, en ese instante, quien tenía derecho a
  hacerlo. Si la passphrase estaba **olvidada**, no hay nadie más usándola; si estaba
  **robada**, el ladrón no necesita un `seal` en curso para nada: ya pudo llevarse las
  claves (§F). En ningún caso el bloqueo protege algo.
- Y costaría: `restore` espera a que alguien copie unas tarjetas, y un bloqueo que durase
  eso dejaría al ERP sin sellar mientras tanto; uno que durase solo el `COMMIT` no
  cambiaría nada, porque el `seal` ya tenía lo que necesitaba antes.

### F. Lo que de verdad destapa: ADR-029 es para una passphrase PERDIDA, no ROBADA

El hallazgo E lo dice de pasada —«si la motivación del cambio era revocar de inmediato una
passphrase filtrada…»— y es lo importante. Fijar una passphrase nueva **cambia la
cerradura, no lo que hay dentro**: la DEK y las claves de firma (las del firmante y las del
log, Ed25519 y ML-DSA-44) siguen siendo las mismas. Quien tuvo la passphrase **y una copia
del fichero del ledger** —el de producción o cualquier respaldo— pudo desenvolver la DEK y,
con ella, sacar las claves. Re-envolver no le quita nada de eso.

Así que hay tres casos, y solo en dos sirve `restore --new-passphrase`:

| la passphrase… | qué hacer |
|---|---|
| **se olvidó** | `restore --new-passphrase` con dos tarjetas. Es el caso para el que existe este ADR |
| **se filtró, y nadie pudo tener ninguna copia del ledger** —ni del fichero ni de un respaldo— | `restore --new-passphrase` cierra las copias que se hagan desde ahora; las de antes se siguen abriendo con la passphrase vieja: destrúyelas o guárdalas como el secreto que son |
| **se filtró, y alguien pudo tener una copia del ledger**, o no lo sabes | las claves están comprometidas. **Un log nuevo**: `nucleo init` en otro `--dir` con otro `--origin`, su política publicada, y el viejo retirado (abajo) |

Retirar el log viejo no borra nada de lo que ya entregaste: los recibos siguen verificando
con su política, porque lo que dicen ya lo cosignaron testigos. Lo que cambia es que, desde
el robo, el ladrón **puede firmar como tú en ese log**: bloques nuevos, recibos nuevos, y
—si tiene una copia al día del ledger— extensiones que un testigo cosignaría. Por eso:

- anota el `tree_size` del log viejo en el momento en que lo retiras (`nucleo --dir VIEJO
  status --json`) y publícalo junto con la retirada: lo tuyo es hasta ahí, y un recibo de
  ese log con un bloque posterior no es tuyo;
- pide a tu testigo que deje de servir el log viejo —`witness serve` lo atiende por su
  `--log-origin`— para que no cosigne nada más de él;
- publica la política del log nuevo por el mismo canal que la primera y ánclala (OPERACION
  §2).

Hoy no hay otra vía: la rotación de identidad dentro del mismo log —un bloque especial
firmado por la clave saliente, PROTOCOL.md §6— está escrita en el protocolo pero **no
implementada**. Cuando lo esté, este apartado cambia.

Y la DEK: los blobs cifrados con ella —los contenidos sellados con cifrado— los puede
descifrar quien la tenga, desde cualquier copia. Un log nuevo trae una DEK nueva para lo que
se selle después; lo ya cifrado no se vuelve a cifrar. Lo que sí sigue en tu mano es la
supresión: borrar el blob (PROTOCOL.md §5).

### G. Los secretos se borran de memoria en cuanto dejan de hacer falta, hasta donde Go deja

El hallazgo (BAJA): `restore` dejaba la KEK de las tarjetas, la passphrase nueva y la DEK de
la comprobación de pertenencia en memoria hasta que pasara el recolector. Ahora:

- la comprobación de pertenencia usa `vault.CheckKEK`, que **no devuelve** la DEK y la borra
  antes de volver; un test estructural falla si la CLI vuelve a llamar a `UnwrapDEK`;
- la KEK reconstruida, la passphrase nueva, la passphrase de `init` y `backup` y la KEK que
  esos dos derivan para las tarjetas se borran con `vault.Wipe` al salir; la passphrase que
  abre el vault en los demás comandos, en cuanto lo ha abierto;
- la passphrase leída de fichero ya no pasa por un `string`, que no se puede borrar.

**El límite, dicho sin adornos**: `Wipe` pone a cero **ese** slice. Go no garantiza que no
haya otras copias —el recolector puede haber movido el array antes, la biblioteca de
Argon2id o de SLIP-0039 puede haber hecho las suyas—, un `string` creado a partir de un
secreto no se puede borrar, y lo que el sistema operativo lleve a swap o a un volcado de
memoria queda fuera de su alcance. Reduce la ventana; no la cierra. En una CLI que vive
segundos, el riesgo que queda es el de cualquier proceso que maneja una clave: quien pueda
leer su memoria mientras corre.

### H. El tutorial repite lo de las copias antiguas

El hallazgo (BAJA documental): el tutorial decía que las tarjetas viejas «no sirven» sin el
matiz de §B —una copia del ledger de antes del cambio se sigue abriendo con ellas—. Ahora lo
dice, y un test comprueba que lo sigue diciendo junto a `restore --new-passphrase`.
