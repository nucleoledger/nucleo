# ADR-032-autoridad-de-supresion

**Estado:** PROPUESTA el 2026-10-11 (Sprint 19), antes de publicar v0.4.0-alpha; **ACEPTADA por el dev el 2026-10-11** (Sprint 19b) · **Fecha:** 2026-10-11 · **Fuentes:** hallazgo del dev sobre ADR-031 y su enmienda (Sprint 19), ADR-031 §C y §E, ADR-017 (la política, raíz de confianza), ADR-018 (formato de cable de la política), ADR-004 y ADR-010 (SLIP-0039), ADR-028 (alarma durable), ADR-029 (la passphrase en el servidor), PROTOCOL §1, §3.2 y §5.1

## El hallazgo

ADR-031 hizo que la reconciliación aceptara como **suprimido** —salida 0— un registro que el
sistema vivo ya no tiene, si la cadena lleva después un bloque `nucleo.erasure.v1` con el
`payload_hash` que toca. Lo único que hacía falta para fabricar ese bloque era la clave que
firma los bloques. Y esa clave la abre la passphrase, que vive en el servidor para poder
sellar (ADR-029 acepta `0640 root:www-data`).

La enmienda del Sprint 18 intentó cerrarlo exigiendo dos tarjetas SLIP-0039 en `erase`. No
separaba nada:

1. **Las tarjetas reconstruyen la KEK, la misma que deriva la passphrase.** La KEK abre la DEK,
   y la DEK la clave de firma. Tarjetas y passphrase son dos caminos a la misma clave; quien
   tiene uno no necesita el otro. Lo que la enmienda cerró fue **una puerta del comando**, no
   el acceso a la clave.
2. **La regla de los tipos reservados solo existía en `seal`.** La reconciliación no
   comprobaba quién había decidido la supresión: comprobaba que el evento estuviera firmado
   por la clave del tenant, que es la del servidor. Quien tiene esa clave sella el evento con
   cuatro líneas de Go —las piezas son internas, pero públicas en el repositorio— sin pasar
   por `erase` ni por `seal`.

Resultado: la decisión de si un registro desapareció legítimamente dependía de una clave que
está en el mismo servidor que el registro. Es justo el adversario del que más hay que
acordarse —el que altera la base operativa—, y es justo el que Núcleo dice detectar.

Se reprodujo antes de cambiar nada:
`internal/reconcile/supresion_test.go#TestSupresionSinAutorizacionNoCuenta` construye con las
piezas internas un evento firmado solo con la clave del tenant, para un registro que falta.
Con el código de ADR-031 y su enmienda, la reconciliación lo daba por suprimido (0).

Además, `alert ack` se guarda sin firmar en `log_state`. Se razona abajo (§G) por qué eso
deja de importar.

## Decisión

Una supresión solo cuenta si la autoriza una clave **que no está en el servidor**: la
**clave de supresión**. Su parte pública va en la política, que es lo único en lo que confía
quien verifica (ADR-017). La reconciliación deja de preguntar «¿lo firmó el tenant?» y pasa a
preguntar «¿lo autorizó la clave de supresión de la política?».

### A. La clave de supresión

- Es una clave **Ed25519 propia**, generada al azar (32 bytes de `crypto/rand`). **No se
  deriva** de la passphrase, de la KEK, de la DEK ni de las tarjetas del vault: si se derivara
  de algo que está o se puede reconstruir en el servidor, este ADR no habría cambiado nada.
- La genera `nucleo erasure-key init`, que **no abre ningún ledger** —se puede ejecutar en un
  portátil sin red— y no escribe nada en disco: reparte la semilla en tarjetas **SLIP-0039**
  propias (2 de 3 por omisión, `--shares` y `--threshold` como en `init`; la misma biblioteca,
  ADR-010), comprueba el reparto antes de enseñarlo (como `vault.BackupKEK`), enseña las
  tarjetas y la clave pública, y pide teclear una palabra de una tarjeta (ADR-004).
- **Quién la custodia**: quien responde de las solicitudes de supresión —en la LOPDP, el
  responsable del tratamiento o su delegado de protección de datos—, y **nunca** en el
  servidor. La separación solo existe si nadie que opere el servidor puede reunir el umbral de
  tarjetas de supresión. Que estas tarjetas no sean las del vault es la regla mínima; que las
  tengan personas distintas de quienes tienen las del vault es lo recomendable, y lo dice
  `docs/OPERACION.md` §3.
- Perder el umbral de tarjetas de supresión no pierde datos: impide suprimir. Se genera una
  clave nueva y se cambia `erasureKey` en la política; las supresiones ya hechas siguen
  contando para quien tenga la política vieja, y dejan de contar para quien solo tenga la
  nueva. Por eso un cambio de clave de supresión se comunica igual que un cambio de testigo:
  con la política entera.

### B. En la política (PROTOCOL §3.2)

Miembro nuevo y **opcional**, `erasureKey`, con el formato de cable de ADR-018: cadena de 64
caracteres `[0-9a-f]`, sin variantes de mayúsculas del nombre, sin `null`. Y una regla que no
tiene ningún otro miembro:

- `erasureKey` **no puede ser igual** a `logKey`, a `signerKey` ni a la clave de ningún
  testigo. Una política en la que la clave de supresión es la del log o la del firmante es
  exactamente la situación que este ADR elimina, escrita en un fichero.

Al abrir un ledger con política, si `erasureKey` coincide con la clave que firma los bloques
—que el parser no ve cuando la política no trae `signerKey`— es un error de uso.

Los tres parsers (Go, TypeScript y PHP) lo aceptan y lo rechazan igual, y lo fijan los vectores
de `testdata/vectors/policy/`, que siguen saliendo de `generar.py`, escrito a mano desde la
tabla. El diferencial de políticas lo muta como a los demás miembros. Los SDK lo leen y no lo
usan para nada más: verifican recibos, y un recibo no depende de esto.

### C. La autorización y dónde va

La custodia firma, con la clave de supresión, este texto exacto (UTF-8, cada línea terminada
en `\n`):

```
nucleo.org/erasure-authorization@v1
origin <origin del log>
erased_payload_hash <h, 64 hexadecimales en minúsculas>
through <índice decimal, sin ceros a la izquierda>
```

`firma = Ed25519(clave de supresión, SHA-256(texto))`, como la de los bloques (PROTOCOL §1): se
firma el digest. El texto no es ambiguo aunque el origin tuviera saltos de línea: las dos
últimas líneas tienen forma fija y se leen desde el final.

- **`origin`** ata la autorización a un log: una misma custodia puede servir a varios.
- **`through`** cierra la repetición. ADR-031 §C permite volver a sellar un contenido después
  de suprimirlo, y esa copia nueva es un registro nuevo. Sin `through`, una autorización vieja
  para `h` serviría para suprimir también la copia nueva, sin que la custodia lo supiera. Con
  él, la autorización cubre los bloques de contenido `h` con índice **≤ through**, y nada más.
  `erase` pone ahí el último bloque que tiene ese contenido.

**Dónde va la firma: en el `payload_cid` del evento**, con esta forma exacta:

```
nucleo-erasure-auth@v1:<through>:<firma, 128 hexadecimales en minúsculas>
```

Por qué ahí, y no en otro sitio:

- **No en el contenido del evento.** La reconciliación encuentra el evento recalculando su
  `payload_hash` a partir del hash suprimido (ADR-031 §C). Una firma dentro del contenido no se
  puede recalcular, y habría que guardar el contenido fuera de la cadena para leerla: un dato
  aparte que se puede perder o que puede poner cualquiera que escriba el fichero. Y el
  contenido **no viaja en el recibo**: un tercero no la vería. El contenido sigue siendo
  exactamente `{"erased_payload_hash":"<h>"}`, y su vector no cambia.
- **En el header, sí.** El header viaja entero en el recibo (PROTOCOL §3.1), lo firma el tenant
  y lo fija la hoja bajo una raíz que los testigos cosignan. `payload_cid` es el único de sus
  ocho campos que es texto libre, y en el evento no tenía uso: era `none://`. El formato del
  bloque no cambia; cambia lo que significa ese campo en un tipo concreto.
- **No una firma de la custodia sobre el header del evento.** El header lleva `prev_hash` y la
  hora, que no se conocen hasta el momento de sellar y cambian en cada reintento
  (ADR-020): la custodia tendría que estar conectada al servidor mientras se sella, que es lo
  contrario de tener la clave fuera.
- **No un bloque aparte de autorización.** Serían dos bloques que hay que emparejar, en una
  transacción o no, y una regla más para decidir cuál vale. La firma dentro del evento llega
  y desaparece con él.

### D. La regla que comprueba la reconciliación (PROTOCOL §5.1)

Con la política que se le pasa (`origin` y `erasureKey`), un evento `E` de tipo
`nucleo.erasure.v1` **está autorizado** si y solo si:

1. su `payload_cid` tiene la forma de §C, con `through < E.index`;
2. hay un bloque anterior a `E` cuyo `payload_hash` `h` cumple
   `E.payload_hash = SHA-256({"erased_payload_hash":"<h>"})` —eso da `h`—;
3. la firma verifica con `erasureKey` sobre el texto de §C con el `origin` de la política, `h`
   y `through`.

Un bloque `B` que el sistema vivo ya no tiene **cuenta como suprimido** (sale en `erased`, sin
hallazgo) si y solo si hay un evento autorizado para su contenido con `B.index ≤ through`. Como
`through < E.index`, el evento es posterior, que es la regla de ADR-031 §E.

Y todo evento que **no** está autorizado es un hallazgo de integridad —estado
`"supresión no autorizada"`, con su motivo en `reason`—, y el bloque que decía suprimir sigue
siendo `faltante`. La reconciliación termina con 2. En particular:

- **sin política**, o con una política **sin `erasureKey`**, ningún evento está autorizado:
  no hay contra qué comprobarlo. No es «comparación imposible» (ADR-022): lo que no se puede
  comprobar no se da por bueno, y un registro que falta sin supresión comprobable es un
  registro que falta;
- una firma de **otra clave**, sobre **otro hash**, con otro `origin` o con un `through` que no
  cubre el bloque, no cuenta.

La alarma de supresión (§G) no cambia: se abre por todo evento, autorizado o no.

### E. Un tercero, sin Núcleo

Con el recibo del evento, el recibo del bloque suprimido y la política:

1. verifica los dos recibos como siempre;
2. del header del evento toma `payload_hash` y `payload_cid`; de este, `through` y la firma;
3. del recibo del bloque toma `index` y `payload_hash` `h`; comprueba
   `index ≤ through < índice del evento` y que `SHA-256({"erased_payload_hash":"<h>"})` es el
   `payload_hash` del evento;
4. construye el texto de §C con el `origin` de la política, `h` y `through`, calcula su
   SHA-256 y verifica la firma con `erasureKey`.

Son `sha256sum` y una verificación Ed25519: PROTOCOL §5.1 da la receta con `openssl`. Lo fija
`cmd/nucleo/autorizacion_supresion_test.go#TestUnTerceroCompruebaLaAutorizacionConLosRecibos`,
que hace los cuatro pasos con la biblioteca estándar de Go y sin `internal/erasure`. Como en
ADR-031 §F, la comprobación no se añade a los SDK hasta que un integrador la pida.

### F. Cómo se suprime ahora

1. En el servidor, `nucleo erase --block N --policy-file politica.json` sin autorización **no
   borra nada**: dice qué hay que autorizar —origin, hash y `through`— y la orden exacta que
   tiene que ejecutar la custodia.
2. La custodia, en su equipo, ejecuta
   `nucleo erasure-key authorize --policy-file politica.json --payload-hash H --through K`,
   teclea sus tarjetas en una consola y obtiene la autorización: una línea de texto, que no es
   secreta (va a ir en la cadena).
3. En el servidor, `nucleo erase --block N --policy-file politica.json --authorization <línea>`
   comprueba la firma contra `erasureKey` **antes** de tocar nada, comprueba que `through` es el
   último bloque con ese contenido —si alguien lo volvió a sellar después, la autorización ya
   no lo cubriría, y lo dice—, y suprime con el evento en la misma transacción.

`authorize` comprueba que las tarjetas reconstruyen la `erasureKey` de esa política: unas
tarjetas del vault, o de otra clave, se rechazan diciendo eso. Las tarjetas **solo se teclean
en una consola**, con el mismo razonamiento que la enmienda de ADR-031 dio para las del vault
—no es la frontera, es lo que evita que alguien las deje en un fichero para automatizar—. Los
tests las pasan por el gancho `NUCLEO_TEST_CARDS`, que el binario publicado rechaza.

**Las tarjetas del vault dejan de pedirse en `erase`, que vuelve a abrir el vault con la
passphrase, como `seal`.** No hacían nada que la passphrase no hiciera —las dos llegan a la
misma clave—, y pedirlas hacía creer que separaban algo. El evento sigue firmándolo la clave
del tenant, porque es un bloque de la cadena; lo que decide si cuenta es la otra firma. Y lo
que `erase` borra —la copia cifrada y los compromisos— quien controla el servidor lo puede
borrar igualmente con un `DELETE`, con passphrase o sin ella: eso nunca fue la frontera. La
frontera es el veredicto de la reconciliación, y ese ya no depende de nada que esté en el
servidor.

### G. `alert ack`

Sigue sin pedir nada, y basta. La alarma avisa; no decide. Con este ADR:

- una supresión **no autorizada** no queda escondida por un `ack`: la reconciliación la informa
  como hallazgo en cada ejecución, y eso no lo cierra nada que esté en `log_state`;
- una supresión **autorizada** reconocida por quien controla el servidor sigue en la cadena, en
  `erased` y en los recibos. Lo único que ese `ack` esconde es el aviso de algo que el
  adversario no pudo hacer.

Firmar el `ack` exigiría una clave más a mano de quien opera de madrugada, y no protegería
ningún veredicto.

### H. PROTOCOL 0.7-draft

§3.2 gana `erasureKey` y su regla de claves distintas; §5.1 gana la autorización, su texto,
su `payload_cid`, la regla de §D y la receta de §E, y la frase «quién puede suprimir es cosa de
la implementación» deja de serlo. **No hay compatibilidad que mantener**: ningún evento de
supresión se ha publicado en un release —v0.4.0-alpha está preparada, sin tag—, así que un
evento con `payload_cid` `none://` no tiene que seguir contando. Bajo 0.7-draft no cuenta.

Para lo demás, 0.7-draft no cambia nada: todo bloque, raíz, checkpoint y recibo de 0.6-draft
sigue verificando; una política de 0.6-draft es una política de 0.7-draft. Un verificador de
0.6-draft rechaza una política con `erasureKey` —es un miembro desconocido para él—, y eso es
lo correcto: no sabría qué hacer con ella.

## Lo que NO resuelve

- **Quien custodie la clave de supresión puede suprimir.** Para eso existe. La supresión queda
  sellada en el ledger, atestiguada en el siguiente `sync`, en `erased` de cada
  reconciliación y con su alarma abierta hasta que alguien la reconozca. Si custodia y
  servidor están en las mismas manos, este ADR no separa nada: la separación es de personas,
  y el programa solo puede hacerla posible.
- **Borrar el contenido sigue al alcance del servidor.** Quien lo controla puede borrar la
  copia cifrada o el registro vivo cuando quiera. Lo que ya no puede es que la reconciliación
  lo dé por bueno.
- **La política tiene que llegar por un medio autenticado** (ADR-017). Quien pueda cambiar la
  política de quien reconcilia puede poner su propia `erasureKey`. Es el mismo límite que con
  los testigos.
- **Las supresiones hechas con una clave retirada.** Cambiar `erasureKey` hace que dejen de
  contar para quien solo tenga la política nueva (§A). Si hace falta que cuenten para siempre,
  la política tendría que llevar varias claves con su periodo; no se hace hasta que alguien lo
  necesite.

## Alternativas descartadas

- **Seguir con las tarjetas del vault.** Es lo que había, y no separaba nada (el hallazgo).
- **Derivar la clave de supresión del vault con otra etiqueta.** Sería reconstruible desde la
  passphrase.
- **Que la reconciliación exija la passphrase o las tarjetas.** La reconciliación no abre el
  vault (ADR-031 §E) y la ejecuta un cron; y no cambiaría el problema, que es dónde vive la
  clave.
- **Un `erasureKey` obligatorio en toda política.** Una política sin él es una política de un
  emisor que no suprime, y es válida: el tercero que verifica recibos no necesita esa clave. Lo
  que no puede ser es que, sin él, una supresión cuente: no cuenta.
- **Firmar `alert ack`.** §G.

## Consecuencias

- `nucleo erasure-key init` y `nucleo erasure-key authorize`, comandos nuevos; `erase` gana
  `--authorization`, exige una política con `erasureKey` y vuelve a aceptar `--passphrase-file`.
- `reconcile --json`: un estado más en `findings`, `"supresión no autorizada"`, con el campo
  `reason` (`docs/CLI-JSON.md`).
- `internal/erasure` gana el texto de la autorización, la forma de `payload_cid` y la regla
  de §D, con vectores calculados fuera del código con la biblioteca `cryptography` de Python
  (`testdata/vectors/erasure/`).
- La demo del ejemplo (paso 10) genera una clave de supresión de juguete, la pone en la
  política y suprime con autorización; el intento con solo la passphrase, sin autorización,
  falla.
- Lo que la enmienda de ADR-031 decía de las tarjetas en `erase` (A') queda sustituido por §F.
  ADR-031 se deja como se escribió, con una nota que remite aquí.

## Enmienda 2026-10-13 (Sprint 20b) — §F: en Windows, la orden es para PowerShell

Autorizada por el dev. El texto de arriba se deja como se escribió.

§F promete que `erase` sin autorización imprime «la orden exacta que tiene que ejecutar la
custodia». En Windows, el Sprint 19b la entrecomillaba con comillas dobles, y la revisión
externa del 2026-10-11 (H2, H3) mostró que, pegada, podía no ser la orden exacta: dentro de
comillas dobles PowerShell expande `$HOME` y `` `n ``, y `cmd.exe` expande `%USERNAME%` (y
`!USERNAME!` con la expansión retardada). Ninguna forma de entrecomillar sirve a la vez para
las dos consolas.

**Decisión: en Windows, las órdenes impresas son para PowerShell**, la consola por defecto de
Windows 10/11. `cmd.exe` no se promete: pegada allí, la orden falla a la vista, porque la ruta,
con las comillas dentro, no existe; y eso es aceptable. En concreto
(`cmd/nucleo/comillas.go#argShell`):

- Siempre comillas simples, que en PowerShell no expanden nada. Dentro, cada comilla simple
  se duplica, también las tipográficas que PowerShell trata como tales (U+2018, U+2019,
  U+201A, U+201B).
- Antes, `filepath.Clean`, que quita la `\` final de un directorio: PowerShell 5.1 pasa una
  ruta con espacios entre comillas dobles al programa, y esa `\` escapaba la comilla de cierre.
- Toda orden impresa empieza por la palabra `nucleo`, sin comillas. Si alguna empezara por
  una ruta entrecomillada, tendría que ir precedida de `& `, o PowerShell la tomaría por texto.
- POSIX no cambia.
- La receta que imprime `sync`, en Windows, es para una tarea programada y no habla de cron ni
  de `chmod`; no se da la receta de `schtasks` ni de `icacls`, que no está probada.

Lo comprueba la consola de verdad, no un modelo de ella:
`cmd/nucleo/comillas_shell_test.go#TestLasOrdenesImpresasFuncionanEnLaConsolaDeVerdad` ejecuta
cada orden con `powershell.exe` (5.1) y `pwsh` (7) en Windows —el CI corre en windows-2025, que
trae los dos— y con `sh` en POSIX, y comprueba el argv exacto que recibe el programa.
