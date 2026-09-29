# Operar Núcleo — guía para integradores

Esta guía es para quien embebe Núcleo en su sistema y lo va a **operar sin llamar a
nadie**. El autor del proyecto no opera infraestructura para terceros: el producto es el
software y su documentación, y todo lo que un despliegue necesita está aquí.

**Cada instrucción está comprobada**, y al lado se dice cómo. La regla del proyecto es que
ningún consejo sale sin que funcione en el entorno donde se da. Lo que no se ha podido
ejecutar —porque exige root o un dominio público— se dice como tal, no se da por bueno.

Entorno de las pruebas: el 2026-09-26, en Ubuntu 22.04 (WSL2, systemd 249), con el binario
**publicado** de `v0.2.0-alpha` para linux/amd64 —el que baja un integrador— salvo donde
se indica que es `main`. PHP 8.2 con el SDK del repositorio.

---

## Lo mínimo, en una lista

- [ ] Un **testigo que no controles tú**, detrás de TLS (§1).
- [ ] La **política** publicada por un canal que no sea el tuyo, con su hash anclado (§2).
- [ ] La **passphrase** fuera de `/home` y de las copias del ledger, con su propio respaldo (§3).
- [ ] Un hosting que cumpla los **requisitos** —`proc_open`, sin `noexec`, `ext-sodium` y
      memoria virtual suficiente— (§4).
- [ ] El **hook `onStale`** configurado: sin él, nadie se entera de que el testigo lleva
      días caído (§5).

---

## 1. El testigo

### Por qué tiene que estar fuera de tu control

El testigo es un tercero que **recuerda** las raíces de tu ledger y las **cosigna** con
fecha. Esa memoria es lo que convierte un borrado o una reescritura en algo detectable, y
esa fecha es el **tiempo demostrable** de tus recibos. Si el testigo es tuyo —su clave y su
memoria están en tu mano—, puedes reescribir la historia y hacer que la cosigne; el tiempo
demostrable deja de demostrar nada, porque lo firma la misma parte que lo afirma
([ADR-014](adr/ADR-014-hoja-y-firma.md), el hueco residual).

Quién puede serlo, en la práctica: tu contador, una notaría, un gremio o cámara, u otra
empresa con la que os atestiguáis mutuamente. Lo que importa es que **ni la clave privada
ni la memoria del testigo estén al alcance de quien sella**.

### Desplegarlo en un VPS

Un proceso de testigo sirve a **un** log (`--log-origin`, `--log-key`). Quien atestigua a
varios emisores levanta una unidad por log, cada una con su puerto y su directorio.

```ini
# /etc/systemd/system/nucleo-testigo.service
[Unit]
Description=Testigo de Núcleo (c2sp.org/tlog-witness)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=nucleo-testigo
Group=nucleo-testigo
# %S es /var/lib en una unidad de sistema: la memoria del testigo y su CLAVE PRIVADA
# quedan en /var/lib/nucleo-testigo, solo para él.
StateDirectory=nucleo-testigo
StateDirectoryMode=0700
UMask=0077
ExecStart=/usr/local/bin/nucleo witness serve \
    --addr 127.0.0.1:8099 \
    --db %S/nucleo-testigo/testigo.db \
    --name testigo.ejemplo.ec/w1 \
    --log-origin ejemplo.ec/facturacion \
    --log-key <la log_pubkey del emisor, 64 hex>
Restart=on-failure
RestartSec=5
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectControlGroups=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX

[Install]
WantedBy=multi-user.target
```

```bash
useradd --system --no-create-home --shell /usr/sbin/nologin nucleo-testigo
install -m 0755 nucleo /usr/local/bin/nucleo
systemctl daemon-reload
systemctl enable --now nucleo-testigo.service
```

La `log_pubkey` te la da el emisor: es la que imprime su `nucleo init`, o su `nucleo --json status`.

| | cómo se comprobó |
|---|---|
| la unidad | `systemd-analyze verify` sin errores. Y **levantada de verdad** como servicio de usuario con las mismas directivas, salvo `User=`/`Group=` (no se admiten en modo usuario), `PrivateUsers=yes` (lo exige el aislamiento sin root) y `ProtectHome=read-only` (en modo usuario todo vive en `/home`). Arrancó, escuchó en `127.0.0.1:8099`, dejó la clave en `0600`, atestiguó un ledger, y tras `systemctl restart` conservó la misma clave y su memoria |
| `useradd`, `install` a `/usr/local/bin` | **no ejecutados aquí**: exigen root. Son las órdenes estándar |

Dos trampas que salieron al probarla:

- **El binario no puede vivir en `/tmp`**: con `PrivateTmp=yes` el servicio tiene su propio
  `/tmp` y no lo ve (`status=203/EXEC`, «Failed to locate executable»). Tampoco en `/home`,
  con `ProtectHome=yes`. `/usr/local/bin` es el sitio.
- El testigo escucha en `127.0.0.1`: **nadie de fuera le habla directamente**. Lo que se
  expone es el TLS de delante.

### TLS delante

Con [Caddy](https://caddyserver.com), que obtiene y renueva el certificado solo:

```caddy
# /etc/caddy/Caddyfile
testigo.ejemplo.ec {
	reverse_proxy 127.0.0.1:8099
}
```

El emisor sincroniza contra `https://testigo.ejemplo.ec`.

| | cómo se comprobó |
|---|---|
| `nucleo sync` por HTTPS a través de Caddy hasta el testigo | **sí**, con Caddy 2.11.4 y su CA interna (`tls internal`) en `https://localhost:8443`: atestiguó, de 2 a 3 bloques |
| este `Caddyfile` | `caddy validate`: *«Valid configuration»* |
| el certificado público automático (ACME) de `testigo.ejemplo.ec` | **no ejecutado aquí**: necesita un dominio público que apunte a la máquina |

Si el certificado lo firma una CA que la máquina del emisor no reconoce, `sync` sale con
código 3, `error_class: environment`, y lo dice: *«el certificado TLS del testigo … lo
firmó una autoridad que esta máquina no reconoce»*, con qué hacer. En Linux, con una CA
propia, `SSL_CERT_FILE=/ruta/raiz.crt nucleo sync …` —comprobado—, o añadirla al almacén
del sistema con `update-ca-certificates` —estándar, no ejecutado aquí—.

### La clave y la memoria del testigo: respaldo

Lo que hay que guardar es **el directorio entero**: `testigo.db` (la memoria) y
`testigo.db.key` (la clave privada). La clave sola no basta: un testigo sin memoria acepta
cualquier historia como la primera que ve, y deja de poder detectar un retroceso.

```bash
systemctl stop nucleo-testigo.service
tar -C /var/lib/nucleo-testigo -cpzf /respaldo/testigo-$(date +%F).tgz .
systemctl start nucleo-testigo.service
```

`-p` conserva los permisos (`0600`). Ese respaldo **contiene una clave privada**: trátalo
como tal, fuera del alcance del emisor.

Comprobado: con el servicio parado, `tar -p` guardó los dos ficheros en `0600`; se borró el
directorio, se restauró, y el testigo arrancó con **la misma clave** y recordando los 3
bloques que había cosignado (`first_time: false`).

### Si se pierden sin respaldo

Un testigo sin su clave y su memoria **es otro testigo**, y tu política no lo acepta:
`sync` sale con código 3 y *«no es una cosignature válida de ese testigo … Esto NO se
arregla reintentando»*. El camino, comprobado de punta a punta:

1. **Antes de nada**, mira hasta dónde llegó a cosignar el testigo perdido. Esos checkpoints
   viven en tu ledger, así que se ve sin red:
   `nucleo --dir LEDGER status --policy-file politica-vieja.json`. Con la atestación
   verificada, `attested_size` es lo último que cosignó; tu `tree_size` tiene que ser igual
   o mayor. Si es **menor**, alguien ha recortado el ledger: no sigas, investígalo. Hazlo
   antes del paso 4: después, el último checkpoint es del testigo nuevo y la política
   vieja ya no lo verifica.
2. Levanta el testigo de reemplazo **con un nombre nuevo** —`testigo.ejemplo.ec/w2`— **desde
   su primer arranque**. Si arranca con el nombre viejo y llega a cosignar, guarda esa nota en
   su memoria y, renombrado después, la sigue sirviendo firmada con el nombre viejo: el `sync`
   falla. (Pasó en la prueba; se arregla borrando su memoria y arrancándolo ya con el nuevo.)
3. La **política** lleva desde ahora los **dos** testigos, con `quorum: 1`, **para
   siempre**: los recibos que ya entregaste los cosignó el viejo. Añade el nuevo, con la
   clave que te da quien lo opera, a la que ya tenías.
4. `sync` usa **esa misma política** y elige con qué testigo hablar por su nombre —también
   el primer `sync` con el nuevo, porque la confianza en su clave ya viene de la política:
   `nucleo --dir LEDGER sync --policy-file politica.json --witness https://… --witness-name testigo.ejemplo.ec/w2`.
   Sin `--witness-name`, con una política de dos testigos, `sync` no elige por ti: *«la
   política … trae 2 testigos (…) y sync habla con uno: elige cuál con --witness-name
   NOMBRE»*.
5. El **cron** es esa misma línea. Un solo fichero de política para todo: el que publicas,
   el que usan los clientes y el que usa el cron.

Comprobado con el binario de `main` el 2026-09-28, con dos testigos levantados con
`witness serve`: tras perder `w1`, con la política de los dos, `sync` sin nombre sale con
código 1 y la lista de testigos; con `--witness-name …/w2` termina en *«✔ atestación
obtenida del testigo testigo.ejemplo.ec/w2»* sin haber dado su clave por banderas; y
`status --policy-file` con la misma política da `attestation: verified`, con la cabeza
atestiguada. Hasta `v0.2.0-alpha`, `sync` exigía exactamente un testigo y el cron
necesitaba **otro** fichero de política con solo el nuevo.

Comprobado con el verificador publicado en npm: con la política de los dos, el recibo
viejo (cosignado por `w1`) y el nuevo (por `w2`) son válidos; con la del nuevo solo, el
recibo viejo falla —*«quórum de testigos no alcanzado: 0 de 1»*—. Y `status` con la de los
dos dio `attestation: verified`, cabeza atestiguada y firmante verificado.

La política cambió, así que **su hash también**: vuelve a publicarla y a anclarla (§2).

---

## 2. La política

La política —`origin`, `logKey`, `signerKey`, `witnesses`, `quorum`— es **lo único en lo que
se confía**; todo lo demás se comprueba contra ella
([ADR-017](adr/ADR-017-politica-raiz-de-confianza.md)). La imprime `nucleo sync` en su salida
(`--json`: el campo `policy`).

### Publicarla por un canal que no sea el tuyo

Quien verifica tus recibos necesita tu política, y la tiene que recibir **por un camino
que tú no puedas cambiar después**. Si solo está en tu web, quien controle tu web controla
qué se verifica. Canales que sirven: el anexo de un contrato, el correo de la contraparte,
el expediente del contador o la notaría.

### Anclar su hash

```bash
sha256sum politica.json > politica.sha256      # tú, al publicarla
sha256sum -c politica.sha256                   # la contraparte, con la que recibió
```

El hash va **en el contrato** (o en el documento que ya firméis): así, la política que se
use para verificar tiene que ser byte a byte la que se acordó. Se ancla **el fichero
exacto**: un espacio de más cambia el hash.

Comprobado: la política buena da `politica.json: OK`; la misma con la clave de un testigo
cambiada da `FAILED` y `sha256sum` sale con 1.

### Úsala en todos los comandos

`status`, `seal`, `sync`, `receipt`, el cron y los SDK, todos con `--policy-file`. Sin
política, la frescura sale del registro local que deja `sync` —que puede escribir
cualquiera con acceso al fichero— y el veredicto puede no coincidir con el de un comando
con política; la alarma de §5 sigue el veredicto de cada comando. La excepción es `sync`
tras cambiar de testigo, que usa la política del testigo actual (§1).

---

## 3. Las llaves: la passphrase y las tarjetas

### En un VPS

La passphrase abre el vault: con ella se sella, se sincroniza y se emiten recibos. Va
**fuera de `/home`** —donde acaban los ficheros de la aplicación y sus copias— y **fuera
de las copias de seguridad del ledger**: un respaldo robado con la passphrase dentro es
el vault entero.

```bash
install -d -m 0750 -o root -g www-data /etc/nucleo
install -m 0640 -o root -g www-data /dev/null /etc/nucleo/passphrase
# escribe la passphrase en /etc/nucleo/passphrase, sin espacios ni líneas de más
```

`www-data` es el usuario que ejecuta el ERP —el de PHP-FPM—, porque es quien la lee al
sellar. Con `0640 root:www-data` la **lee pero no puede cambiarla**, y como el directorio
es de `root`, **tampoco borrarla**: una aplicación comprometida no puede dejar al ERP sin
passphrase ni sustituirla. Es la receta que el `Sealer` de PHP acepta desde ADR-029; se
niega si **otros** pueden leer el fichero o si **el grupo** puede escribirlo (*«lo puede
leer o cambiar alguien más»*). `0600` del propio `www-data` también vale, y es peor por lo
dicho.

| | cómo se comprobó |
|---|---|
| la regla del `Sealer` (`0600`, `0640` y `0440` sí; `0644`, `0660`, `0604` no) | la suite de PHP la ejerce en Linux (CI). Aquí el PHP disponible es el de Windows, donde esa comprobación no aplica: se comprobó solo la aritmética de la máscara (`$modo & 0037`) |
| `install -d -m 0750` y `install -m 0640 /dev/null …` | crean el directorio en `0750` y el fichero vacío en `0640`; comprobado sin `-o`/`-g` |
| `install -o root -g www-data` | **no ejecutado aquí**: exige root |

La passphrase necesita **su propio respaldo**, aparte del ledger: un gestor de contraseñas
o un sobre cerrado en otro sitio. Si se pierde, lo que la sustituye son las tarjetas.

### Si se pierde la passphrase

Con **dos tarjetas**, `restore` fija una passphrase nueva (ADR-029):

```bash
printf '%s\n' 'la passphrase nueva' > /root/passphrase-nueva   # o sin fichero: --new-passphrase la pide por terminal
nucleo --dir /var/lib/nucleo restore --new-passphrase-file /root/passphrase-nueva
```

Pide las tarjetas por terminal (o `--shares-file`), comprueba que son **de este vault**,
enseña **tarjetas nuevas** y pide teclear una palabra de la primera, como `init`. Solo
entonces escribe, y termina con *«✔ passphrase nueva fijada»*. Después, la passphrase
nueva va a `/etc/nucleo/passphrase` (receta de arriba) y se borra el fichero temporal.

Lo que hay que saber, y está comprobado con el binario de `main` el 2026-09-28:

- **Las tarjetas viejas dejan de valer** para este vault: `restore` con ellas responde
  *«NO es la de este vault, o son tarjetas de antes de un cambio de passphrase: esas
  quedaron sin valor»*. Valen las nuevas. Destruye las viejas.
- **Una copia del ledger hecha antes del cambio** se sigue abriendo con las tarjetas
  viejas —y con la passphrase vieja—: se comprobó sellando en una copia hecha justo antes.
  Guarda esas copias como guardarías las tarjetas, o destruye las tarjetas viejas.
- **La cadena no se toca**: la clave de datos es la misma, solo cambia la cerradura.
  Se sella con la passphrase nueva y `verify --full` sigue en verde.
- **Si el proceso muere a medias**, el vault queda como estaba o con la passphrase nueva,
  nunca sin forma de abrirse: los tests lo matan en cada frontera y lo comprueban.
- Si la palabra no coincide, **no cambia nada** y las tarjetas de la pantalla no sirven.
- El camino interactivo —tarjetas, passphrase nueva dos veces y la palabra, todo por
  terminal— se recorrió con un pseudo-terminal: con la palabra buena termina en
  *«✔ passphrase nueva fijada»* y se sella con la nueva; con una mala sale con código 1 y
  la passphrase y las tarjetas de antes siguen abriendo.
- Con `--json` hace falta `--assume-confirmed`, y las tarjetas nuevas salen en el JSON
  (`new_shares`).

**Sin tarjetas** no hay vuelta: con ese vault no se vuelve a sellar. Lo que no se pierde:
`status` y `verify --full` funcionan sin passphrase, y los recibos ya entregados siguen
valiendo, porque se verifican con la política. Para seguir sellando hace falta un **ledger
nuevo** (`nucleo init` en otro `--dir`) y su política, que hay que publicar y anclar como
la primera.

### Las tarjetas SLIP-0039

`init` entrega tres tarjetas, y dos reconstruyen la clave. **Repártelas**: dos tarjetas en
el mismo cajón son una sola. Quien reúna dos tiene la clave del vault, y desde ADR-029
puede además fijar una passphrase nueva: son tan valiosas como la passphrase. `backup`
emite tarjetas nuevas **que conviven** con las viejas (misma clave); `restore
--new-passphrase` emite tarjetas nuevas **que sustituyen** a las viejas.

### Por qué en hosting compartido no hay un buen sitio

En un hosting compartido no hay «fuera de `/home`»: la passphrase vive en la cuenta, la lee
cualquier cosa que corra con esa cuenta —incluida una aplicación comprometida— y entra en
las copias que hace el proveedor. Se puede sellar desde ahí —el SDK de PHP está pensado
para eso—, pero **la passphrase vale lo que vale la cuenta**. Si eso no es aceptable, sella
desde un VPS.

---

## 4. Requisitos del hosting

Para sellar desde PHP, el hosting tiene que dejar **ejecutar el binario** y darle
**memoria virtual suficiente**. Cada punto, con el mensaje que da si no se cumple:

| requisito | si no se cumple | cómo se comprobó |
|---|---|---|
| `proc_open` habilitada | `SealEnvironmentError`: *«proc_open está deshabilitada en este PHP (disable_functions)… pídele que la habilite»* | PHP con `-d disable_functions=proc_open` |
| el binario en un sistema de ficheros **sin `noexec`** | el binario tiene `0700` y aun así no se ejecuta; el `Sealer` lo dice (*«el sistema de ficheros puede estar montado noexec»*). Diagnóstico: `findmnt -no OPTIONS --target /ruta/del/binario` | un tmpfs `noexec` montado en un espacio de nombres de usuario: `access(X_OK)` dice que no —es lo que mira `is_executable`— y ejecutarlo da `Permission denied` (126). `findmnt` mostró `noexec` |
| `ext-sodium` | el SDK no carga: *«necesita la extensión PHP "sodium" (Ed25519) y no está cargada… pídele que la habilite»* | PHP sin la extensión |
| **memoria virtual ≥ ~800 MiB** por proceso | el binario muere al arrancar, con código 2 y sin respuesta. El SDK de PHP y el ejemplo Node lo dan como fallo de **entorno**, con qué pedir, nunca como fallo de integridad | `prlimit --as` con el binario publicado, tres veces por punto: con 704 MiB no arranca nada; con 800 MiB o más, todo, con cualquiera de los dos perfiles |

Sobre la memoria, dos cifras distintas que conviene no confundir:

- **Memoria virtual** (lo que limita `ulimit -v` o el «VMEM» de los paneles de hosting):
  el runtime de Go reserva espacio de direcciones al arrancar. Por debajo de ~770 MiB no
  arranca ni `status`; desde 800 MiB, todo. El perfil de KDF no cambia este umbral.
- **Memoria real** (el «PMEM»), el pico medido con `/usr/bin/time`:

  | | perfil `default` | perfil `constrained` |
  |---|---|---|
  | `init` | 144 MiB | 53 MiB |
  | `seal` | 80 MiB | 32 MiB |
  | `status` | 15 MiB | 15 MiB |

  El perfil se elige en `init` (`--kdf-profile constrained`) y queda para ese vault. No
  se ha podido probar aquí un límite de memoria real (los cgroups de esta máquina no están
  delegados al usuario): las cifras son los picos, no un umbral medido.

El **`memory_limit` de PHP no cuenta**: Argon2 corre en el proceso del binario, no en el de
PHP. Comprobado: con `memory_limit=16M`, el perfil `default` selló y PHP no pasó de 2 MiB.

---

## 5. La alarma de frescura: configura `onStale`

Si el testigo deja de contestar, la atestación envejece. **Núcleo sigue sellando** —un
registro que no se sella se pierde; una atestación atrasada se recupera en el siguiente
`sync`— y abre una **alarma** que guarda en el ledger
([ADR-028](adr/ADR-028-alarma-de-frescura-durable.md)).

**Configurar el hook `onStale` es un requisito de integración.** El aviso por stderr no
basta: en un hosting, el cron termina en `> /dev/null 2>&1` y el ERP no lee stderr. El hook
se llama en cada operación mientras la alarma esté abierta y sin reconocer; el canal lo
eliges tú:

```php
$sealer = new Nucleo\Sealer($bin, $dir, '/etc/nucleo/passphrase', $politica, 60,
    function (array $alert): void {
        mail('operaciones@tuempresa.ec', 'Núcleo: atestación vieja',
            "Sin atestación desde {$alert['stale_since']}. Revisa el testigo y el cron de sync.");
    });
```

- **Deja de avisar** cuando alguien se entera: `$sealer->alertAck('nombre')`, o
  `nucleo alert ack --by nombre`. Hazlo cuando el aviso se haya entregado, no dentro del
  hook.
- **Se cierra sola** con el próximo `sync` que salga bien.
- **Sin SDK**: `nucleo alert status --exit-code` sale con 3 mientras haya una alarma abierta
  sin reconocer, para un cron que no lea JSON.
- **Si prefieres no sellar** con la atestación vieja —tienes cola y puedes reintentar—:
  `seal --fail-on-stale` (en PHP, `failOnStale: true`) no escribe y sale con 3, transitorio.

El cron del `sync`, con la passphrase por fichero porque `sync` firma:

```cron
0 * * * * /usr/local/bin/nucleo --dir /var/lib/nucleo sync --policy-file /etc/nucleo/politica.json --witness https://testigo.ejemplo.ec --passphrase-file /etc/nucleo/passphrase
```

Todo lo de esta sección está cubierto por tests: `cmd/nucleo/alarma_test.go` (sin leer stderr
en ningún momento), la suite del SDK de PHP y el paso 9 de la demo del ejemplo Node, que
corre en CI.

---

## Qué se comprobó y qué no

| | |
|---|---|
| **Ejecutado** | la unidad systemd del testigo (verificada y levantada), `sync` por HTTPS a través de Caddy, el respaldo y la restauración del testigo, la recuperación con un testigo nuevo y los recibos viejos y nuevos verificando, el anclaje del hash de la política, la pérdida de la passphrase y su sustitución con dos tarjetas (`restore --new-passphrase-file`, con una copia del ledger de antes del cambio), `proc_open`, `noexec`, `ext-sodium`, los umbrales de memoria virtual y los picos de memoria real, el `memory_limit` de PHP, y la alarma de frescura |
| **No ejecutado aquí** | lo que exige root (`useradd`, `install -o`, `update-ca-certificates`, una unidad de sistema como tal), el certificado ACME de un dominio público, un límite de memoria **real** por cgroups, y la regla de permisos del `Sealer` en un PHP de Linux (lo cubre el CI) |

Cuatro fallos salieron de escribir esta guía y están arreglados en el mismo sprint:
un binario que moría sin memoria se daba por fallo de integridad; un certificado TLS no
aceptado se explicaba como un problema de red; el testigo decía «Ctrl-C para parar» en el
journal de systemd; y el producto prometía que `restore` recuperaba un vault cuya
passphrase se había perdido. Esa promesa es verdad desde ADR-029 (Sprint 14), que es cuando
se cumplió: la guía dijo lo contrario mientras no lo era.
