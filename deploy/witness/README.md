# Operar un testigo de Núcleo

Esta guía es para quien **opera un testigo para otros**: un estudio contable que atestigua
a sus clientes, un fabricante de ERP que lo ofrece a sus instalaciones, o una empresa que
atestigua a otra (testigo mutuo). Quien **integra** Núcleo en su sistema tiene su guía en
[`docs/OPERACION.md`](../../docs/OPERACION.md).

El autor del proyecto no opera testigos para nadie: esto es el software y el kit. Cada orden
de esta guía se ejecutó en local con el binario de `main` el 2026-10-10, salvo las que
exigen root, que lo dicen. El CI valida los tres ficheros de esta carpeta en cada push
(`scripts/valida-kit-testigo.sh`).

| fichero | qué es | dónde va |
|---|---|---|
| [`nucleo-testigo.service`](nucleo-testigo.service) | la unidad de systemd | `/etc/systemd/system/` |
| [`Caddyfile`](Caddyfile) | TLS delante, con certificado automático | `/etc/caddy/Caddyfile` |
| [`testigo.json.ejemplo`](testigo.json.ejemplo) | la configuración: qué logs atiende ([ADR-030](../../docs/adr/ADR-030-testigo-de-varios-logs.md)) | `/etc/nucleo-testigo/testigo.json` |

## Lo que es un testigo, en una frase

Recuerda la última raíz que cosignó de cada log y solo cosigna una nueva si demuestra que
**extiende** a la anterior. Esa memoria, y que la tenga alguien que no es el emisor, es lo
que convierte un ledger reescrito o recortado en algo detectable.

## Instalarlo

```bash
useradd --system --no-create-home --shell /usr/sbin/nologin nucleo-testigo
install -m 0755 nucleo /usr/local/bin/nucleo          # el binario verificado: docs/RELEASING.md
install -d -m 0755 /etc/nucleo-testigo
install -m 0644 testigo.json /etc/nucleo-testigo/testigo.json
install -m 0644 nucleo-testigo.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now nucleo-testigo.service
```

Todas exigen root y **no se ejecutaron aquí**; son las órdenes estándar. Lo que sí: la unidad
pasa `systemd-analyze verify` sin un solo aviso, y `witness serve --config` arranca con la
configuración de ejemplo (2 logs servidos, 1 retirado) —las dos cosas también en el CI—. Y la
unidad se **levantó de verdad** como servicio de usuario de systemd 249, con las mismas
directivas salvo las que el modo usuario no admite (`User=`/`Group=` fuera, `PrivateUsers=yes`,
`ProtectHome=read-only`): quedó activa, creó la clave en `0600`, atestiguó a un cliente, y
tras `systemctl restart` conservó la misma clave y su memoria (*«extensión de 1 a 2, con prueba
de consistencia»*).

La configuración es **de root y de solo lectura** para el servicio (`0644`): quien la
escribe decide qué cosigna el testigo, y el propio testigo no tiene por qué poder cambiarla.
Si otros pueden escribirla, el testigo lo avisa al arrancar.

## Tu clave pública: lo que publicas

La primera vez que arranca, el testigo crea su clave en `/var/lib/nucleo-testigo/testigo.db.key`
(modo `0600`). La pública es la que tus clientes ponen en su política:

```bash
sudo -u nucleo-testigo /usr/local/bin/nucleo witness key --db /var/lib/nucleo-testigo/testigo.db
```

**Con `sudo -u nucleo-testigo`, no como root**: si la clave aún no existe, esa orden la crea,
y creada por root el servicio no podría leerla. (`witness key` y su `0600` se comprobaron
aquí; el `sudo -u`, no: exige root.) Publícala con el `name` de tu configuración por un canal
que no sea el testigo: tu web, un documento firmado, en persona.

## Dar de alta a un cliente

1. El cliente te da el **origin** y la **clave pública de su log**: los imprime su
   `nucleo --json status` (`origin`, `log_pubkey`).
2. Añádelo a `logs` en `/etc/nucleo-testigo/testigo.json` y `systemctl restart nucleo-testigo`.
   La memoria de los demás no se toca: vive en la base, no en el proceso.
3. Le das tu `name`, tu clave pública y la URL (`https://testigo.ejemplo.ec`). Su primer
   `sync` con esos datos termina en *«✔ atestación obtenida del testigo …»* —comprobado—.

## Retirar a un cliente

Muévelo de `logs` a `retired` **con la misma clave** y reinicia. La clave se comprueba: si
no es la que firmó lo que el testigo recuerda de ese log, el testigo no arranca y lo dice. Desde ese momento su `sync` recibe un 404 y la CLI
le dice *«el testigo … dejó de cosignar este log: lo retiró quien lo opera»*; su memoria se
queda, y su último checkpoint se sigue publicando (abajo). Es lo que pide un cliente cuya
passphrase se robó ([ADR-029](../../docs/adr/ADR-029-restore-fija-passphrase-nueva.md),
enmienda §F): que no cosignes nada más de ese log, y poder enseñar hasta dónde llegó.

**No lo borres del fichero sin más**: el testigo lo recordará igual —la memoria no se borra—
y lo dirá al arrancar, pero dejará de publicarlo.

## Qué respaldas

El directorio entero, **con el servicio parado**, y el fichero de configuración:

```bash
systemctl stop nucleo-testigo
tar -C /var/lib/nucleo-testigo -cpzf /respaldo/testigo-$(date +%F).tgz .
cp /etc/nucleo-testigo/testigo.json /respaldo/
systemctl start nucleo-testigo
```

- `testigo.db` es la **memoria**: sin ella el testigo acepta cualquier historia como la
  primera que ve, y no detecta un rollback —comprobado en el ensayo del testigo mutuo—.
- `testigo.db.key` es la **clave privada**: sin ella, eres otro testigo.
- Ese respaldo **contiene una clave privada**: guárdalo como tal, y nunca al alcance de los
  emisores a los que atestiguas.

Comprobado aquí con el proceso parado: el `tar -p` guarda la clave en `0600`; se borró el
directorio, se restauró, y el testigo arrancó con **la misma clave** (`created: false`) y
siguió cosignando al cliente desde donde estaba, *«extensión de 1 a 2, con prueba de
consistencia»*. (El `systemctl` no se ejecutó aquí: exige root.)

## Qué vigilas

| qué | cómo | comprobado |
|---|---|---|
| que el servicio está vivo | `systemctl is-active nucleo-testigo`; los fallos, en `journalctl -u nucleo-testigo` | no aquí (root) |
| que responde por cada cliente | `curl -fsS https://testigo.ejemplo.ec/$(printf %s 'cliente-a.ec/facturacion' \| sha256sum \| cut -d' ' -f1)/checkpoint` devuelve el último checkpoint que cosignó para ese origin | sí, contra el testigo local por HTTP |
| que la clave no ha cambiado | tras cada reinicio o restauración, `witness key` da la misma clave que publicaste | sí |
| el certificado | Caddy lo renueva solo; si falla, los `sync` de tus clientes salen con un error de TLS | no aquí (dominio público) |
| el disco | la base crece con el número de logs, no con el de bloques: guarda **un** checkpoint por log | — |

Si un cliente deja de sincronizar, **no es cosa tuya** salvo que tu testigo no responda: su
alarma de frescura suena en su lado. Pero si te avisa de un rollback —su `sync` sale con
código 2—, **conserva tu memoria tal como está**: es la evidencia de lo que cosignaste.

## Si pierdes la clave, o la memoria

- **Sin la clave** eres otro testigo: las cosignatures que ya emitiste se siguen verificando
  con tu clave pública vieja, pero no puedes emitir más con ella. Levanta el nuevo con **otro
  `name`** desde el primer arranque —con el viejo, y renombrado después, sirve notas firmadas
  con el nombre viejo y los `sync` fallan— y avisa a **todos** tus clientes: su política
  añade tu testigo nuevo y **conserva el viejo**, porque los recibos que ya entregaron los
  cosignaste con él. Es el procedimiento de [`docs/OPERACION.md`](../../docs/OPERACION.md) §1,
  «Si se pierden sin respaldo», desde el otro lado.
- **Sin la memoria pero con la clave**, restaura el respaldo. Si no hay respaldo, trátalo
  como una clave perdida —otro `name`, otra clave, aviso a todos—: un testigo sin memoria
  firmando con la clave de siempre cosignaría cualquier historia como la primera, y no
  detectaría el rollback de nadie.
- **Si te roban la clave**, lo mismo, y además díselo a tus clientes como lo que es: quien la
  tenga puede emitir cosignatures en tu nombre.
