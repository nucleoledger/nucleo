# Releasing Núcleo

Este documento tiene dos mitades y las dos importan:

- **[Cómo se publica una versión](#publicar-una-versión)**, para quien mantiene el proyecto.
- **[Cómo se verifica una descarga](#verificar-una-descarga)**, para quien la usa.

La segunda es la que justifica la primera. Un proyecto que vende integridad
verificable y distribuye binarios que nadie puede comprobar estaría vendiendo
algo que él mismo no practica.

---

## Qué se firma, y con qué

Los binarios se compilan con [GoReleaser](https://goreleaser.com) y **el fichero
de checksums se firma con [cosign](https://github.com/sigstore/cosign) en modo
keyless**, desde el workflow de GitHub Actions.

*Keyless* significa que **no hay ninguna clave privada de firma**: ni guardada en
un secreto del repositorio, ni en el llavero de nadie, ni que se pueda perder o
filtrar. En su lugar, cosign pide un token OIDC a las Actions de GitHub —que
acredita *qué workflow, de qué repositorio, sobre qué tag* está corriendo—, obtiene
de Sigstore un certificado efímero atado a esa identidad, firma con él, y publica
la entrada en [Rekor](https://docs.sigstore.dev/logs/overview/), un log de
transparencia público.

El resultado es que quien descarga puede comprobar dos cosas distintas:

1. Que los bytes son los que se firmaron (la firma).
2. **Quién los firmó**: no "alguien con una clave", sino "el workflow
   `release.yml` del repositorio `nucleoledger/nucleo`, en el tag `vX.Y.Z`". Eso
   es lo que una clave privada no puede decir.

Y esa afirmación queda en un log de transparencia que ni quien publica puede
reescribir después. Es exactamente la propiedad que Núcleo ofrece para los
registros de sus usuarios, aplicada a su propia distribución.

### Lo que NO va en el binario publicado

Los ganchos de prueba —`NUCLEO_TEST_SEED`, `NUCLEO_TEST_CLOCK`,
`NUCLEO_TEST_PASSPHRASE`— viven tras el build tag `testhooks`, y goreleaser
compila **sin** ese tag. Ese código no está en el ejecutable que se publica.

Un binario publicado que los honrara permitiría fijar desde el entorno del
proceso el material "aleatorio" con el que se generan las claves de un vault.
Que el gancho estuviera "apagado por una condición" no bastaría: seguiría siendo
código presente y alcanzable. Lo que no se compiló no tiene esa superficie.

El binario publicado sí conoce los NOMBRES de esas variables, porque los necesita
para rechazarlas: si alguna está definida, **aborta** con un error que lo
explica, en vez de avisar y seguir. Se puede comprobar sobre el binario
descargado:

```bash
# El código de los ganchos no está:
strings nucleo | grep -c "HONRA los ganchos de prueba"   # → 0
# Y el rechazo sí:
NUCLEO_TEST_SEED=x ./nucleo status ; echo $?             # → 1
```

Se firma **el fichero de checksums**, no cada archivo por separado. El
`checksums.txt` contiene el SHA-256 de todos los artefactos, así que una firma
sobre él cubre a todos, y verificarla son dos comandos en vez de doce.

---

## Publicar una versión

### Antes del tag

- [ ] `go test ./... -race` en verde.
- [ ] `go test -tags testhooks ./... -race` en verde.
- [ ] `golangci-lint run ./...` sin issues.
- [ ] `./scripts/demo-criterio-exito.sh` en verde. Es el criterio del proyecto:
      si falla, no hay versión que publicar.
- [ ] `cd sdk/ts && npm ci && npm run typecheck && npm test` en verde.
- [ ] `CHANGELOG.md` con la sección de la versión, escrita a mano.
- [ ] `git status` limpio.
- [ ] `goreleaser check` sin errores.

Una prueba en seco, que compila los seis binarios sin publicar nada:

```bash
goreleaser release --snapshot --clean --skip=sign
ls dist/
```

### El tag

```bash
git tag -a v0.1.0-alpha -m "v0.1.0-alpha"
git push origin v0.1.0-alpha
```

El push del tag es lo que dispara el workflow. **Nada más lo dispara**: un push
a `main` no publica, y **un tag del SDK tampoco**.

`release.yml` escucha solo los tags del core: `v` seguida de un **dígito**
(`v[0-9]*`). Los del SDK de TypeScript empiezan por `vsdk-` y los atiende
`publish-npm.yml`. Hasta el 25 de septiembre de 2026 el filtro era `v*`, que
capturaba los dos: el tag `vsdk-0.2.0-alpha.0` lanzó el release del binario (run
36098169879), pasó los tests y la demo, y solo se paró porque goreleaser no pudo
leer `vsdk-0.2.0-alpha.0` como versión semántica. No publicó nada, pero lo que lo
impidió fue un parser, no un control. Además, el workflow le pasa a goreleaser el
tag que lo disparó (`GORELEASER_CURRENT_TAG`): en ese run, goreleaser había elegido
por su cuenta el tag del SDK como versión.

Así que las dos cadencias son independientes de verdad, y no solo en el papel:
un tag `vsdk-*` publica el paquete de npm y nada más, y un tag `vX.Y.Z` publica los
binarios y nada más.

### Después

1. El workflow deja el release **en borrador**. Es deliberado: da la oportunidad
   de mirar los artefactos antes de que exista para el mundo.
2. Verifica tu propio release con el procedimiento de abajo, desde otra máquina
   y descargando de la página. Si no puedes verificarlo tú, tus usuarios tampoco.
3. Publica el borrador.

### Errores y cómo deshacerlos

Un tag empujado que resultó estar mal:

```bash
git tag -d v0.1.0-alpha
git push --delete origin v0.1.0-alpha
```

Borra también el release en borrador desde la interfaz de GitHub. **La entrada de
Rekor no se borra** —es un log de transparencia y esa es su gracia—, así que
quedará constancia de que se firmó algo con ese tag. No es un problema: es
información honesta. Publica la corrección con un tag nuevo, nunca reutilizando
el anterior.

---

## Verificar una descarga

Necesitas [cosign](https://docs.sigstore.dev/cosign/system_config/installation/).
Son unos treinta segundos.

### 1. Descarga

De la página del release, tres ficheros:

- el archivo de tu plataforma, p. ej. `nucleo_0.1.0-alpha_linux_amd64.tar.gz`
- `checksums.txt`
- `checksums.txt.sig` y `checksums.txt.pem`

### 2. Comprueba quién firmó los checksums

```bash
cosign verify-blob checksums.txt \
  --signature checksums.txt.sig \
  --certificate checksums.txt.pem \
  --certificate-identity-regexp '^https://github\.com/nucleoledger/nucleo/\.github/workflows/release\.yml@refs/tags/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

Debe imprimir `Verified OK`.

**Los dos `--certificate-*` no son opcionales.** Sin ellos, cosign comprueba que
la firma es válida pero no *de quién*, y cualquiera puede producir una firma
válida a su propio nombre. Lo que hace útil a este comando es que exige que quien
firmó sea el workflow `release.yml` de este repositorio, ejecutándose sobre un
tag.

### 3. Comprueba que tu archivo es uno de los que se firmaron

```bash
sha256sum --ignore-missing -c checksums.txt
```

Debe imprimir `OK` para el fichero que descargaste.

Ese es el enganche entre los dos pasos: la firma cubre el `checksums.txt`, y el
`checksums.txt` cubre tu archivo. Comprobar solo uno de los dos no demuestra nada.

### 4. Y ya

```bash
tar xzf nucleo_0.1.0-alpha_linux_amd64.tar.gz
./nucleo help
```

### Verificación en un solo comando

Para meterlo en un script de instalación:

```bash
set -euo pipefail
VER=0.1.0-alpha
BASE=https://github.com/nucleoledger/nucleo/releases/download/v$VER
ARCHIVO=nucleo_${VER}_linux_amd64.tar.gz

curl -fsSLO "$BASE/$ARCHIVO"
curl -fsSLO "$BASE/checksums.txt"
curl -fsSLO "$BASE/checksums.txt.sig"
curl -fsSLO "$BASE/checksums.txt.pem"

cosign verify-blob checksums.txt \
  --signature checksums.txt.sig --certificate checksums.txt.pem \
  --certificate-identity-regexp '^https://github\.com/nucleoledger/nucleo/\.github/workflows/release\.yml@refs/tags/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com

sha256sum --ignore-missing -c checksums.txt
tar xzf "$ARCHIVO"
```

### Si la verificación falla

**No ejecutes el binario.** Un fallo aquí significa una de tres cosas: la
descarga se corrompió, estás mirando ficheros de releases distintos, o alguien
puso algo que no es lo que se publicó. Vuelve a descargar; si sigue fallando,
[abre un issue](https://github.com/nucleoledger/nucleo/issues) con la salida
exacta de cosign.

---

## La clave de un testigo, en Windows

`nucleo witness serve` guarda su clave privada junto a su base de datos y, en
Unix, **rehúsa arrancar si ese fichero es legible por otros usuarios**: un testigo
cuya clave privada puede leer cualquiera no atestigua nada, porque quien la lea
puede firmar en su nombre.

En Windows esa comprobación **no se hace**. Los permisos que Go expone allí son
una traducción aproximada; el control de acceso real vive en la ACL del fichero,
que no se ve desde ahí. Una comprobación que puede decir «está bien» cuando no lo
está es peor que no tenerla, así que no se finge.

Si operas un testigo en Windows, restringe la ACL a tu cuenta:

```powershell
icacls testigo.db.key /inheritance:r /grant:r "$env:USERNAME:(R,W)"
```

## Compilar desde el código

Siempre es una alternativa a descargar, y no depende de confiar en nadie:

```bash
git clone https://github.com/nucleoledger/nucleo
cd nucleo
go build -o nucleo ./cmd/nucleo
```

Las compilaciones de release usan `-trimpath` y `-ldflags "-s -w"` con el
timestamp del commit, así que un binario compilado desde el mismo commit y con la
misma versión de Go debería dar los mismos bytes. Si el tuyo no coincide con el
publicado, eso es exactamente el tipo de cosa que queremos saber.

---

## Publicar el SDK de TypeScript en npm

El paquete `@nucleoledger/verify` se publica desde
`.github/workflows/publish-npm.yml`, con su propio tag `vsdk-<versión>` para que
su ritmo no quede atado al del binario Go (y `release.yml` no lo escucha: ver
[El tag](#el-tag)). La autenticación es **npm Trusted
Publishing**: OIDC contra ese workflow concreto, sin ningún token de npm en los
secretos del repositorio.

### Lo que hay que configurar una sola vez, en npmjs.com

El paquete tiene que existir antes de poder configurarlo. `0.1.0-alpha.0` se publicó a
mano y sin procedencia (ver CHANGELOG); **`0.2.0-alpha.0` fue la primera versión
publicada por esta vía**, el 2026-09-25, y la configuración de abajo es la que está
hecha.

1. Entrar en `https://www.npmjs.com/package/@nucleoledger/verify` → pestaña
   **Settings**.
2. En la sección **Trusted Publisher**, en "Select your publisher", pulsar
   **GitHub Actions**.
3. Rellenar los campos exactamente así:

   | Campo | Valor |
   |---|---|
   | **Organization or user** | `nucleoledger` |
   | **Repository** | `nucleo` |
   | **Workflow filename** | `publish-npm.yml` |
   | **Environment name** | *dejar vacío* |

   El nombre del workflow es **solo el fichero**, no la ruta, y distingue
   mayúsculas: tiene que coincidir carácter a carácter con el que hay en
   `.github/workflows/`. Si algún día se rellena "Environment name", el job
   necesita además una clave `environment:` con ese mismo nombre, o npm rechaza
   la petición.

4. En **Allowed actions**, marcar que se permite **`npm publish`**, no solo
   `npm stage publish`. Esto importa: desde el 3 de septiembre de 2026 las
   configuraciones nuevas solo permiten *staging* por omisión y la publicación
   directa es opt-in. Si se deja como viene, el workflow falla con 403 aunque
   todo lo demás esté bien.
5. Guardar.

Alternativa, si más adelante se prefiere una aprobación humana por versión: dejar
solo el *staging*, cambiar el último paso del workflow a `npm stage publish`, y
aprobar desde una máquina con `npm stage list @nucleoledger/verify` y
`npm stage approve <stage-id>` (esto sí pide 2FA, y exige npm 11.15.0+).

### Publicar una versión

```bash
# 1. La versión en sdk/ts/package.json es la que manda.
cd sdk/ts && npm version 0.2.0-alpha.0 --no-git-tag-version
# 2. Commit y, ya en la raíz, el tag con el MISMO número.
git commit -am "chore(sdk): versión 0.2.0-alpha.0"
git tag -a vsdk-0.2.0-alpha.0 -m "sdk 0.2.0-alpha.0"
git push origin main vsdk-0.2.0-alpha.0
```

El workflow comprueba que el tag y `package.json` coinciden antes de tocar la
red, y corre typecheck, tests y build antes de publicar. También se puede
disparar a mano (`workflow_dispatch`), y en ese caso la comprobación del tag se
salta porque no hay tag que comprobar.

### El tag de npm, y el paso que queda a mano

El workflow publica con **`--tag latest`**, explícito. Dos razones:

- **npm 11 no publica una prerelease sin `--tag`** (*«You must specify a tag using
  --tag when publishing a prerelease version»*), y el workflow instala npm 11. Se
  comprobó en local, con los mismos pasos del workflow, antes de empujar el primer
  tag `vsdk-*`.
- **`latest` es lo que instala todo el mundo.** Mientras todas las versiones sean
  alfas, dejar `latest` en una anterior es entregar por defecto un verificador que
  quizá no lee los recibos del binario de hoy —que es exactamente lo que pasó con
  0.1.0-alpha.0 frente al recibo @v2—.

El tag `alpha` **se mueve a mano**, cuando el workflow termina en verde:

```bash
npm dist-tag add @nucleoledger/verify@<versión> alpha
npm view @nucleoledger/verify dist-tags    # latest y alpha en <versión>
```

A mano porque trusted publishing autoriza a este workflow a **publicar**, no a
mover dist-tags; eso pide la cuenta y su 2FA. El día de la 1.0 la regla se invierte:
las prereleases se publican con su propio tag y `latest` queda para las estables.

### Qué comprobar después de publicar

- En la página del paquete, la sección **Provenance**: construido desde
  `nucleoledger/nucleo`, workflow `publish-npm.yml`, en el commit del tag. Si no
  aparece, el paquete no salió por esta vía y hay que averiguar por cuál.
- La pestaña de código: `LICENSE`, `README.md`, `dist/` y `package.json`, nada más.
- Que un recibo recién emitido por el binario verifica con el paquete **del
  registro** (`npm pack @nucleoledger/verify@<versión>`, no el build local).

### Si el workflow falla

No se publica nada y el tag se borra sin daño:

```bash
git tag -d vsdk-<versión>
git push origin :vsdk-<versión>
```

Lo que no se recupera es un número de versión **ya publicado** en npm, aunque se
despublique: por eso los fallos se buscan en local antes de empujar el tag.

### Por qué no se pasa `--provenance`

Con trusted publishing, npm genera la atestación de procedencia por su cuenta.
`publishConfig.provenance: true` se queda en `package.json` de todas formas: así
una publicación por cualquier otra vía —una máquina de desarrollo, por ejemplo—
**falla** en vez de salir sin procedencia en silencio. Que esa bandera siga en
pie lo vigila `sdk/ts/test/packaging.test.ts`, porque perderla no rompería nada
visible.

Requisitos de versión, por si el paso de publicar falla sin explicarse: trusted
publishing necesita **npm 11.5.1+** y Node 22.14+. El npm que trae Node 22 es el
10.9.x, así que el workflow instala uno más nuevo a propósito.
