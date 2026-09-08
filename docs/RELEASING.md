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
a `main` no publica.

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
