# ADR-026-ejemplo-de-integracion

**Estado:** ACEPTADA el 2026-09-23 por el dev (Sprint 11) · **Fecha:** 2026-09-23 · **Fuentes:** CONCEPTO-v1.2-es.md §18 (criterio de éxito de la v1), ADR-021 (el SDK de PHP y su asimetría), ADR-025 (la salida `--json` como formato de cable), `docs/ensayo-de-operacion-20260923.md`

## El problema

El criterio de éxito de la v1 dice: *«un desarrollador cualquiera, sin saber criptografía,
integra Núcleo en menos de una hora siguiendo la documentación»*. Hay tutorial, hay
protocolo, hay tres verificadores y hay un SDK de PHP. Lo que no hay es **una aplicación
que integre Núcleo**, y sin ella esa frase no se puede ni medir ni enseñar.

Hace falta decidir dos cosas antes de escribir una línea: **dónde vive** el ejemplo y de
**qué versión del verificador** depende.

## Decisión

### A. Vive en este repositorio, en `examples/erp-node/`

No en un repositorio aparte, y la razón es la que acabamos de comprobar en carne propia
mientras escribíamos este ADR: **el paquete publicado en npm no verifica los recibos que
emite el binario de hoy.**

```
@nucleoledger/verify@0.1.0-alpha.0  (publicado el 2026-09-10)
  → "el recibo no se pudo leer: se esperaba nucleo.org/receipt@v1 en la primera línea"
```

`receipt@v2` llegó con ADR-014 y el paquete no se ha vuelto a publicar. Un ejemplo en un
repositorio aparte, con sus dependencias fijadas, habría seguido en verde con la versión
vieja durante semanas: es exactamente la forma en la que un ejemplo se podre sin que nadie
lo note. Dentro del repositorio:

- se construye contra el **binario de este commit** y contra el **SDK de este commit**;
- su CI corre en cada push, así que un cambio de formato lo rompe **aquí** y no en casa de
  un cliente;
- y quien clona el repositorio para auditarlo se encuentra el protocolo, los ADR, los
  verificadores y una aplicación que los usa, en el mismo árbol y con la misma historia.

El precio: el repositorio gana un directorio de primer nivel y el CI un job. Se paga.

### B. Depende del SDK del repositorio, no del de npm, y lo dice

`package.json` del ejemplo usa `"@nucleoledger/verify": "file:../../sdk/ts"`. Un
integrador de verdad escribe `npm install @nucleoledger/verify`, y el README del ejemplo lo
dice en la primera pantalla —junto con la advertencia de que la versión publicada hoy es
anterior a `receipt@v2`, así que hasta que se republique hay que usar la del repositorio—.

La alternativa era depender de npm para que el ejemplo fuera «realista». Sería realista y
estaría roto, y un ejemplo roto enseña a no confiar en el ejemplo.

### C. El envoltorio del binario se escribe DESDE el contrato, sin mirar el de PHP

El sellado invoca el binario, igual que `Nucleo\Sealer` (ADR-021 §A): el ledger tiene un
solo escritor. Pero el envoltorio de Node se escribe leyendo `docs/CLI-JSON.md`, no
traduciendo el PHP, y eso es a propósito: da un **segundo consumidor independiente** del
contrato de ADR-025 en otro lenguaje. Si el contrato está bien definido, dos envoltorios
escritos por separado lo consumen sin sorpresas; si no, la fricción aparece aquí.

El ejemplo **no reimplementa criptografía** —eso lo hace el SDK— y **no esconde a Núcleo**:
cada pantalla enseña el comando que se ejecutó y el recibo tal cual.

### D. Qué demuestra, y por qué eso y no otra cosa

Los cinco pasos del criterio de éxito, dentro de una aplicación: sellar cada factura al
emitirla **con clave de idempotencia** (ADR-020 §D), sincronizar con la receta de cron que
el ensayo de operación dejó funcionando, emitir el recibo del cliente, verificar un recibo
**pegado** con el SDK, y reconciliar enseñando una alteración detectada.

Y el manejo de errores que el ensayo de operación documentó, demostrado y no ignorado: qué
hace el ERP si falta el binario, si el testigo no contesta, si el sellado pierde una
carrera, si la salida no cumple el contrato.

## Consecuencias

- El criterio de éxito §18 pasa a ser **medible**: hay algo que cronometrar.
- Cualquier cambio en la salida `--json`, en el formato del recibo o en los códigos de
  salida rompe el job del ejemplo. Eso es el objetivo, no un efecto secundario.
- El ejemplo es Node porque el verificador ya existe en TypeScript y porque así el
  contrato gana un segundo consumidor. Un ejemplo en PHP tendría que usar el SDK de PHP,
  que ya está probado contra los mismos vectores: aportaría menos.
- Queda una deuda con nombre: **republicar `@nucleoledger/verify`**. Hasta entonces, el
  README del SDK y el del ejemplo dicen que la versión de npm es anterior a `receipt@v2`.
  **Cerrada el 2026-09-25**: ver [Cierre de la deuda de §B](#cierre-de-la-deuda-de-b).

## Cierre de la deuda de §B

**2026-09-25.** `@nucleoledger/verify@0.2.0-alpha.0` se publicó en npm desde
`publish-npm.yml` con trusted publishing, y con procedencia SLSA: la atestación dice
`nucleoledger/nucleo`, workflow `.github/workflows/publish-npm.yml`,
`refs/tags/vsdk-0.2.0-alpha.0`, commit `669eaf2`. Los dos dist-tags, `latest` y `alpha`,
apuntan a esa versión.

Antes de cambiar el ejemplo se comprobó el paquete **del registro**, no el build local:
instalado en un proyecto vacío, `npm audit signatures` da *«1 package has a verified
attestation»*, verifica un recibo `@v2` recién emitido por el binario de HEAD —las dos
firmas, tiempo demostrable, un cosignatario— y rechaza ese mismo recibo con un carácter
cambiado.

El ejemplo depende ahora de `"@nucleoledger/verify": "0.2.0-alpha.0"`, fijado por versión
exacta y, en `package-lock.json` —que pasa a versionarse—, por el hash sha512 del tarball
publicado. `bin/setup.js` instala con `npm ci` y se niega a seguir si encuentra un enlace a
una carpeta local, y el job `ejemplo` del CI corre `npm audit signatures`. El CI comprueba
por tanto lo mismo que obtendría un tercero que clone el repositorio.

**Lo que cambia de las consecuencias.** El job `ejemplo` ya no ve los cambios del
verificador del repositorio hasta que se publiquen. Es lo que se quería y tiene un efecto
útil: si el formato del recibo vuelve a cambiar, el ejemplo se pondrá rojo con la versión
publicada, y ese rojo es el aviso de que hay que publicar el SDK antes de publicar el
binario. Exactamente lo que faltó entre el 10 y el 25 de septiembre.

## Alternativas descartadas

- **Repositorio aparte (`nucleo-ejemplo-erp`).** Más «limpio» y se podre solo: sus
  dependencias se fijan, su CI no ve los cambios del protocolo, y el primer integrador que
  lo clone se encontrará lo que nos encontramos hoy con npm.
- **Un hola-mundo de veinte líneas.** Sella y no demuestra nada: ni idempotencia, ni
  reconciliación, ni qué hacer cuando el testigo no está. El criterio de éxito habla de
  alterar un registro y detectarlo, y eso necesita una aplicación con datos propios.
- **Un ejemplo con framework (Express, Next).** Añade dependencias que no son del problema
  y envejecen más rápido que Núcleo. El ejemplo usa solo la biblioteca estándar de Node, y
  así su `node_modules` es exactamente el verificador y nada más.
- **Esconder Núcleo detrás de una capa propia** («NucleoService», «LedgerRepository»). Es
  lo que haría un ejemplo que quiere lucirse; aquí lo que hay que ver es el comando, el
  JSON y el recibo.
