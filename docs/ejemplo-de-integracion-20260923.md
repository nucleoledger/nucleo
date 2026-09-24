# El ejemplo de integración, y lo que encontró (Sprint 11)

**Fecha**: 23 de septiembre de 2026.
**Entregable**: `examples/erp-node/` — un ERP mínimo pero realista en Node.js que sella
sus facturas, sincroniza con un testigo, entrega recibos, verifica uno pegado y reconcilia.
**Decisión de dónde vive y de qué depende**: [ADR-026](adr/ADR-026-ejemplo-de-integracion.md).

Dos objetivos, y el segundo importaba tanto como el primero:

1. que un desarrollador que no conoce Núcleo pueda clonar, levantar y entender en menos
   de una hora cómo su sistema sella registros y entrega recibos;
2. **poner un segundo consumidor independiente del contrato `--json`** (ADR-025), en otro
   lenguaje y escrito desde `docs/CLI-JSON.md` sin mirar el envoltorio de PHP. Si dos
   lectores escritos por separado consumen el mismo JSON sin sorpresas, el contrato está
   bien definido. Si no, el ejemplo lo descubre aquí y no en casa de un cliente.

Lo segundo dio seis hallazgos. Cuatro se arreglaron en este sprint; dos son decisiones del
dev y quedan anotadas.

---

## 1. Qué se construyó

| Fichero | Qué es |
|---|---|
| `src/contrato.js` | Lector estricto de la salida `--json`. El gemelo en Node de `Nucleo\Contract` |
| `src/nucleo.js` | El envoltorio del binario: política en toda ejecución, passphrase por fichero, códigos de salida como errores con tipo, stderr recogido |
| `src/erp.js` | Las facturas: documento canónico con `nonce`, clave de idempotencia = número de factura, y el JSONL que consume `reconcile` |
| `src/servidor.js` | Cinco pantallas y el manejo de errores, que es media integración |
| `src/paginas.js` | El HTML. Sin dependencias, y con una regla: el comando se ve |
| `bin/setup.js` | El arranque: binario, verificador, ledger, primera atestación y política |
| `bin/testigo.js` | Un testigo local, en su propio proceso |
| `bin/demo.js` | El recorrido completo sin navegador, **con aserciones**. Es lo que corre el CI |
| `bin/cron.js` | La receta del ensayo de operación, lista para un crontab |

Cero dependencias de runtime más allá del verificador: `node:http` y cadenas. El
ejemplo **no** reimplementa criptografía, **no** envuelve el protocolo en abstracciones
propias y **no** esconde lo que hace Núcleo: cada pantalla enseña el comando que ejecutó.

Y tiene su propio job de CI (`ejemplo`), que corre los dos comandos que el README manda
teclear, comprueba que el cron propaga sus códigos de salida y que el servidor sirve el
panel. Si el contrato, el recibo o un código de salida cambian, ese job se pone rojo con
los demás en verde: eso es la señal que se quería.

---

## 2. Los hallazgos

### H1 — El paquete publicado en npm no lee los recibos que emite el binario

`@nucleoledger/verify@0.1.0-alpha.0` (publicado el 10 de septiembre) solo conoce
`nucleo.org/receipt@v1`. Un recibo emitido hoy vuelve con `valid: false` y la razón
*"se esperaba nucleo.org/receipt@v1 en la primera línea"*.

El ejemplo depende por eso de `file:../../sdk/ts`, y su README lo dice en voz alta: un
integrador escribiría `npm install @nucleoledger/verify`. **No se arregla con código**:
hay que republicar el paquete, y eso es del dev. Deuda declarada en ADR-026.

### H2 — `replay_suspect` estaba en la salida y no en el contrato

`sync` publica `replay_suspect` desde el Sprint 8; la tabla de `sync` en
`docs/CLI-JSON.md` no lo mencionaba, solo aparecía de pasada en la sección `freshness`.

Consecuencia práctica: un consumidor escrito contra el documento no lo lee —y se pierde
el aviso de cosignature vieja—, y uno escrito mirando la salida lo exige contra un
documento que no lo promete. **Documentado** (`572a5ee`).

### H3 — `findings` era `null` justo en el caso bueno

El contrato promete un array. Una lista nil en Go se serializa como `null`, así que el
cotejo que **no encuentra nada** entregaba `"findings": null` y rompía al consumidor
estricto que exige ADR-025. Con hallazgos sí entregaba un array: el fallo solo se veía
cuando todo estaba bien.

Arreglado en el emisor y no tolerado en el consumidor, por la regla que ya estaba en el
contrato —los booleanos son booleanos y los enteros enteros— con test de regresión que
falla si se vuelve a la lista nil (`abb2957`). De paso, la tabla decía que `full_verify`
sale "solo con `--full`", y en `reconcile` **`--full` vale `true` por omisión**: el cotejo
recomprueba todas las firmas históricas salvo que se pase `--full=false`.

### H4 — El hallazgo del bloque 0 salía sin índice

`Index` llevaba `omitempty`, así que un hallazgo sobre el bloque 0 se serializaba sin
índice y quien lee el informe no podía distinguir "índice 0" de "no vino el campo". No es
un caso de laboratorio: el bloque 0 es la primera factura de cualquiera que integre
Núcleo, y el ejemplo lo pisó en su primer minuto de vida. Arreglado con su test
(`d3ca9c2`).

### H5 — Un consejo de permisos que no se puede seguir

Secuencia exacta, con el repositorio en `/mnt/c` (WSL):

```
nucleo witness serve --db datos/testigo/testigo.db ...   → arranca y crea la clave
Ctrl-C y arrancarlo otra vez                             → código 1:
  "la clave del testigo ... tiene permisos 0777 ... Corrígelo con: chmod 600 ..."
chmod 600 testigo.db.key && ls -l                        → sigue en 0777
```

El testigo arranca **una** vez —la que crea su clave— y no vuelve a arrancar nunca, con
un mensaje que manda hacer justo lo único que en ese sistema de ficheros no hace nada:
`/mnt/c` se monta sin metadatos y `chmod` contesta que sí.

La negativa está bien y se queda: una clave privada legible por otros usuarios no
atestigua nada. Lo que se arregló es el diagnóstico —si el directorio no guarda permisos
POSIX, el mensaje lo dice y manda mudar la memoria con `--db`— y lo mismo en el aviso de
la política, que el ejemplo imprimía en **cada** comando (`12c8f07`, `1134530`). La
comprobación se hace con un fichero temporal propio, nunca tocándole el modo a la clave:
una clave que estuvo expuesta lo estuvo.

### H6 — El código 1 mezcla dos cosas que un ERP necesita distinguir

Pedir el recibo de un bloque que ningún testigo ha cubierto todavía devuelve **código 1**
con un mensaje impecable (*"la entrada aún no está cubierta por un checkpoint... Ejecuta
`nucleo sync`"*). El problema no es el mensaje: es que llega con el mismo código que un
argumento mal escrito, y lo que un ERP hace con cada uno es opuesto —reintentar tras
sincronizar, o arreglar el código—. Distinguirlos hoy exige mirar el texto, que es lo que
un contrato de cable no debería pedir.

Los códigos de salida no cambian (está en el contrato), y añadir un discriminador
legible por máquina era una decisión de formato, o sea del dev vía ADR. Mientras tanto el
ejemplo hacía lo correcto sin depender del texto: **sella, sincroniza y entonces emite el
recibo**, que es el orden bueno, y solo si aun así falla enseña el mensaje tal cual.

> **RESUELTO el 2026-09-24**, al día siguiente y por decisión del dev:
> [ADR-027](adr/ADR-027-clase-del-error-en-json.md) añade `error_class` al objeto de error
> —`usage`, `transient`, `environment`, `integrity`—, ortogonal al código de salida y con
> conjunto cerrado. El recibo de un bloque sin cubrir sale ahora con código 1 y clase
> `transient`, y los dos consumidores externos —PHP y el ejemplo— la leen. El ejemplo dejó
> de tener que explicar en su página de error que el código 1 significa dos cosas.

### H7 — La excepción del objeto de error es fácil de implementar mal

`reconcile` con hallazgos sale con código 2 y entrega **su informe completo** con
`ok: false`, sin `error` ni `exit_code`. Está dicho en las convenciones de
`docs/CLI-JSON.md`, pero un consumidor que implemente la regla general —"si el código no
es 0, lee el objeto de error"— falla con un `ErrorDeContrato` en el caso que más importa.
Le pasó a este envoltorio en su primera ejecución.

**No se ha tocado el producto**: la salida es la documentada y la buena —tirar el informe
para volver a pedirlo sería peor—. El envoltorio se arregló como debe hacerse: manda el
código del **proceso**, y el objeto de error se lee solo si está. Queda anotado porque el
segundo consumidor tropezó en el mismo sitio que tropezaría un tercero.

### Además, un tropiezo operativo que no es del contrato

Si la memoria del testigo se pierde, al arrancar se crea una **clave nueva** y la política
del ERP deja de reconocerlo: *"lo que contestó no es una cosignature válida de ese
testigo... esto NO se arregla reintentando"*. Mensaje correcto y desconcertante si no
sabes que cambiaste de testigo. El ejemplo lo avisa al levantarlo, comparando su clave con
la de la política.

---

## 3. La medición cronometrada

El criterio de éxito (CONCEPTO §18) pide que *un desarrollador cualquiera, sin saber
criptografía, integre Núcleo en menos de una hora siguiendo la documentación*. Nadie lo
había medido. Esto es lo que se puede medir y lo que no.

**Lo que se midió**: el camino mecánico desde un clon limpio hasta un recibo verificado,
en un portátil, sobre el sistema de ficheros de Linux.

| Paso | Tiempo |
|---|---|
| `git clone` del repositorio | 8,1 s |
| `go build -o nucleo ./cmd/nucleo` | 1,3 s con caché caliente · **21,6 s en frío** |
| `npm run setup` (construye el verificador, crea el vault y el ledger, primera atestación y política) | 3,3 s |
| `npm run demo` (sella 3, reintenta, sincroniza, recibo, verificación, cotejo, alteración, fallos) | **1,8 s** |
| **Total de máquina, de clon a recibo verificado** | **≈ 15 s en caliente, ≈ 35 s en frío** |

Y dentro de la demo:

- **sellar una factura: 88, 94 y 97 ms** (incluye arrancar el proceso, abrir el ledger con
  atestación, firmar y escribir con `synchronous=FULL`).
- el recorrido completo de siete pasos: **1,6 s de reloj**.
- el recibo emitido por el ejemplo, verificado con **el mismo bundle que sirve
  `web/verify/`** —los bytes que correría un teléfono—: `valid: true`, tiempo demostrable
  presente, las dos firmas verificadas, un cosignatario, **13 ms**.

Sobre `/mnt/c` (WSL, el sistema de ficheros de Windows visto desde Linux) los mismos
sellados tardan **508–623 ms**, cinco veces más. No es una sorpresa y conviene saberlo:
`synchronous=FULL` paga cada `fsync`, y ahí cuestan.

**Lo que no se puede medir así, y hay que decirlo**: el tiempo de *comprensión* de un
desarrollador que no conoce Núcleo. Quien escribió el ejemplo no puede cronometrarse
leyéndolo: sabe dónde mirar. Lo que estas cifras demuestran es que **el camino mecánico no
gasta la hora** —gasta medio minuto—, y que la hora queda entera para lo único que de
verdad cuesta: entender qué prueba un recibo y qué no. La medición con un sujeto que no
haya visto el proyecto sigue pendiente, y es la que cierra §18.

---

## 4. Lo que el ejemplo demuestra, paso a paso

1. **Sellar al emitir**, con `nonce` de 16 bytes en el documento (ADR-023 §C) y la clave de
   idempotencia = número de factura (ADR-020 §D). El reintento con la misma clave contesta
   `idempotent: true` y el ledger no crece: comprobado en la demo.
2. **El cron** del ensayo de operación, con `--passphrase-file` porque `sync` firma, stderr
   al correo porque ahí van las alarmas, y el código de salida propagado tal cual.
3. **El recibo del cliente**, con el orden que impone el formato: sellar → sincronizar →
   emitir.
4. **Verificar un recibo pegado** con `@nucleoledger/verify`, en el mismo proceso y sin
   red. Con un carácter cambiado: `valid: false` y las tres razones que fallan.
5. **Reconciliar y ver la alteración**: el criterio de éxito dentro de una aplicación. El
   recibo entregado antes de la alteración sigue verificando, porque no depende del ERP.
6. **Los fallos**: binario que falta, timeout a medio sellar, testigo caído, cotejo con
   hallazgos y salida que no cumple el contrato. Cada uno con su respuesta, y las tres
   preguntas contestadas: qué pasó, qué hizo el ERP con mi factura, qué hacer.

---

## 5. Lo que queda

- **Republicar `@nucleoledger/verify`** con soporte de `receipt@v2` (H1). Es lo único que
  impide que el ejemplo dependa del paquete como lo haría cualquiera.
- ~~**Decidir sobre H6**~~: decidido y hecho el 2026-09-24, ADR-027.
- **La medición de §18 con un sujeto real**, que es la mitad que no se puede fabricar
  desde dentro.
