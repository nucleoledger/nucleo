# ADR-021-sdk-php

**Estado:** ACEPTADA el 2026-09-17 por el dev (Sprint 8) · **Fecha:** 2026-09-17 · **Fuentes:** [revisión externa, por un modelo, del 2026-09-13](../revision-externa-modelo-20260913.md) §7 «Riesgos de diseño y operación», primer punto: «integración transaccional con el ERP y tratamiento de eventos nunca enviados». **Enmendado el 2026-09-22:** esta línea citaba «H9, "cómo sella un ERP PHP en la misma transacción"», y ni el número ni la frase son del informe —H9 es la independencia de los golden y esa frase no aparece—. Se pudo comprobar en cuanto el informe entró en el repositorio, que es justamente para lo que sirve tenerlo; ADR-005 (CLI primaria), ADR-009 (esquema), ADR-017 y ADR-018 (la política como raíz de confianza y como formato de cable), ADR-020 (idempotencia), PROTOCOL.md §2.1, §3.1, §3.2, §3.3 y §5

## El problema, tal como llega

El mercado de este producto es PHP sobre cPanel. Hoy hay una CLI en Go y un verificador
en TypeScript, y un ERP en PHP no tiene forma de sellar sin salir de su proceso. La
pregunta del sprint es la forma antes que el código: **¿envoltorio del binario Go, o
implementación nativa?**

La respuesta no puede ser la misma para las dos mitades del problema, porque las dos
mitades no se parecen en nada:

| | sellar | verificar |
|---|---|---|
| ¿tiene secretos? | sí: la clave de firma vive en el vault | no |
| ¿escribe? | sí, y para siempre | no |
| ¿quién lo ejecuta? | el emisor, en su servidor | la CONTRAPARTE, en cualquier sitio |
| ¿qué pasa si dos implementaciones divergen? | bloques que no verifican en ninguna parte | un veredicto distinto, que es el hallazgo |

## Decisión

### A. Sellar: ENVOLTORIO del binario Go. Una sola implementación que escribe

`Nucleo\Sealer` ejecuta el binario `nucleo` con `proc_open` y lee su `--json`. No
reimplementa nada.

Por qué no nativo, en orden de gravedad:

1. **El escritor sostiene invariantes que no están en el formato.** El encadenamiento
   contra el último bloque persistido, la transacción única de ADR-020, el cerrojo
   anti-retroceso de PROTOCOL §3, la atestación en la apertura de ADR-016. Una segunda
   implementación no tiene que equivocarse en criptografía para romper un ledger: basta
   que olvide uno de esos.
2. **Una divergencia al escribir es permanente.** Si el JCS de PHP difiere del de Go en
   un escape, el bloque se firma sobre otros bytes y no verifica en ningún verificador,
   incluido el propio. Y ya está en el ledger de un cliente, append-only.
3. **Sellar exige la passphrase.** Un sellador nativo necesitaría Argon2id, XChaCha20-
   Poly1305 y SLIP-0039 dentro del proceso web, que es el proceso más expuesto del
   despliegue. El envoltorio deja la clave donde ya está: en el vault, detrás del
   binario, con la passphrase en un fichero que solo lee el usuario del sistema.

Lo que el envoltorio SÍ aporta, y no es poco: la idempotencia de ADR-020 puesta donde el
ERP la necesita (`idempotencyKey` es un parámetro, no una bandera que haya que recordar),
los códigos de salida traducidos a excepciones tipadas, y un error explícito —nunca un
degradado silencioso— cuando el entorno no puede ejecutar el binario.

### B. Verificar: NATIVO en PHP

`Nucleo\Verifier` implementa el recibo `receipt@v2` completo desde PROTOCOL.md, sin
llamar a nada.

Por qué no un envoltorio:

1. **Quien verifica es la contraparte.** Pedirle que ejecute el binario del emisor para
   comprobar el recibo del emisor es pedirle que confíe en lo que está comprobando. El
   verificador tiene que poder correr en el hosting de quien recibe la factura, sin
   binarios y sin red.
2. **Una tercera implementación desde la especificación vale más que una tercera copia
   del código.** Es el mismo argumento del oráculo Python del Sprint 7f:
   dos implementaciones que comparten linaje comparten errores. La tercera se escribe
   leyendo el protocolo, y el diferencial mide si coinciden.
3. No hay secretos ni escritura: el peor fallo posible es un veredicto equivocado, y eso
   es exactamente lo que el diferencial caza.

### C. Cómo llega el binario a un hosting compartido

Tres formas, y la tercera es un "no puede":

1. **Binario en la cuenta.** `~/bin/nucleo` subido por FTP o por el gestor de ficheros,
   `chmod 0700`. Go produce un ejecutable estático sin dependencias, así que no hace
   falta compilar nada en el servidor. Es lo normal en cPanel con SSH o con el
   Terminal del panel.
2. **El ERP no está en compartido.** Un VPS o un contenedor donde `exec` es normal. Es
   el caso al que el envoltorio no le tiene que hacer nada especial.
3. **`exec` deshabilitado o `/home` montado `noexec`.** Pasa, y es decisión del
   proveedor. El sellador lo **detecta y lo dice**: qué función falta (`proc_open` en
   `disable_functions`), o que el fichero existe y no se puede ejecutar. No hay
   degradado: un sellador que "sigue adelante" sin sellar es lo peor que este producto
   puede hacer.

Y un límite dicho donde vive: en el caso 3 la salida NO es un sellador nativo, es sellar
en otra máquina. Queda anotado en "lo que queda abierto".

La passphrase va en un fichero que el envoltorio exige en modo 0600 y pasa con
`--passphrase-file`. Nunca por argumento: la lista de procesos la ve toda la máquina.
Nunca por entorno: en muchos paneles el entorno del proceso PHP es legible.

### D. El subconjunto, dicho por entero

| | en PHP | por qué |
|---|---|---|
| verificar `receipt@v2` (los seis pasos de §3.1) | **sí** | es el caso de la contraparte |
| política estricta (§3.2) | **sí** | ADR-018: es un formato de cable, mismo trato en los tres |
| bloque de firmas de la nota y conteo de cosignatures (§3.3) | **sí** | idem |
| canonicidad JCS del header | **sí** | los bytes exactos son lo firmado |
| inclusión Merkle con leaf/v2 (§2.1) | **sí** | es la prueba |
| sellar | **envoltorio** | decisión A |
| abrir un ledger, vault, SLIP-0039, sync, testigo | **no** | son del emisor, y el emisor tiene la CLI |
| firma ML-DSA-44 del log | **no** | no hay ML-DSA en PHP; se IGNORA como firma de clave desconocida, igual que en TypeScript |

Sin composer y sin dependencias: `require` de un `autoload.php` de nueve líneas.
Extensiones exigidas: **ext-sodium** (Ed25519) y **ext-json**. Las dos vienen con PHP
desde 7.2, pero un proveedor puede desactivarlas, así que el paquete lo comprueba al
cargarse y lo dice con el nombre de la extensión.

### E. Límite de los enteros, explícito

Los enteros de PHP son de 64 bits con signo. Donde TypeScript usa `BigInt` porque se le
rompen a 2^53, PHP llega a 2^63 y **rechaza** lo que no quepa en vez de convertirlo a
coma flotante en silencio: un tamaño de árbol o un índice por encima de `PHP_INT_MAX` da
un recibo inválido con su razón. Es un límite de 9,2·10^18 entradas dicho en voz alta,
no un redondeo escondido.

### F. Entra en el diferencial desde el primer día

El diferencial compara **dictámenes** entre implementaciones (Sprint 7f, F.7). PHP entra
con las mismas reglas:

- un proceso, no uno por caso: `bin/dictamen.php` lee JSONL por la entrada estándar y
  escribe un dictamen por línea. Trece mil procesos serían veinte minutos de compuerta;
  así son segundos.
- divergencia de **dictamen** entre dos verificadores que aceptan: fatal.
- **motivo** de rechazo: no se compara, igual que entre Go y TypeScript. Go se para
  donde deriva el texto y TS donde lee el magic; PHP tendrá sus propios sitios. Se
  cuentan y se imprimen.
- si `php` no está en la máquina, el diferencial lo dice en voz alta y sigue con dos de
  tres. Lo que no hace es callarse: una compuerta que no distingue "coinciden" de "no se
  comprobó" no es una compuerta.

## Consecuencias

- El producto pasa a tener tres verificadores independientes (Go, TypeScript, PHP) y
  **un** sellador. Es la asimetría correcta: verificar es donde la independencia paga, y
  escribir es donde cuesta.
- El ERP en PHP puede sellar en la misma petición en la que emite la factura, con clave
  de idempotencia, y distinguir "no pude sellar" de "ya estaba sellado".
- La compuerta gana un verificador y un modo de fallo nuevo: PHP ausente. Se dice.
- El texto legible del recibo **no está en PROTOCOL.md**: la plantilla vive en el código
  de Go y en el de TypeScript. Esta tercera implementación la ha tomado de los vectores
  compartidos, que es la fuente correcta para un tercero, y de paso deja demostrado que
  se puede. Que la plantilla debería estar en el protocolo queda anotado abajo.

## Alternativas descartadas

- **Sellador nativo en PHP.** Ver decisión A. Se descarta por lo que costaría cuando
  falle, no por lo que cuesta escribirlo.
- **Un daemon local y PHP hablando HTTP con él.** Resuelve el `exec` deshabilitado y
  trae un servicio que hay que arrancar, vigilar, autenticar y actualizar. `nucleod` no
  existe y no está planificado para la v1 (ADR-005); meterlo por la puerta de atrás del
  SDK de PHP sería una decisión de arquitectura disfrazada de comodidad.
- **Extensión PHP en C envolviendo el código Go.** Imposible de instalar en el hosting
  compartido que es justamente el mercado.
- **Verificador PHP como envoltorio del binario.** Le quita el único valor que tiene: la
  contraparte verificaría con el programa del emisor.
- **Composer y una dependencia de criptografía.** `ext-sodium` ya viene con PHP y hace
  falta exactamente una primitiva. Una dependencia con árbol de dependencias en un
  paquete cuyo trabajo es NO tener que confiar en nadie es un mal cambio.

## Lo que queda abierto

- **`exec` deshabilitado no tiene salida dentro de este SDK.** La respuesta real es
  sellar en otra máquina, y eso es diseño de producto, no una función que falte.
- **La plantilla del texto legible no está en PROTOCOL.md.** Tres implementaciones la
  reproducen byte a byte y ninguna la tiene escrita como norma. Es un candidato a §3.1.
- **El vector ML-DSA-44 sigue sin tercer verificador** (ver 8.5): ni Python ni PHP pueden
  producir ni comprobar esa firma.
