# ADR-017-politica-raiz-de-confianza

**Estado:** ACEPTADA el 2026-09-12 por el dev · implementada en el Sprint 7d · **Fecha:** 2026-09-12 · **Fuentes:** segunda auditoría adversarial 2026-09-12 (hallazgos ALTO ×2), ADR-016, ADR-015, PROTOCOL.md §1, `ledger.VerifyChain`, `internal/store/integrity.go`, `internal/proof`

## Los hallazgos

La segunda auditoría adversarial ejecutó dos cosas contra el código de ADR-016:

**Uno.** Reescribió los bloques 1-4 firmándolos con **su propia clave**, con
`signer_pubkey` apuntando a ella —firmas autoconsistentes— y borró los
checkpoints. `Open` aceptó ("SIN ATESTIGUAR, cadena localmente válida") y
**`verify --full` aceptó** ("verificación EXHAUSTIVA superada"). PROTOCOL §1 dice
que *"full-chain verification MUST enforce an expected signer key"*; nadie lo
hacía. `VerifyLink` comprueba índice, `prev_hash` y timestamps, no el firmante;
`store.walk` nunca compara `signer_pubkey` entre bloques; y `ledger.VerifyChain`,
el único que sí exige un firmante, no se usaba en ningún sitio de producción. El
límite del README —*"`verify --full` catches it"*— quedó falsificado: caza firmas
basura, no firmas válidas bajo una clave sustituida.

**Dos.** Un recibo de ese bloque ajeno, bajo el checkpoint del log real y cosignado
por el testigo real, **verificó en Go, TypeScript y la página** con
`firma del bloque ✔ verificada contra signer_pubkey` y `(firmado por el emisor)`.
La política fija la clave del log y las de los testigos; **nunca la del que firma
los bloques.** "Firmado por el emisor" significaba "firmado por quien sea cuya
clave esté en el header".

Los dos hallazgos son el mismo: **la clave del firmante de bloques no estaba
fijada en ningún punto del sistema.** Ni en la cadena (continuidad), ni en la
política (identidad).

## Decisión

**La política es la única raíz de confianza, y contiene todo lo que un verificador
necesita traer de fuera.** Tres decisiones:

### (a) La política gana la clave esperada del firmante de bloques

```
signerKey  — clave pública Ed25519 del tenant que firma los bloques
```

- En la **política de un recibo** es **obligatoria**. Un recibo verificado bajo una
  política sin `signerKey` no puede afirmar autoría: "firmado por el emisor" con la
  clave sacada del propio recibo es una afirmación del recibo sobre sí mismo. El
  verificador la exige, y `signer_pubkey` del header tiene que coincidir.
- En la **política con la que se abre el ledger** es **opcional**, y la apertura
  distingue honestamente: `firmante: verificado` con ella, `firmante: NO
  verificado contra ninguna política` sin ella. Lo que NO es opcional es la
  continuidad (ver §Capas).
- Si la política de apertura trae `logKey`, tiene que coincidir con la clave que
  `vault_meta` declara; una discrepancia es error de integridad. Es la capa de
  detección de la sustitución de clave que ADR-016 dejó descrita y sin código.

### (b) Fichero de política: `--policy-file`

Ya son cinco cosas que teclear —origin, clave del log, clave del firmante,
testigo y su clave— y una política que se teclea es una política que se
transcribe mal o se omite. Un solo formato, JSON, **el mismo que ya consume el
SDK de TypeScript y la página web**, así que la contraparte y el operador usan el
mismo fichero:

```json
{
  "origin":    "nucleoledger.com/mi-empresa",
  "logKey":    "9ad2…f004",
  "signerKey": "57857f…4f2a",
  "witnesses": { "witness.nucleoledger.com/w1": "dd7e…7263" },
  "quorum":    1
}
```

`--policy-file` en `status`, `verify`, `seal`, `reconcile`, `sync` y `receipt`.
Las banderas sueltas (`--witness-name`, `--witness-key`, y la nueva
`--signer-key`) siguen existiendo; fichero **y** banderas a la vez es error de uso,
no una fusión: dos fuentes de verdad se contradicen en silencio.

### (c) `sync` imprime el snippet exacto para el cron

Al terminar con atestación verificada, `sync` escribe el contenido del fichero de
política —origin y claves del propio ledger, más el testigo que acaba de usar— y
las dos formas de invocarlo. Quien acaba de sincronizar tiene en pantalla lo que
tiene que pegar en el cron, y la política deja de ser algo que hay que saber
construir.

## Por qué la clave del firmante NO puede venir de `vault_meta`

El mismo argumento de ADR-016, y con más fuerza. `vault_meta` vive en el fichero
que el adversario escribe. Verificar el firmante contra una clave que está en
`vault_meta` sube el listón exactamente en una sentencia `UPDATE`: el atacante que
reescribe la cadena con su clave escribe su clave también en `vault_meta`, y la
"verificación" pasa.

`vault_meta` sirve para lo que sirve: es donde `init` deja la identidad pública
para que `status` la publique y para que un cotejo contra la política **detecte
la sustitución**. Es una fuente de comparación, no una raíz de confianza. La raíz
de confianza es lo que viene de fuera: la política.

## Capas, y qué detecta cada una

| capa | qué exige | detecta | ¿cuándo actúa? |
|---|---|---|---|
| **Continuidad** | `signer_pubkey` idéntico en toda la cadena al del bloque 0 | re-firmado **parcial**: un bloque, o desde uno en adelante, con otra clave | **siempre**, sin política, en `Open` y en `verify --full` |
| **Identidad** | `signer_pubkey` == `policy.signerKey`; `logKey` de la política == `vault_meta` | reescritura **total** autoconsistente con otra clave; sustitución de la clave del log | con política |
| **Memoria externa** | el testigo recuerda tamaño y raíz; las contrapartes guardan recibos | reescritura total **con** la clave legítima (emisor deshonesto, o clave robada) | en el siguiente `sync` (422: misma altura, otra raíz) y cuando alguien presenta un recibo viejo |

La continuidad es la novedad barata y sin coste de configuración: no exige que
nadie traiga nada, y cierra el exploit tal cual se ejecutó. La identidad es lo que
cierra la variante total, y no puede ser gratis: exige traer una clave. La tercera
capa no la implementa este ADR; la implementan un testigo que el emisor no
controla y los recibos en manos ajenas, que es el producto pendiente.

No hay rotación de la clave del firmante. Cuando la haya, será un bloque de
rotación firmado por la clave saliente (ADR pendiente), y la continuidad se
definirá a través de él. Hasta entonces, un cambio de `signer_pubkey` dentro de
una cadena solo tiene una lectura.

## Lo que cambia para quien usa esto

- Toda política de recibo —fichero de la contraparte, JSON pegado en la página,
  vectores golden— gana `signerKey`. Los recibos no cambian de bytes; cambian las
  políticas. Cambio de ruptura pre-1.0 en la política, no en el formato.
- `status` gana la línea `firmante : ✔ verificado` / `◐ NO verificado contra
  ninguna política`, y `--json` el objeto `signer`.
- `verify --full` deja de aceptar una cadena re-firmada por otra clave, aunque no
  se aporte política. Eso ya no es una opción.

## Tests de regresión

Los dos exploits de la auditoría, tal cual se ejecutaron:
- re-firmado parcial (bloques 1-4 con clave ajena) → rechazo **siempre**;
- reescritura total autoconsistente → rechazo con política; sin política, el
  estado dice `firmante: NO verificado`;
- el recibo del bloque ajeno → rechazo en Go, TypeScript y bundle bajo una política
  con `signerKey`.
