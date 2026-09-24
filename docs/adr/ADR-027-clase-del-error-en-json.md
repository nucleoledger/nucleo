# ADR-027-clase-del-error-en-json

**Estado:** ACEPTADA el 2026-09-23 por el dev (Sprint 12, a partir del hallazgo H6 del Sprint 11) · **Fecha:** 2026-09-23 · **Fuentes:** [informe del ejemplo de integración](../ejemplo-de-integracion-20260923.md) §H6 y §H7, ADR-025 (la salida `--json` como formato de cable) y su §D, ADR-020 §E (ningún error del motor llega al usuario), ADR-022 (una comparación que no se puede hacer no es un veredicto), `docs/CLI-JSON.md`

> El número. La lista de trabajo del dev pedía esto como «ADR-026»; ese número ya lo
> ocupa el ejemplo de integración, aceptado el mismo día. Va como ADR-027.

## El problema

Escribir un segundo consumidor del contrato `--json` —el envoltorio en Node del ejemplo de
integración, hecho desde `docs/CLI-JSON.md`— dejó a la vista algo que el primero no había
tropezado: **el código de salida no dice qué hacer.**

La secuencia exacta, del informe del Sprint 11:

```
POST /factura/000001/recibo
  → nucleo receipt --block 0 ...
  → código 1: "receipt: la entrada aún no está cubierta por un checkpoint:
               bloque 0, el checkpoint cubre 0
               Ejecuta `nucleo sync` para que un testigo cubra ese bloque."
```

El mensaje es impecable para una persona. Para un programa es indistinguible de
`--tenant` mal escrito: los dos son código `1`. Y lo que hay que hacer con cada uno es
opuesto —sincronizar y reintentar, o corregir el código y desplegar de nuevo—, así que el
ejemplo tenía dos salidas: adivinar leyendo el texto del mensaje, o tratar los dos casos
igual. Leer el texto es exactamente lo que un formato de cable no debe pedir: el texto es
para personas, está en español, y se reescribe cada vez que alguien lo mejora —este
proyecto lo ha hecho en cuatro sprints seguidos—.

Los cuatro códigos de salida son correctos y no se tocan. Lo que falta es una dimensión
más: el código dice **en qué salió mal**, y hace falta decir **qué clase de problema es**.

Hay además un precedente que empuja en el mismo sentido. ADR-025 §D dejó anotado que no se
añadía un campo de versión al JSON, y lo dejó anotado *«como paso posible el día que haya
más de un consumidor externo»*. Ese día llegó: hay dos —el SDK de PHP y el ejemplo en
Node—, escritos por separado, y los dos tropezaron en este mismo sitio.

## Decisión

### A. El objeto de error lleva `error_class`, con un conjunto CERRADO de cuatro valores

```json
{"ok": false, "error": "...", "exit_code": 1, "error_class": "transient"}
```

| valor | qué afirma | qué hace un programa con él |
|---|---|---|
| `usage` | lo que se pidió no se puede pedir así: una bandera mal, una política inválida, una passphrase que no es la de este vault | **no reintentar**. Cambiar la llamada o la entrada |
| `transient` | una condición que se resuelve sola o con un reintento: el testigo no contesta, otro proceso tiene el ledger tomado, el bloque no está cubierto todavía | **reintentar luego**, con la misma clave de idempotencia si había escritura de por medio (ADR-020 §D) |
| `environment` | el despliegue está roto y lo tiene que arreglar una persona: permisos, disco lleno, un fichero que falta, un testigo cuya clave no es la de la política | **no reintentar**: avisar a quien opera. El reintento da exactamente lo mismo |
| `integrity` | la verificación falló: alteración, discrepancia, retroceso | **incidente**. No reintentar, no borrar, preservar y mirar |

Cuatro y no más. La tentación de una taxonomía fina —un `reason` con treinta slugs— se
rechaza abajo, en §E.

### B. La clase es ORTOGONAL al código de salida, y ahí está su valor

Los códigos siguen siendo los de siempre (`1` uso, `2` verificación, `3`
sincronización), y la clase no los sustituye ni los deduce:

| código | clases posibles |
|---|---|
| `1` | `usage`, `transient` (el bloque sin cubrir), `environment` |
| `2` | `integrity`, y solo esa |
| `3` | `transient` (no se llega al testigo), `environment` (se llega y su clave no es la de la política: eso no se arregla reintentando) |

Un `3` que es `transient` y un `3` que es `environment` piden cosas distintas del cron que
los recibe. Eso es lo que no se podía distinguir sin leer el texto.

### C. El consumidor lo lee como OPCIONAL, y el código de salida es el respaldo

Los binarios anteriores a este ADR no traen el campo, así que exigirlo rompería contra un
despliegue que todavía no se ha actualizado —y la regla de compatibilidad de ADR-025 §A
dice que los campos se pueden añadir, no que aparezcan retroactivamente—. Un consumidor
estricto, entonces:

- si `error_class` **está**, tiene que ser una de las cuatro cadenas. Un valor desconocido
  es un error de contrato, igual que un `attestation` desconocido: un valor que no se
  entiende no se interpreta a la baja;
- si **no está**, se deduce del código: `1 → usage`, `2 → integrity`, `3 → transient`. Es
  exactamente el comportamiento de hoy, así que nada empeora y lo que se gana es nuevo.

### D. Quien la produce es el sitio que sabe, y hay un único lugar que la decide

La clase no se escribe en cada uno de los noventa sitios que construyen un error: se
decide en `claseDelError`, en `cmd/nucleo/main.go`, con tres reglas en este orden:

1. si el error trae una clase EXPLÍCITA —la puso el subcomando porque es el único que
   sabe, como el recibo de un bloque sin cubrir—, esa manda;
2. si no, se mira la cadena de errores con `errors.Is` contra los centinelas que ya
   existen: `store.ErrBusy` es `transient`; `store.ErrReadOnly`, `ErrDiskFull` y `ErrIO`
   son `environment`; `store.ErrNotALedger` y los desajustes de cadena de `internal/ledger`
   son `integrity`; `vault.ErrUnwrap` es `usage`;
3. y si tampoco, por el código de salida.

Un único lugar que clasifica es la diferencia entre un contrato y una costumbre. Y usar
los centinelas que ya existen —los que el Sprint 10 creó para que el mensaje dijera qué
comprobar— evita una segunda descripción del mismo hecho.

### E. Lo que NO se hace

- **No se añade un `reason` con slugs finos** (`witness_unreachable`, `block_not_covered`,
  `disk_full`…). Sería una tercera descripción del mismo error —ya están el código y el
  mensaje— y cada slug nuevo es un compromiso de compatibilidad para siempre. Las cuatro
  clases cubren la decisión que un programa toma de verdad: reintentar, no reintentar,
  llamar a una persona o abrir un incidente. Si algún día un consumidor demuestra con un
  caso real que necesita más grano, se añade entonces; añadir un campo es compatible,
  quitarlo no.
- **No se cambia ningún código de salida**, ni se añade un quinto. Están en el contrato
  desde la v0.1 y los usa gente en crons.
- **No aparece en la salida para personas.** La clase es para programas; a una persona se
  le dice qué hacer en su idioma, que es lo que ya hace el mensaje. Meter `[transient]` en
  la salida humana sería jerga del motor llegando al usuario, justo lo que prohíbe
  ADR-020 §E.
- **No se clasifica el aviso de frescura ni el de rollback.** No son errores: van por
  stderr y tienen su propio sitio en el JSON (`freshness`, `rollback`). Un aviso que
  además fuera un error sería dos cosas a la vez.

## Consecuencias

- Los dos consumidores externos —`sdk/php` y `examples/erp-node`— leen la clase y dejan de
  depender del texto. El ejemplo, además, deja de tener que explicar en su página de error
  que el código 1 significa dos cosas.
- Los vectores de `testdata/vectors/cli-json/` cambian: el válido de error gana un campo.
  Se regeneran con la CLI de verdad, como manda ADR-025 §C, y se añade un inválido con una
  clase desconocida para fijar que el consumidor la rechaza.
- `docs/CLI-JSON.md` gana una fila normativa en las convenciones y la tabla de valores.
- Coste asumido: cada error nuevo de la CLI tiene que elegir su clase, o heredar la del
  código. El riesgo real no es equivocarse en un caso —es que la clase se vuelva
  decorativa por no mantenerla—, y contra eso están los tests que afirman la clase de las
  seis situaciones que el ensayo de operación y el ejemplo encontraron.
