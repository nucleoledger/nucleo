# ADR-030-testigo-de-varios-logs

**Estado:** ACEPTADA el 2026-10-10 por el dev (Sprint 15) · **Fecha:** 2026-10-10 · **Fuentes:** ADR-011 (el testigo HTTP, `c2sp.org/tlog-witness`), ADR-018 (formato estricto de la política), ADR-029 y su enmienda §F (retirar un log cuya clave se robó), CONCEPTO §1 y §7 (el autor no opera infraestructura), `docs/OPERACION.md` §1

## El problema

`nucleo witness serve` atiende **un** log: `--log-origin` y `--log-key`. Sirve para probar y
para un despliegue de una empresa con un testigo prestado, pero no para quien de verdad va a
operar un testigo para otros, que es lo que el producto necesita para que el tiempo
demostrable exista (PLAN.md, «producto-testigo»):

- un **estudio contable** que atestigua los ledgers de decenas de clientes;
- un **fabricante de ERP** que ofrece testigo a todas sus instalaciones;
- **dos empresas que se atestiguan entre sí** (testigo mutuo), cada una con su log y el
  del otro.

Con un proceso por log, eso son decenas de unidades de systemd, decenas de puertos y
decenas de memorias que respaldar. Y falta algo que la enmienda de ADR-029 pide: **retirar**
un log —el de una passphrase robada— para que el testigo deje de cosignarlo sin olvidar lo
que ya cosignó.

El núcleo ya lo permite: `internal/witness` guarda un verificador por origin y la memoria
—`witness_logs`— está indexada por origin. Lo que falta es cómo se le dice al proceso qué
logs sirve, y qué significa retirar uno.

## Decisión

### A. Un fichero de configuración, con la gramática estricta de la política

```
nucleo witness serve --config testigo.json --db testigo.db --addr 127.0.0.1:8099
```

```json
{
  "name": "testigo.ejemplo.ec/w1",
  "logs": {
    "ejemplo.ec/cliente-a": "<clave pública Ed25519 del log, 64 hex en minúsculas>",
    "ejemplo.ec/cliente-b": "<…>"
  },
  "retired": {
    "ejemplo.ec/cliente-c": "<…>"
  }
}
```

- `name`: el nombre del testigo, el que va en sus cosignatures. Obligatorio.
- `logs`: los logs que **cosigna**, origin → clave. Obligatorio, con al menos uno.
- `retired`: los logs **retirados**, origin → clave. Opcional.

El formato es tan estricto como la política (ADR-018), y por la misma razón: quien escribe
este fichero decide qué cosigna el testigo, y un fichero que se lee de dos maneras es un
testigo que avala lo que su operador no pidió. Así que se lee con **el mismo lector**:
miembros repetidos, variantes de mayúsculas de un miembro conocido, miembros desconocidos,
comentarios, comas finales, BOM, arrays, booleanos, `null`, todo es error. Las claves, en
hexadecimal en minúsculas de 64 caracteres; un origin no puede estar a la vez en `logs` y en
`retired`. Tamaño máximo: 1 MiB, que son miles de logs.

Ese lector deja de vivir dentro de `internal/policy` y pasa a `internal/estricto`, con los
**mismos mensajes** para la política: un cambio de mensaje en un formato de cable también es
un cambio, y se comprueba contra todos los vectores de `testdata/vectors/policy/`.

### B. Compatibilidad: `--log-origin` y `--log-key` siguen igual

`witness serve --name N --log-origin O --log-key K` hace exactamente lo de antes. `--config`
y esas banderas no se combinan —dos fuentes de configuración se contradicen en silencio—, y
mezclarlas es un error de uso.

### C. Retirar un log: deja de cosignarse, y su memoria se queda

Un log en `retired`:

- **no se cosigna**: un `add-checkpoint` de ese origin recibe **404**, que es lo que
  `c2sp.org/tlog-witness` prevé para un origin que el testigo no sirve, con el cuerpo
  `log retirado` en vez de `origin desconocido`. La CLI de Núcleo reconoce ese cuerpo y lo
  dice sin rodeos —*«el testigo … dejó de cosignar este log: lo retiró quien lo opera»*— en
  vez del consejo genérico de un 404 («comprueba la URL»). Para cualquier otro cliente sigue
  siendo un 404 del protocolo.
- **se sigue publicando** en la ruta de monitorización (`GET …/checkpoint`): el último
  checkpoint que cosignó es exactamente el «hasta aquí es tuyo» que la enmienda de ADR-029
  pide publicar al retirar un log robado.
- **conserva su memoria** en la base: retirar no borra nada, y volver a activarlo —moverlo de
  `retired` a `logs`— continúa desde lo que el testigo recordaba, nunca desde cero.

**Altas y bajas** son editar el fichero y reiniciar el proceso. La memoria vive en la base, no
en el proceso: un reinicio no pierde nada (ADR-011, persistencia transaccional). No hay
recarga en caliente; un `systemctl restart` tarda lo que tarda en abrir SQLite, y un proceso
que cambia de configuración a medias es un estado más que probar.

Al arrancar, el testigo **dice** qué memoria tiene de origins que la configuración ya no
menciona —ni en `logs` ni en `retired`—: no la usa ni la borra, pero quien lo opera tiene
que saber que está ahí. Un origin que se quitó del fichero y se vuelve a poner, aunque sea
con **otra clave**, se encuentra su memoria: no puede volver a empezar desde un tamaño menor,
porque eso es exactamente un rollback.

### D. Dos logs no se pisan nunca la memoria

Cada origin tiene su fila en `witness_logs` y su verificador; la clave de un log no
verifica checkpoints de otro origin, y una nota firmada por la clave de un log con el origin
de otro se rechaza (ya lo hacía `cosign`: el origin declarado solo **elige** la clave, y la
nota tiene que estar firmada por ella). Un test lo fija: varios logs que avanzan intercalados,
uno que intenta usar el origin de otro, y uno cuyo origin es prefijo del de otro.

## Lo que NO se hace

- **Autenticación de los logs ante el testigo.** Cualquiera puede *enviar* un checkpoint; el
  testigo solo cosigna los de los origins configurados y firmados por su clave. Es el modelo
  de `tlog-witness`.
- **Un panel o una API para dar de alta logs.** El fichero es la API: se versiona, se respalda,
  se revisa en un diff.
- **Operarlo.** Este ADR da el software y el kit (`deploy/witness/`); el autor del proyecto no
  opera testigos para nadie (CONCEPTO §1 y §7).

## Consecuencias

- Un testigo para N clientes es **un** proceso, **una** base y **un** fichero que respaldar.
- La enmienda de ADR-029 tiene su herramienta: retirar el log robado sin perder su memoria y
  publicando hasta dónde llegó.
- La política del lado del cliente no cambia: sigue nombrando el testigo por su `name` y su
  clave; que ese testigo atienda a otros logs no le afecta.
