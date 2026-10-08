<!--
Este preámbulo lo añade el repositorio; el informe empieza donde lo dice y no se ha
tocado una coma. Si alguna vez hay que separar las dos cosas, el corte es la línea
"FIN DEL PREÁMBULO".
-->

# Nota de procedencia

**Recuperado el 2026-10-07 de la sesión de OpenCode donde se produjo.** El fichero que
escribió el modelo vivía en un clon en `/tmp/opencode/nucleo-v030-alpha-review/`, y ese
directorio ya estaba vacío. Se recuperó de la base de la sesión (`opencode.db`, leída de
una copia): el texto es el del parche con el que el modelo **creó** el fichero
(`apply_patch`, *Add File*), y coincide línea a línea —las 240— con la lectura que el
propio modelo hizo del fichero un minuto después. No hay ninguna otra escritura sobre él
en la sesión.

| | |
|---|---|
| **Modelo** | `gpt-5.5` (OpenAI), vía OpenCode 1.15.12 |
| **Sesión** | «Auditoría adversarial de criptografía», `ses_f871559b1ffeqreA4WwQzx7F8F` |
| **Encargo** | 2026-10-03 20:21 UTC: revisar solo el código nuevo de v0.3.0-alpha que toca las claves (ADR-029), sobre un clon en el tag |
| **Instante del informe** | 2026-10-03 20:32 UTC (`prt_10377b62e001Gbm8Wvcemr4fTc`) |
| **Commit revisado** | `b417cb4`, el del tag `v0.3.0-alpha` |
| **Método** | ejecutó `go test ./... -race` y `go test -tags testhooks ./... -race` (los dos pasan) y evaluó por lectura |
| **Longitud** | 13.232 caracteres, 240 líneas, tal como se recuperaron |

FIN DEL PREÁMBULO

---

# Revisión externa técnica — ADR-029 / restore con passphrase nueva

Proyecto revisado: `github.com/nucleoledger/nucleo`.

Release: `v0.3.0-alpha`.

Commit del tag revisado: `b417cb4`.

Fecha de revisión: 2026-10-03.

Alcance pedido: solo código nuevo o relevante para claves en v0.3.0-alpha: ADR-029, `internal/vault`, `store.ReplaceMeta`, `internal/store`, `cmd/nucleo restore`, y documentación operativa relacionada.

## Pruebas ejecutadas

```text
go test ./... -race
```

Resultado: pasa.

```text
go test -tags testhooks ./... -race
```

Resultado: pasa.

La suite con `testhooks` incluye los tests específicos de muerte/interrupción de `restore` y `ReplaceMeta`.

## Resumen ejecutivo

No encontré un camino que deje el vault en un estado mixto irreversible, sin passphrase vieja ni nueva. La parte crítica de ADR-029 está bien diseñada: `vault/params/v1` y `vault/dek/v1` se reemplazan juntas en una transacción SQLite, con comparación contra los valores leídos antes de escribir.

Las tarjetas viejas dejan de abrir el vault actual después del commit porque respaldan la KEK anterior y la DEK queda reenvuelta bajo una KEK nueva. El código comprueba además que la nueva envoltura se puede desenvolver antes de escribir nada.

Los hallazgos son de borde operativo y manejo de secretos en memoria:

- **Media:** un `seal` que ya desbloqueó el vault antes del commit de `restore` puede terminar de sellar después del cambio usando material cargado con la passphrase vieja. No rompe atomicidad ni vuelve a hacer válida la passphrase vieja para nuevas aperturas, pero matiza la promesa operacional de “desde este momento la passphrase vieja no sirve”.
- **Baja:** `restore` deja copias de KEK/DEK/passphrase nueva en memoria más tiempo del necesario; algunas se pueden borrar explícitamente.
- **Baja documental:** `TUTORIAL-es.md` dice que las tarjetas viejas “no sirven” sin repetir el matiz de copias antiguas del ledger; `OPERACION.md` sí lo explica correctamente.

## Observaciones por severidad

### Media — Un `seal` ya desbloqueado puede completar después del cambio de passphrase

Archivos:

- `cmd/nucleo/seal.go:87-98`
- `cmd/nucleo/seal.go:140-154`
- `cmd/nucleo/env.go:181-215`
- `cmd/nucleo/backup.go:189-205`
- `internal/store/store.go:31-45`
- `internal/store/store.go:121-133`
- `internal/store/blobs.go:141-180`

`seal` abre el store, lee la passphrase, llama a `vault.Unlock`, carga la identidad y deja el vault abierto en memoria antes de construir y escribir el bloque. `restore` no bloquea el vault durante todo el flujo; solo toma una transacción al final en `ReplaceMeta`.

Orden posible entre dos procesos:

1. Proceso A ejecuta `seal` con la passphrase vieja.
2. A llega a `vault.Unlock` antes de que `restore` confirme el cambio; ya tiene la DEK y la identidad en memoria.
3. Proceso B ejecuta `restore --new-passphrase...` y confirma el cambio. `vault/params/v1` y `vault/dek/v1` quedan en estado nuevo.
4. A continúa y escribe un bloque después del commit de B.

Esto no deja el vault corrupto: la DEK no cambia en ADR-029, y SQLite serializa escrituras. Tampoco permite abrir de nuevo con la passphrase vieja: una nueva llamada a `vault.Unlock` leerá salt/DEK envuelta nuevos y fallará.

Pero sí significa que el cambio de passphrase no cancela operaciones ya desbloqueadas. Si la motivación del cambio era revocar de inmediato una passphrase filtrada, un proceso que ya la usó antes del commit puede seguir sellando hasta terminar.

Prueba automatizada faltante:

- Test con `testhooks` que pause `seal` justo después de `vault.Unlock` y antes de `AppendRecord`, ejecute `restore --new-passphrase-file`, deje continuar `seal`, y documente el comportamiento esperado: o se permite y se documenta, o se rechaza con una comprobación de generación/versión de vault antes de escribir.

Posible mitigación si se quiere semántica estricta:

- Guardar una versión de rekey o huella de `vault/params/v1` al desbloquear y revalidarla justo antes de escribir operaciones que usan el vault. Si cambió, abortar y pedir reintento con la passphrase nueva.

### Baja — Secretos de `restore` quedan en memoria más tiempo del necesario

Archivos:

- `cmd/nucleo/backup.go:105-128`
- `cmd/nucleo/backup.go:152-160`
- `cmd/nucleo/backup.go:201-205`
- `internal/vault/rekey.go:64-68`
- `internal/vault/rekey.go:76-83`
- `internal/vault/rekey.go:88-98`
- `internal/vault/rekey.go:134-138`
- `internal/vault/keys.go:300-305`

`PrepareRekey` maneja bien la DEK que desenvuelve internamente: `defer zero(dek)`. También borra `newKEK` con `Rekey.Close`, y `vault.Unlock` borra su KEK derivada con `defer zero(kek)`.

Pero en `cmdRestore` hay copias sensibles que no se borran explícitamente:

- `kek`, reconstruida por `vault.RestoreKEK(cards)` en `cmd/nucleo/backup.go:105`.
- La DEK devuelta por la comprobación preliminar `vault.UnwrapDEK(kek, wrapped, string(rawID))` en `cmd/nucleo/backup.go:125`; el valor se descarta, pero el slice queda en memoria hasta GC.
- `newPass`, leída desde terminal o fichero en `cmd/nucleo/backup.go:152`.

Esto no aparece en logs ni mensajes de error y no es una vulnerabilidad explotable por sí sola en un proceso CLI corto. Pero el propio código ya reconoce con `Vault.Close` que borrar slices reduce ventana aunque Go pueda copiar. En la ruta de cambio de passphrase, se puede hacer mejor con coste bajo.

Prueba automatizada faltante:

- No es fácil probar borrado de memoria de forma robusta en Go. Sí se puede añadir revisión por estructura: helper interno para `unwrapCheck` que borre la DEK antes de devolver, y `defer zero(kek)` / `defer zero(newPass)` en `cmdRestore` tras leerlos.

Mitigación sugerida:

- Cambiar la comprobación de pertenencia a:
  `dek, err := vault.UnwrapDEK(...); if err != nil { ... }; vault.ZeroForTestOrInternal(dek)` o exponer un helper interno que no devuelva la DEK.
- Añadir `defer zero(kek)` en `cmdRestore` después de `RestoreKEK`.
- Añadir `defer zero(newPass)` después de leer la passphrase nueva.

### Baja — El tutorial omite el matiz de copias antiguas del ledger

Archivos:

- `docs/TUTORIAL-es.md:750-766`
- `docs/OPERACION.md:284-289`
- `cmd/nucleo/backup.go:215-221`
- `docs/adr/ADR-029-restore-fija-passphrase-nueva.md:67-72`

`OPERACION.md` y la salida del comando son precisas: las tarjetas viejas dejan de valer para el vault actual, pero una copia del ledger hecha antes del cambio sigue abriendo con la passphrase/tarjetas viejas.

`TUTORIAL-es.md` dice: “desde ese momento las tarjetas viejas no sirven: destrúyelas”. Para el vault actual es correcto. Como explicación completa para un usuario, falta el matiz de las copias antiguas, que ADR-029 considera importante y que `OPERACION.md` sí conserva.

Prueba automatizada faltante:

- Test documental o grep en `operacion_test.go` que asegure que el tutorial conserva una frase sobre “copia del ledger hecha antes del cambio” cerca del bloque de `restore --new-passphrase`.

## Áreas que resistieron la revisión

### 1. Atomicidad

Archivos:

- `internal/vault/rekey.go:100-116`
- `internal/vault/rekey.go:126-132`
- `internal/store/blobs.go:141-180`
- `internal/store/replacemeta_test.go:61-98`
- `cmd/nucleo/restore_test.go:168-224`

`PrepareRekey` prepara `expected` con los bytes exactos actuales de `vault/params/v1` y `vault/dek/v1`, y `updates` con los nuevos parámetros y la DEK reenvuelta. `Commit` llama a `ReplaceMeta`.

`ReplaceMeta` abre una transacción, comprueba dentro de ella que todas las filas esperadas existen y tienen exactamente los bytes leídos, actualiza todas las filas y solo entonces hace `Commit`.

Los tests matan el proceso con `os.Exit` en fronteras relevantes:

- después de comprobar tarjetas;
- después de emitir tarjetas nuevas;
- después de confirmar;
- dentro de la transacción tras escribir cada clave;
- después de fijar la passphrase.

Conclusión: no encontré un orden de operaciones del código normal que deje salt nuevo con DEK vieja, DEK nueva con salt viejo, o ausencia de ambas formas de apertura. Ante muerte antes del commit queda el estado viejo; después del commit queda el nuevo.

Límite: ningún software puede prometer recuperación si el almacenamiento incumple la semántica de SQLite/WAL/synchronous=FULL o si hay corrupción arbitraria post-commit. Bajo el modelo del proyecto, la atomicidad está correctamente implementada.

### 2. Tarjetas viejas

Archivos:

- `internal/vault/rekey_test.go:58-140`
- `cmd/nucleo/restore_test.go:37-90`
- `cmd/nucleo/backup.go:115-128`
- `cmd/nucleo/backup.go:215-221`

Las tarjetas respaldan la KEK. Después de `restore --new-passphrase`, la DEK queda reenvuelta con una KEK nueva derivada de la passphrase nueva y salt nuevo. Las tarjetas viejas reconstruyen la KEK anterior, que ya no desenvuelve `vault/dek/v1` actual.

El código lo comprueba por dos vías:

- tests de vault: las tarjetas viejas reconstruyen una KEK, pero `UnwrapDEK` falla contra el `wrapped` actual;
- tests CLI: `restore` con tarjetas viejas devuelve código de verificación y menciona que quedaron sin valor.

La excepción está documentada correctamente: copias antiguas del ledger, hechas antes del cambio, siguen abriendo con material viejo porque contienen el `vault/dek/v1` anterior.

### 3. Parámetros y aleatoriedad

Archivos:

- `internal/vault/rekey.go:70-80`
- `internal/vault/rekey_test.go:131-139`
- `internal/vault/backup.go:40-76`
- `internal/vault/backup_test.go:107-132`

`PrepareRekey` conserva los parámetros Argon2id existentes (`Time`, `Memory`, `Threads`, `KeyLen`) y cambia solo `Salt` con `crypto/rand`. La prueba `TestRekeyPerderLaPassphraseYFijarOtra` verifica mismo perfil y salt distinto.

Las tarjetas nuevas se generan con `BackupKEK(rk.NewKEK(), shares, threshold)` antes del commit, y `BackupKEK` delega en SLIP-0039 con identificador/coeficientes aleatorios. `TestRestoreRejectsSharesFromDifferentBackups` comprueba que dos respaldos de la misma KEK producen shares distintos e incompatibles entre sí.

No vi reutilización indebida de salt ni de tarjetas.

### 4. Lectura de passphrase nueva y exposición en errores

Archivos:

- `cmd/nucleo/backup.go:67-93`
- `cmd/nucleo/backup.go:152-155`
- `cmd/nucleo/env.go:218-264`

`--new-passphrase` exige terminal real y lee sin eco, dos veces, usando el mismo helper que `init`. Si no hay terminal, el mensaje recomienda `--new-passphrase-file`, no la bandera equivocada.

`--new-passphrase-file` lee un fichero limitado por tamaño y recorta solo CR/LF finales. No se pasa por argv ni por entorno. Los errores nombran rutas o condiciones, no el contenido de la passphrase.

Permisos: la CLI no exige permisos al fichero de passphrase, ni para `--passphrase-file` ni para `--new-passphrase-file`. Esto coincide con ADR-029: la comprobación de permisos estricta vive en el `Sealer` PHP para automatización web. Operativamente, `OPERACION.md` recomienda crear `/etc/nucleo/passphrase` como `0640 root:www-data` y usar un temporal en `/root` para la nueva passphrase.

### 5. Vault equivocado y tarjetas mezcladas

Archivos:

- `internal/vault/backup.go:116-147`
- `internal/vault/backup_test.go:107-132`
- `internal/vault/backup_test.go:234-296`
- `internal/vault/rekey_test.go:168-185`
- `cmd/nucleo/backup.go:105-128`

Dos tarjetas de respaldos distintos no reconstruyen una KEK válida bajo SLIP-0039; el test lo cubre.

Tarjetas válidas de otro vault sí pueden reconstruir “una” KEK, y eso es correcto. La pertenencia al vault se prueba después con `UnwrapDEK` contra la DEK envuelta de este vault y el `vaultID` como AAD. El CLI hace esa comprobación antes de prometer éxito o preparar el rekey.

No encontré un camino que acepte tarjetas de otro vault como propias.

### 6. Documentación operativa

Archivos:

- `docs/OPERACION.md:236-314`
- `docs/TUTORIAL-es.md:750-770`

`OPERACION.md` §3 describe con precisión el comportamiento: passphrase nueva, tarjetas nuevas, confirmación antes de escribir, tarjetas viejas inválidas para el vault actual, copias antiguas todavía abribles con material viejo, muerte a medias segura, y `--json` con `--assume-confirmed`.

`TUTORIAL-es.md` describe correctamente el flujo principal, pero debería repetir el matiz de las copias antiguas del ledger para evitar que “las tarjetas viejas no sirven” se lea como afirmación absoluta sobre backups históricos.

## Recomendaciones

1. Documentar o cerrar la carrera “seal ya desbloqueado durante restore”. Si se acepta, decir explícitamente que el cambio invalida nuevas aperturas, no procesos que ya cargaron la DEK.
2. Borrar explícitamente `kek`, `newPass` y la DEK temporal de comprobación en `cmdRestore`.
3. Añadir el matiz de copias antiguas en `TUTORIAL-es.md` junto al bloque de pérdida de passphrase.
4. Añadir un test de concurrencia con `testhooks` para fijar la semántica de `seal` vs `restore`.

## Veredicto

ADR-029 cumple su propiedad principal: perder la passphrase ya no implica perder el vault si se conservan tarjetas suficientes, y el cambio no deja estados mixtos bajo las garantías de SQLite configuradas por el proyecto.

La implementación es razonable para v0.3.0-alpha. Antes de vender el cambio como revocación inmediata de una passphrase comprometida, conviene resolver o documentar la concurrencia con comandos ya desbloqueados.
