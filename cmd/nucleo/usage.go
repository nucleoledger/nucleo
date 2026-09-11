package main

// usageText es la ayuda. Se escribe a mano y en español porque es lo primero
// que ve quien no conoce el programa.
func usageText() string {
	return `nucleo — registro con integridad demostrable

USO
  nucleo [--dir D] [--json] [--stale-after D] <subcomando> [opciones]

SUBCOMANDOS
  init        crea el vault y el ledger, y entrega las tarjetas de respaldo
  seal        sella un registro en el ledger
  status      muestra el estado del ledger y si está atestiguado
  verify      verifica la integridad del ledger  (--full para la exhaustiva)
  receipt     emite el recibo de un bloque para un destinatario
  reconcile   coteja el sistema vivo contra lo sellado
  sync        pide atestación a un testigo
  witness     witness serve — levanta un testigo · witness key — su clave pública
  backup      vuelve a emitir las tarjetas SLIP-0039 de la KEK
  restore     reconstruye la KEK desde las tarjetas

BANDERAS GLOBALES
  --dir D     directorio del despliegue (por defecto, el actual)
  --json      salida para máquinas en vez de para personas
  --stale-after D
              a partir de cuánto se considera VIEJA la última atestación
              verificada (por omisión 72h). Ver ATESTACIÓN VIEJA.

CÓDIGOS DE SALIDA
  0  todo correcto
  1  error de uso o de entrada
  2  la verificación falló: hay una alteración o una discrepancia
  3  la sincronización con el testigo falló (incidente operativo)

LÍMITES DE LECTURA
  documento a sellar         64 MiB   (--max-payload para subirlo)
  fichero de passphrase       1 MiB
  fichero de tarjetas         1 MiB
  clave del testigo           1 MiB

  Existen para que un fichero equivocado —un volcado de la base, un log
  rotado— dé un error en vez de consumir la memoria de la máquina.

ATESTACIÓN VIEJA
  Integridad y frescura son cosas distintas. Un ledger puede estar íntegro y
  atestiguado hasta el bloque 4.000 y llevar dos meses sin que nadie de fuera
  vea una raíz: las dos frases serían verdad, y solo la primera consuela.

  status, seal y verify avisan por STDERR —también con --json— cuando la última
  atestación verificada pasa del umbral, o cuando nunca hubo ninguna. En --json
  el veredicto va además en el objeto "freshness", con el campo "stale".

  El aviso sale por stderr a propósito: un cron con stdout a un fichero y
  stderr al correo del administrador hace sonar la alarma sin que nadie haya
  tenido que programar nada. Ninguno de los tres falla por ello; el que falla
  con código 3 es sync, que es el que de verdad no pudo hacer su trabajo.

  La fecha que se compara es la que afirmó el TESTIGO en su cosignature, leída
  después de verificarla contra su clave, no el reloj de esta máquina. Si los
  dos relojes discrepan tanto que la atestación parece del futuro, se avisa de
  eso en vez de dar la frescura por buena.

LA CLAVE DEL TESTIGO
  witness serve guarda su clave privada junto a su base de datos, la crea en
  exclusiva (nunca pisa una existente) y, en Linux y macOS, rehúsa arrancar si
  otros usuarios pueden leerla.

  En Windows esa comprobación NO se hace: el acceso lo gobierna la ACL del
  fichero, que no se ve desde los permisos que expone Go, y una comprobación que
  puede decir "está bien" cuando no lo está da una confianza que no se ha
  ganado. Allí, restringe la ACL a tu cuenta (ver docs/RELEASING.md).

La passphrase se pide por terminal sin eco. Nunca se pasa por argumento: los
argumentos son visibles en la lista de procesos de toda la máquina.
`
}
