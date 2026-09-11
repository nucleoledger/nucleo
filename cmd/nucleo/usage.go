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
  receipt     emite el recibo FIRMADO de un bloque para un destinatario
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
              verificada (por omisión 72h). Ver EL RECIBO Y SUS DOS FIRMAS
  Un recibo @v2 lleva dos firmas, las dos de la clave del emisor, y dicen cosas
  distintas:

    firma del bloque   quién escribió el registro. Es lo que permite además
                       recomponer la hoja del árbol (regla leaf/v2).
    firma del recibo   quién emitió ESTE documento para ESTE destinatario con
                       ESTE texto, advertencia legal incluida.

  Quien recibe el recibo las verifica con lo que ya tiene: la clave sale de
  signer_pubkey, que va dentro del header, y el header está bajo la raíz que
  cosignan los testigos. No hay claves que repartir.

  Por eso el subcomando receipt pide la passphrase: firma. Un recibo de la versión anterior
  (@v1) se reconoce y se rechaza diciendo que lo es.

ATESTACIÓN VIEJA.

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

PERFILES DE DERIVACIÓN (init --kdf-profile)
  La passphrase se convierte en clave con Argon2id, y eso cuesta memoria a
  propósito: es lo que hace caro probar passphrases.

    default      64 MiB · 3 iteraciones · 4 hilos   — RFC 9106 §4, 2.ª opción
    constrained  19 MiB · 2 iteraciones · 1 hilo    — mínimo de OWASP

  Medido en un Ryzen 7 5700U: abrir el vault tarda 51 ms con default y 25 ms con
  constrained, y reserva 67 MB contra 20 MB.

  El perfil reducido es MÁS DÉBIL y no hay forma de decirlo de otra manera: con
  8 GiB, un atacante pasa de unos 2.400 intentos por segundo a unos 16.700, un
  factor 7. Se ofrece porque en un plan compartido 64 MiB × 4 hilos choca con
  los límites de LVE/CageFS, y ahí la alternativa real no es un perfil más
  fuerte: es no cifrar nada. Si lo usas, compensa con una passphrase más larga.

  Los parámetros se guardan en el vault: se abre con los que se creó, no con los
  de la versión del binario. Cambiar de perfil exige crear un vault nuevo.

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
