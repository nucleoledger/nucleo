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

LA POLÍTICA (--policy-file)
  Todo lo que un verificador tiene que traer de FUERA del fichero, en un JSON
  que es el mismo que usan el SDK de TypeScript y la página web:

    {
      "origin":    "nucleoledger.com/mi-empresa",
      "logKey":    "<hex>",    clave pública del log
      "signerKey": "<hex>",    clave pública del que firma los bloques
      "witnesses": { "witness.ejemplo/w1": "<hex>" },
      "quorum":    1
    }

  El subcomando sync la imprime lista para guardar al terminar. Se pasa con --policy-file a
  status, verify, seal, reconcile, sync y receipt. Las banderas sueltas
  (--witness-name, --witness-key, --signer-key) siguen valiendo; fichero Y
  banderas a la vez es error: dos fuentes de verdad se contradicen en silencio.
  Si una bandera se repite, gana la ÚLTIMA, que es lo que hace el paquete flag
  de Go; no es un mecanismo para combinar valores.

  Por qué la clave del firmante no puede salir del propio ledger: vive en el
  fichero que un atacante escribe, y "verificarla" contra sí misma sube el
  listón en un UPDATE. status la publica para que la COMPARES con tu política,
  no para que la copies de ahí.

QUÉ SIGNIFICA "ATESTIGUADA"
  Un checkpoint guardado en el ledger solo cuenta como atestación si se puede
  VERIFICAR, con la misma maquinaria que un recibo: la firma del log con la
  clave que el propio ledger declara, y la cosignature del testigo con una
  clave que viene de FUERA del fichero. Esa clave la aportas tú:

    nucleo status --policy-file politica.json
    (o --witness-name y --witness-key; también verify, seal y reconcile)

  Con "signerKey" en la política, además se comprueba que la cadena la firma
  quien tú dices: sin ella, status dice "firmante: NO verificado". La
  continuidad —una sola clave en toda la cadena— se comprueba siempre.

  Sin ella, la apertura no puede afirmar nada sobre terceros y no lo afirma:
  dice "checkpoint presente, NO verificado". Y sin atestación verificada no
  hay atajo: se recomputan todas las firmas, que en 10^5 bloques son ~8 s en
  vez de medio segundo. Es el precio de que status no mienta.

  En --json el campo "attestation" vale "none", "unverified" o "verified", y
  "attested" es true solo con "verified".

  Por qué la clave del testigo no puede vivir en el fichero: un atacante con
  escritura en la base puede fabricar un checkpoint entero, y una auditoría lo
  hizo. Lo único que no puede fabricar es una cosignature de un testigo cuya
  clave no tiene — y eso solo se comprueba con una clave que tú traes.

ATESTACIÓN VIEJA
  Integridad y frescura son cosas distintas. Un ledger puede estar íntegro y
  atestiguado hasta el bloque 4.000 y llevar dos meses sin que nadie de fuera
  vea una raíz: las dos frases serían verdad, y solo la primera consuela.

  status, seal, verify y reconcile avisan por STDERR —también con --json—
  cuando la última atestación pasa del umbral, o cuando nunca hubo ninguna. En
  --json el veredicto va además en el objeto "freshness", con el campo "stale".

  La frescura está SUBORDINADA a la atestación. Con la política y la atestación
  verificada, la fecha sale de la cosignature que se acaba de comprobar, y la
  línea lleva ✔. Sin política, lo único que hay es el registro que dejó el
  último sync en este mismo fichero —que cualquiera con la base puede escribir,
  y una auditoría lo escribió—, y la línea lo dice: "registro local, NO
  verificado". En --json, "freshness.verified" y "freshness.source"
  ("attestation" | "local_record" | "none") dicen de dónde salió la fecha. Un
  cron que mire "stale" sin mirar "verified" se está fiando del disco.

  El contrato completo de la salida --json está en docs/CLI-JSON.md.

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
