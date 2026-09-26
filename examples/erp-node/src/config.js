// Dónde está cada cosa. Un solo fichero para que el servidor, la demo y el cron no
// discrepen: tres rutas distintas al mismo ledger es la forma más tonta de "perder"
// datos.

import { fileURLToPath } from "node:url";
import { dirname, join, resolve } from "node:path";
import { Nucleo } from "./nucleo.js";

export const RAIZ = dirname(dirname(fileURLToPath(import.meta.url)));
export const REPO = dirname(dirname(RAIZ));

/** DATOS es el despliegue: ledger, vault, facturas, política, passphrase. */
export const DATOS = process.env.NUCLEO_EJEMPLO_DATOS
  ? resolve(process.env.NUCLEO_EJEMPLO_DATOS)
  : join(RAIZ, "datos");

export const DIR_LEDGER = join(DATOS, "ledger");
export const DIR_DOCUMENTOS = join(DATOS, "documentos");
export const FICHERO_FACTURAS = join(DATOS, "facturas.json");
export const FICHERO_PASSPHRASE = join(DATOS, "passphrase.txt");
export const FICHERO_POLITICA = join(DATOS, "politica.json");
export const FICHERO_VIVO = join(DATOS, "vivo.jsonl");

/**
 * BINARIO es el ejecutable de Núcleo.
 *
 * Por omisión, el que queda al compilar el repositorio. En producción sería el release
 * firmado, verificado con cosign (docs/RELEASING.md); lo que NO sería nunca es un
 * binario que el ERP se baje solo.
 */
export const BINARIO = process.env.NUCLEO_BIN
  ? resolve(process.env.NUCLEO_BIN)
  : join(REPO, process.platform === "win32" ? "nucleo.exe" : "nucleo");

export const ORIGIN = process.env.NUCLEO_ORIGIN ?? "ejemplo.local/facturacion";
export const TESTIGO = process.env.NUCLEO_TESTIGO ?? "http://127.0.0.1:8099";
export const PUERTO = Number(process.env.PORT ?? 3000);

/**
 * ALARMA es la última alarma de frescura que llegó por el hook, o null.
 *
 * Es el canal del ejemplo: un banner en la pantalla de estado y una línea en el log. En
 * producción, el hook es el sitio donde el integrador manda un correo o un WhatsApp; el
 * ejemplo no envía nada porque no tiene credenciales de nadie, y no debe tenerlas.
 */
export const ALARMA = { actual: null };

function avisaDeAlarma(alerta) {
  ALARMA.actual = alerta;
  console.error(`[nucleo:alarma] atestación vieja desde ${alerta.stale_since} (${alerta.reason}). ` +
    "Nadie la ha reconocido todavía: `nucleo alert ack` cuando alguien se entere.");
}

/** DIARIO guarda los últimos avisos que Núcleo mandó por stderr, para poder ENSEÑARLOS. */
export const DIARIO = [];

/**
 * vistos cuenta cuántas veces ha llegado cada aviso.
 *
 * Núcleo repite sus avisos en cada ejecución, y hace bien: cada comando es un proceso
 * nuevo que no sabe qué se imprimió antes. Pero un ERP que sella cien facturas
 * escribiría cien veces el mismo párrafo y el log deja de leerse, que es otra forma de
 * perderlo. Así que el ejemplo los AGRUPA —el primero entero, los repetidos contados— y
 * no tira ninguno: todos siguen en el diario y en la pantalla de estado.
 */
const vistos = new Map();

/**
 * nucleo construye el envoltorio.
 *
 * `conPolitica: false` es para el arranque, cuando la política todavía no existe: el
 * primer `init` es el que la produce. Pasado ese momento, va en todas las ejecuciones.
 */
export function nucleo({ conPolitica = true, timeoutMs = 60_000, onStale = null, staleAfter = null } = {}) {
  return new Nucleo({
    // El hook de ADR-028. Por omisión, el del ejemplo: lo apunta en ALARMAS y en el log
    // del proceso. En tu ERP, aquí va tu canal —correo, WhatsApp, un ticket—.
    onStale: onStale ?? avisaDeAlarma,
    // NUCLEO_STALE_AFTER permite ver la alarma sin esperar tres días —p. ej. "30s"— y
    // probar el hook propio. En producción no se toca: el umbral por omisión son 72 h.
    staleAfter: staleAfter ?? process.env.NUCLEO_STALE_AFTER ?? null,
    binario: BINARIO,
    dir: DIR_LEDGER,
    passphraseFile: FICHERO_PASSPHRASE,
    policyFile: conPolitica ? FICHERO_POLITICA : null,
    timeoutMs,
    log: (nivel, mensaje) => {
      DIARIO.unshift({ nivel, mensaje, cuando: new Date().toISOString() });
      DIARIO.length = Math.min(DIARIO.length, 50);
      // También al log del proceso: en un servidor de verdad esto va al syslog, y es la
      // única alarma que hay. Descartarlo es quedarse ciego (ensayo de operación §3).
      const veces = (vistos.get(mensaje) ?? 0) + 1;
      vistos.set(mensaje, veces);
      if (veces === 1) console.error(`[nucleo:${nivel}] ${mensaje}`);
      else if (veces % 25 === 0) console.error(`[nucleo:${nivel}] (repetido ${veces} veces) ${mensaje.split("\n")[0]}`);
    },
  });
}
