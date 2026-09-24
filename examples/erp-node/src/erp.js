// El "ERP": facturas en un fichero JSON. Es lo mínimo para que el ejemplo sea realista
// sin traer una base de datos, y a la vez lo bastante real para que el paso que importa
// —alterar un registro y que la reconciliación lo cace— tenga sentido.
//
// Lo que este fichero enseña de Núcleo:
//
//   · el payload que se sella es un DOCUMENTO del ERP, canónico y con entropía dentro
//     (ADR-023 §C). Una factura es un documento de baja entropía: cliente, fecha,
//     importe. Sin un campo aleatorio, su hash —que va en el header y por tanto en cada
//     recibo— se puede confirmar por enumeración. Los dieciséis bytes del `nonce` son la
//     diferencia entre "el hash confirma una conjetura" y "el hash no dice nada".
//   · la clave de idempotencia es el NÚMERO DE FACTURA. No un UUID nuevo en cada
//     intento: la clave tiene que ser la misma cuando el ERP reintenta, o no sirve de
//     nada (ADR-020 §D).
//   · el ERP guarda el índice del bloque y el hash del contenido. Con eso emite recibos
//     y reconcilia; sin eso tendría que buscar en el ledger, y el ledger no es su índice.

import { randomBytes } from "node:crypto";
import { mkdirSync, readFileSync, writeFileSync, existsSync } from "node:fs";
import { dirname, join } from "node:path";

/** TENANT es el RUC del emisor. En un ERP de verdad sale de su configuración. */
export const TENANT = "1790012345001";

/** TIPO es el tipo de registro. Con perfil sería ecuador.sri.factura.v1. */
export const TIPO = "sri.factura.v1";

export class ERP {
  /**
   * @param {object} o
   * @param {string} o.fichero  dónde vive la "base de datos" del ERP
   * @param {import("./nucleo.js").Nucleo} o.nucleo
   * @param {string} o.dirDocumentos  dónde se escriben los payloads que se sellan
   */
  constructor({ fichero, nucleo, dirDocumentos }) {
    this.fichero = fichero;
    this.nucleo = nucleo;
    this.dirDocumentos = dirDocumentos;
    mkdirSync(dirname(fichero), { recursive: true });
    mkdirSync(dirDocumentos, { recursive: true });
    this.datos = existsSync(fichero)
      ? JSON.parse(readFileSync(fichero, "utf8"))
      : { siguienteNumero: 1, facturas: [] };
  }

  #guarda() {
    writeFileSync(this.fichero, JSON.stringify(this.datos, null, 2) + "\n");
  }

  facturas() {
    return this.datos.facturas;
  }

  factura(numero) {
    return this.datos.facturas.find((f) => f.numero === numero) ?? null;
  }

  /**
   * documento devuelve los bytes EXACTOS que se sellaron (o se van a sellar).
   *
   * Es una sola función y la usan el sellado y la reconciliación, a propósito: si el ERP
   * construyera el documento de dos maneras, la reconciliación denunciaría alteraciones
   * que no existen. Las claves van ordenadas y sin espacios para que el mismo contenido
   * dé siempre los mismos bytes.
   */
  documento(f) {
    return JSON.stringify({
      cliente: f.cliente,
      fecha: f.fecha,
      items: f.items,
      nonce: f.nonce,
      numero: f.numero,
      ruc: f.ruc,
      total: f.total,
    });
  }

  /**
   * emite una factura: la escribe en el ERP y la sella en Núcleo.
   *
   * El orden importa y es el que usaría un ERP de verdad: primero se decide el número
   * —que es la clave de idempotencia—, después se sella, y solo si el sellado sale bien
   * se guarda como emitida. Si el sellado falla, la factura queda "pendiente" con su
   * número reservado, y el reintento usa LA MISMA clave: o entra, o descubre que ya
   * estaba sellada y no duplica nada.
   */
  async emite({ cliente, ruc, items }) {
    const numero = String(this.datos.siguienteNumero).padStart(6, "0");
    const total = items.reduce((s, i) => s + Math.round(i.cantidad * i.precioCentavos), 0);
    const f = {
      numero,
      fecha: new Date().toISOString().slice(0, 10),
      cliente,
      ruc,
      items,
      total: (total / 100).toFixed(2),
      // Entropía DENTRO del documento (ADR-023 §C): sin esto, el payload_hash que va en
      // el recibo confirma una conjetura de la factura entera.
      nonce: randomBytes(16).toString("hex"),
      estado: "pendiente",
      nucleo: null,
    };
    this.datos.siguienteNumero += 1;
    this.datos.facturas.push(f);
    this.#guarda();
    return this.#sella(f);
  }

  /**
   * reintenta el sellado de una factura que quedó pendiente.
   *
   * Reutiliza LA MISMA clave de idempotencia. Si el primer intento sí escribió —un
   * timeout no dice que no se escribiera—, este segundo no duplica: contesta lo del
   * primero con `idempotent: true`. Es la única respuesta correcta a un sellado que
   * falló a medias, y este método existe para enseñarla.
   */
  async reintenta(numero) {
    const f = this.factura(numero);
    if (!f) throw new Error(`no hay factura ${numero}`);
    if (f.estado === "emitida") return { factura: f, sellado: null };
    return this.#sella(f);
  }

  async #sella(f) {
    const ruta = join(this.dirDocumentos, `factura-${f.numero}.json`);
    writeFileSync(ruta, this.documento(f));
    const clave = `factura-${f.numero}`;

    // El comando se guarda ANTES de ejecutarlo, y se guarda siempre: si el sellado
    // falla, lo que el operador necesita ver es precisamente la orden que falló.
    const comando = this.nucleo.comando(["seal", "--tenant", TENANT, "--type", TIPO,
      "--payload", ruta, "--passphrase-file", "<fichero>", "--idempotency-key", clave]);
    f.comandoDeSellado = comando;
    this.#guarda();

    const sellado = await this.nucleo.sella({
      payloadFile: ruta,
      tipo: TIPO,
      tenant: TENANT,
      // La clave de idempotencia ES el número de factura. Un reintento del mismo
      // documento la repite; otra factura, no.
      idempotencyKey: clave,
    });

    f.estado = "emitida";
    f.nucleo = {
      bloque: sellado.index,
      hashBloque: sellado.hash,
      hashContenido: sellado.payloadHash,
      idempotencyKey: clave,
      idempotente: sellado.idempotent,
      duplicadoDe: sellado.duplicateOf,
      selladaEn: new Date().toISOString(),
    };
    this.#guarda();
    return { factura: f, sellado };
  }

  /**
   * altera una factura en la base del ERP, sin tocar el ledger.
   *
   * Es el paso 8 del criterio de éxito: Núcleo no puede impedir que alguien edite la
   * base operativa —no es suya— y lo que hace es recordar qué decía el registro cuando se
   * selló. Esto simula al que baja un importe después de emitir.
   */
  altera(numero, cambios) {
    const f = this.factura(numero);
    if (!f) throw new Error(`no hay factura ${numero}`);
    Object.assign(f, cambios);
    f.alterada = true;
    this.#guarda();
    return f;
  }

  /**
   * vivoJSONL escribe lo que el ERP dice HOY, en el formato que espera `reconcile`:
   * una línea por registro, con el índice del bloque y el contenido actual en base64.
   */
  vivoJSONL(ruta) {
    const lineas = this.datos.facturas
      .filter((f) => f.nucleo)
      .map((f) =>
        JSON.stringify({
          index: f.nucleo.bloque,
          payload_b64: Buffer.from(this.documento(f), "utf8").toString("base64"),
        }),
      );
    writeFileSync(ruta, lineas.join("\n") + (lineas.length ? "\n" : ""));
    return ruta;
  }
}
