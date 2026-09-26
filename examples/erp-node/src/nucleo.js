// El envoltorio del binario `nucleo`. No reimplementa nada.
//
// Por qué un envoltorio y no una implementación: el ledger tiene UN escritor (ADR-021 §A).
// Los invariantes del que escribe —el encadenamiento, la transacción única, el cerrojo
// anti-retroceso, la atestación al abrir— no están en el formato, así que una segunda
// implementación no necesita equivocarse en criptografía para romper un ledger.
//
// Lo que este fichero aporta, y es lo único que aporta:
//
//   · la política se pasa en TODA ejecución (ADR-017). El SDK de PHP tuvo un fallo alto
//     por guardarla y no pasarla, y aquí se pasa en el camino común por eso;
//   · la passphrase va por FICHERO, nunca por argumento: la lista de procesos la ve toda
//     la máquina;
//   · los códigos de salida se convierten en errores con tipo, porque lo que un ERP hace
//     con cada uno es distinto;
//   · stderr no se tira. Ahí van los avisos de frescura y de rollback, también con
//     --json, y un ERP que los descarta se queda sin la única alarma que tiene.

import { spawn } from "node:child_process";
import { accessSync, constants, statSync } from "node:fs";
import * as contrato from "./contrato.js";

export { ErrorDeContrato } from "./contrato.js";

/** ErrorDeNucleo es la base: todos los fallos del binario pasan por aquí. */
export class ErrorDeNucleo extends Error {
  constructor(mensaje, { exitCode = -1, stderr = "", clase = "" } = {}) {
    super(mensaje);
    // El nombre de la clase de VERDAD —ErrorDeSincronizacion, ErrorDeUso…—, no el de la
    // base: es lo que sale en los logs del integrador, y "ErrorDeNucleo" para un testigo
    // caído obliga a mirar el código de salida para saber qué pasó.
    this.name = new.target.name;
    this.exitCode = exitCode;
    this.stderr = stderr;
    /**
     * clase es lo que el código de salida no puede decir (ADR-027): usage, transient,
     * environment o integrity. El caso que la hizo falta está en este ejemplo: pedir el
     * recibo de un bloque que ningún testigo cubrió sale con código 1 —como una bandera
     * mal escrita— y es TRANSITORIO, se arregla sincronizando.
     */
    this.clase = clase;
  }

  /** esReintentable es la pregunta que un ERP hace de verdad. */
  esReintentable() {
    return this.clase === "transient";
  }
}

/** ErrorDeUso es el código 1: error de uso o de entrada. Es un bug del integrador. */
export class ErrorDeUso extends ErrorDeNucleo {}

/** ErrorDeIntegridad es el código 2: la verificación falló. Es un incidente, no un reintento. */
export class ErrorDeIntegridad extends ErrorDeNucleo {}

/** ErrorDeSincronizacion es el código 3: el testigo. Se reintenta luego. */
export class ErrorDeSincronizacion extends ErrorDeNucleo {}

/**
 * ErrorDeEntorno es cuando el binario NO LLEGA A EJECUTARSE.
 *
 * Su arreglo no está en el código: está en el despliegue. Un ERP que lo confunda con un
 * error de negocio mostrará "no se pudo emitir la factura" cuando lo que pasa es que
 * falta un fichero.
 */
export class ErrorDeEntorno extends ErrorDeNucleo {}

const PORCODIGO = { 1: ErrorDeUso, 2: ErrorDeIntegridad, 3: ErrorDeSincronizacion };

export class Nucleo {
  /**
   * @param {object} opciones
   * @param {string} opciones.binario        ruta del ejecutable `nucleo`
   * @param {string} opciones.dir            directorio del despliegue (el del nucleo.db)
   * @param {string} opciones.passphraseFile fichero con la passphrase, en modo 0600
   * @param {string=} opciones.policyFile    política de verificación (ADR-017)
   * @param {number=} opciones.timeoutMs     cuánto esperar antes de darlo por colgado
   * @param {(nivel: string, mensaje: string) => void=} opciones.log  a dónde van los avisos
   * @param {(alerta: object) => void=} opciones.onStale  se llama en CADA operación
   *        mientras haya una alarma de frescura abierta y sin reconocer (ADR-028 §E).
   *        Es un requisito de integración: el integrador elige el canal, Núcleo le
   *        garantiza que se entera.
   * @param {string=} opciones.staleAfter  umbral de frescura (`--stale-after`), p. ej. "72h"
   */
  constructor({ binario, dir, passphraseFile, policyFile = null, timeoutMs = 60_000, log = null, onStale = null, staleAfter = null }) {
    this.binario = binario;
    this.dir = dir;
    this.passphraseFile = passphraseFile;
    this.policyFile = policyFile;
    this.timeoutMs = timeoutMs;
    this.log = log ?? ((nivel, mensaje) => console.error(`[nucleo:${nivel}] ${mensaje}`));
    this.onStale = onStale;
    this.staleAfter = staleAfter;
  }

  /**
   * sella un documento y devuelve el sellado ya comprobado contra el contrato.
   *
   * `idempotencyKey` no es opcional en la práctica: un ERP que reintenta tras un timeout
   * sin ella duplica el registro (ADR-020 §D). La firma lo pide como parámetro con
   * nombre para que no se pase por descuido.
   */
  async sella({ payloadFile, tipo, tenant, idempotencyKey, cifrar = true, fallaSiVieja = false }) {
    if (!idempotencyKey) {
      throw new ErrorDeUso(
        "sella() necesita idempotencyKey: sin ella, un reintento tras un timeout duplica el registro (ADR-020 §D)",
      );
    }
    const args = ["seal", "--tenant", tenant, "--type", tipo, "--payload", payloadFile,
      "--passphrase-file", this.passphraseFile, "--idempotency-key", idempotencyKey];
    if (!cifrar) args.push("--no-encrypt");
    // --fail-on-stale: con la atestación vieja NO sella y lanza ErrorDeSincronizacion
    // (clase transient). Desactivado por omisión: un registro no sellado se pierde.
    if (fallaSiVieja) args.push("--fail-on-stale");
    return contrato.sellado(await this.#ejecuta(args));
  }

  /** sincroniza con el testigo. Devuelve lo que contestó, ya comprobado. */
  async sincroniza({ witnessURL, timeoutMs = null }) {
    const args = ["sync", "--witness", witnessURL, "--passphrase-file", this.passphraseFile];
    const j = await this.#ejecuta(args, { timeoutMs: timeoutMs ?? this.timeoutMs });
    contrato.booleano(j, "ok");
    return {
      origin: contrato.cadena(j, "origin", { vacia: false }),
      localSize: contrato.entero(j, "local_size"),
      witnessSize: contrato.entero(j, "witness_size"),
      attested: contrato.booleano(j, "attested"),
      replaySuspect: contrato.booleano(j, "replay_suspect"),
      raw: j,
    };
  }

  /** estado del ledger, que es lo que mira un cron. */
  async estado() {
    return contrato.estado(await this.#ejecuta(["status"]));
  }

  /** verifica la integridad. `completa` recomputa todas las firmas. */
  async verifica({ completa = false } = {}) {
    const args = completa ? ["verify", "--full"] : ["verify"];
    const j = await this.#ejecuta(args);
    return { modo: contrato.cadena(j, "mode", { vacia: false }), treeSize: contrato.entero(j, "tree_size"), raw: j };
  }

  /** emite el recibo de un bloque para un destinatario, y devuelve su texto. */
  async recibo({ bloque, destinatario }) {
    const j = await this.#ejecuta(["receipt", "--block", String(bloque), "--recipient", destinatario,
      "--passphrase-file", this.passphraseFile]);
    contrato.booleano(j, "ok");
    return {
      bloque: contrato.entero(j, "block"),
      destinatario: contrato.cadena(j, "recipient", { vacia: false }),
      texto: contrato.cadena(j, "receipt", { vacia: false }),
      tiempoDemostrable: contrato.cadena(j, "provable_time"),
      cosignatarios: j.cosigners ?? [],
      raw: j,
    };
  }

  /**
   * reconcilia el sistema vivo contra lo sellado.
   *
   * Es el único comando que sale con código 2 cuando hace bien su trabajo: encontrar una
   * discrepancia NO es un fallo del programa. Por eso devuelve el informe en las dos
   * ramas en vez de lanzar.
   */
  async reconcilia({ sourceFile }) {
    try {
      return contrato.cotejo(await this.#ejecuta(["reconcile", "--source", sourceFile]));
    } catch (e) {
      if (e instanceof ErrorDeIntegridad && e.json) {
        return contrato.cotejo(e.json);
      }
      throw e;
    }
  }

  /** estadoDeAlarma devuelve la alarma de frescura (ADR-028): { state, … } del contrato. */
  async estadoDeAlarma() {
    const j = await this.#ejecuta(["alert", "status"]);
    const a = contrato.alerta(j);
    if (!a) throw new contrato.ErrorDeContrato("alert status no trajo el objeto alert: el binario es anterior a ADR-028");
    return a;
  }

  /**
   * reconoceAlarma dice que alguien se ha enterado. No la cierra —la cierra un sync que
   * sale bien—, pero onStale deja de llamarse hasta el siguiente episodio. Llámalo cuando
   * tu canal haya ENTREGADO el aviso, no dentro del propio hook.
   */
  async reconoceAlarma({ por = null } = {}) {
    const args = ["alert", "ack"];
    if (por) args.push("--by", por);
    const j = await this.#ejecuta(args);
    return { reconocida: contrato.booleano(j, "acked"), alerta: contrato.alerta(j) };
  }

  /** compruebaEntorno mira lo que un despliegue puede tener mal, antes de ejecutar nada. */
  compruebaEntorno() {
    try {
      const st = statSync(this.binario);
      if (!st.isFile()) throw new Error("no es un fichero");
    } catch {
      throw new ErrorDeEntorno(
        `no hay ningún binario de Núcleo en ${this.binario}.\n` +
          `  Constrúyelo con "go build -o nucleo ./cmd/nucleo" o baja el release firmado, y apunta\n` +
          `  NUCLEO_BIN a él. Sin binario no se sella: este ERP no tiene forma de fabricar un ledger.`,
      );
    }
    if (process.platform !== "win32") {
      // is_executable no se consulta en Windows por lo mismo que en el SDK de PHP: allí
      // el acceso lo gobierna la ACL, que no se ve desde los permisos que expone Node.
      try {
        accessSync(this.binario, constants.X_OK);
      } catch {
        throw new ErrorDeEntorno(`${this.binario} existe y no se puede ejecutar. Dale permiso: chmod 0700 ${this.binario}`);
      }
    }
    try {
      statSync(this.passphraseFile);
    } catch {
      throw new ErrorDeEntorno(
        `no hay fichero de passphrase en ${this.passphraseFile}.\n` +
          `  Sin él la CLI la pediría por terminal, y un servidor no tiene terminal.`,
      );
    }
    if (this.policyFile) {
      try {
        statSync(this.policyFile);
      } catch {
        throw new ErrorDeEntorno(
          `se configuró la política ${this.policyFile} y el fichero no está.\n` +
            `  Seguir sin ella sellaría sin verificar la atestación ni el firmante (ADR-017).`,
        );
      }
    }
  }

  /** La línea de comandos que se va a ejecutar, para poder ENSEÑARLA. */
  comando(args) {
    return [this.binario, ...this.#globales(), ...this.#conPolitica(args)]
      .map((a) => (/\s/.test(a) ? JSON.stringify(a) : a))
      .join(" ");
  }

  /**
   * conPolitica mete --policy-file DESPUÉS del subcomando.
   *
   * El orden no es cosmético: --dir y --json son globales y van antes del subcomando,
   * --policy-file lo registra cada subcomando y va después. Al revés, la CLI contesta
   * "subcomando desconocido" y el envoltorio parece roto por otro motivo.
   */
  #conPolitica(args) {
    if (!this.policyFile) return args;
    // `alert status` y `alert ack` son subcomandos de DOS palabras: la política va
    // detrás de las dos, no entre ellas.
    const n = args[0] === "alert" && args.length > 1 ? 2 : 1;
    return [...args.slice(0, n), "--policy-file", this.policyFile, ...args.slice(n)];
  }

  /** globales son las banderas que van ANTES del subcomando. */
  #globales() {
    const g = ["--dir", this.dir, "--json"];
    if (this.staleAfter) g.push("--stale-after", this.staleAfter);
    return g;
  }

  /**
   * avisaSiHayAlarma llama a onStale con una alarma abierta y sin reconocer.
   *
   * Al menos una vez (ADR-028 §E): se repite en cada operación hasta reconoceAlarma().
   * Si el hook falla, el fallo va al log y la operación sigue: el sellado ya está hecho
   * cuando se llama, y un aviso que no sale no puede convertirlo en uno fallido.
   */
  #avisaSiHayAlarma(j) {
    if (!this.onStale || !Object.prototype.hasOwnProperty.call(j, "alert")) return;
    let a;
    try {
      a = contrato.alerta(j);
    } catch {
      return; // un alert que no cumple lo rechaza el camino normal
    }
    if (!a || a.state !== "open") return;
    try {
      const r = this.onStale(a);
      if (r && typeof r.catch === "function") {
        r.catch((e) => this.log("alarma", `el hook onStale falló: ${e?.message ?? e}. La alarma sigue abierta desde ${a.stale_since}.`));
      }
    } catch (e) {
      this.log("alarma", `el hook onStale falló: ${e?.message ?? e}. La alarma sigue abierta desde ${a.stale_since}.`);
    }
  }

  async #ejecuta(args, { timeoutMs = null } = {}) {
    this.compruebaEntorno();
    const cmd = [this.binario, ...this.#globales(), ...this.#conPolitica(args)];
    const limite = timeoutMs ?? this.timeoutMs;

    const { code, signal, stdout, stderr, spawnError } = await new Promise((resolve) => {
      // spawn con la lista de argumentos y sin shell: así no hay citado que se pueda
      // equivocar con un nombre de fichero raro.
      const p = spawn(cmd[0], cmd.slice(1), { stdio: ["ignore", "pipe", "pipe"] });
      let out = "";
      let err = "";
      let terminado = false;
      const reloj = setTimeout(() => {
        terminado = true;
        p.kill("SIGKILL");
      }, limite);
      p.stdout.on("data", (d) => (out += d));
      p.stderr.on("data", (d) => (err += d));
      p.on("error", (e) => {
        clearTimeout(reloj);
        resolve({ code: -1, signal: null, stdout: out, stderr: err, spawnError: e });
      });
      p.on("close", (c, s) => {
        clearTimeout(reloj);
        resolve({ code: c, signal: terminado ? "timeout" : s, stdout: out, stderr: err, spawnError: null });
      });
    });

    // stdin cerrado a propósito (stdio "ignore"): la CLI pide la passphrase por terminal
    // si no encuentra el fichero, y un servidor no tiene terminal. Sin esto, un olvido
    // del fichero de passphrase se quedaría esperando para siempre.
    if (spawnError) {
      throw new ErrorDeEntorno(`no se pudo ejecutar ${this.binario}: ${spawnError.message}`, { stderr });
    }
    if (signal === "timeout") {
      throw new ErrorDeEntorno(
        `${args[0]} no terminó en ${limite} ms. El registro PUEDE haberse escrito: reintenta con la MISMA\n` +
          `  clave de idempotencia, que es exactamente para esto (ADR-020 §D).`,
        { stderr },
      );
    }

    // Los avisos de Núcleo viajan por stderr, también con --json: frescura, rollback,
    // replay. No son errores y no se tiran.
    for (const linea of stderr.split("\n")) {
      const l = linea.trimEnd();
      if (l === "") continue;
      this.log(l.startsWith("✘") ? "alarma" : "aviso", l);
    }

    const j = contrato.decode(stdout);
    // La alarma, antes que nada: también cuando la CLI devuelve error. Un `sync` que no
    // llega al testigo y un `seal --fail-on-stale` que se niega la traen en el objeto de
    // error, y son justo los dos momentos en que más importa.
    this.#avisaSiHayAlarma(j);
    if (code === 0) return j;

    // No todo código distinto de 0 trae un objeto de error, y esto lo descubrió el
    // ejemplo: `reconcile` con hallazgos sale con 2 y entrega su INFORME completo, con
    // ok:false y sin `error` ni `exit_code`. Está dicho en docs/CLI-JSON.md, en las
    // convenciones, y es fácil de pasar por alto si se implementa solo la regla general.
    // Así que manda el código del proceso, y el objeto de error se lee si está.
    let mensaje;
    let exitCode = code;
    let clase = "";
    if (Object.prototype.hasOwnProperty.call(j, "exit_code")) {
      const err = contrato.errorDeLaCLI(j);
      mensaje = err.error;
      exitCode = err.exitCode;
      clase = err.clase;
    } else {
      if (contrato.booleano(j, "ok") !== false) {
        throw new contrato.ErrorDeContrato(`la CLI salió con ${code} y dice ok: true`);
      }
      mensaje = `${args[0]} salió con código ${code} y entregó su informe, sin objeto de error`;
      clase = contrato.claseDelError(j, code);
    }
    const Clase = PORCODIGO[exitCode] ?? ErrorDeNucleo;
    const e = new Clase(mensaje, { exitCode, stderr, clase });
    // El JSON entero viaja con el error: `reconcile` publica su informe completo con
    // ok:false y código 2, y tirarlo obligaría a volver a ejecutarlo para leerlo.
    e.json = j;
    throw e;
  }
}
