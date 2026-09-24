// El contrato de la salida `--json` de Núcleo, leído en serio.
//
// Es el equivalente en Node de `Nucleo\Contract` del SDK de PHP, y está escrito desde
// docs/CLI-JSON.md SIN mirar el de PHP: eso es lo que le da al contrato de ADR-025 un
// segundo consumidor independiente. Si los dos envoltorios, escritos por separado,
// consumen el mismo JSON sin sorpresas, el contrato está bien definido.
//
// La regla de ADR-025 §B tiene dos mitades y las dos se aplican aquí:
//
//   · lo OBLIGATORIO que falta, o que viene con otro tipo, es un error. Nunca un valor
//     por omisión: un índice -1 o un "no atestiguado" que nadie afirmó es cómo un
//     binario antiguo o una salida truncada acaban pareciendo un sellado correcto.
//   · lo DESCONOCIDO se ignora. Un binario más nuevo puede añadir campos y este ERP
//     tiene que seguir funcionando.

/** ErrorDeContrato es lo que se lanza cuando la salida no cumple el contrato. */
export class ErrorDeContrato extends Error {
  constructor(mensaje) {
    super(mensaje);
    this.name = "ErrorDeContrato";
    /** Por qué existe esta clase aparte: la causa no está en el ledger ni en la
     * factura, está en el BINARIO. Un binario antiguo, truncado o sustituido cae aquí,
     * y lo que hay que hacer con eso —revisar el despliegue— no se parece a nada de lo
     * que un ERP hace con un error de negocio. */
    this.esDelBinario = true;
  }
}

/** decode convierte el stdout de la CLI en un objeto, o lanza. */
export function decode(raw) {
  let v;
  try {
    v = JSON.parse(raw);
  } catch (e) {
    throw new ErrorDeContrato(
      `la CLI no devolvió JSON (${e.message}). Primeros bytes: ${JSON.stringify(raw.slice(0, 200))}`,
    );
  }
  // typeof null === "object" y Array.isArray existe por algo: un array o un null son
  // JSON válido y no son el objeto que promete el contrato.
  if (v === null || typeof v !== "object" || Array.isArray(v)) {
    throw new ErrorDeContrato(`la CLI devolvió JSON que no es un objeto, sino ${v === null ? "null" : typeof v}`);
  }
  return v;
}

function presente(o, k) {
  if (!Object.prototype.hasOwnProperty.call(o, k)) {
    throw new ErrorDeContrato(
      `falta el campo obligatorio ${JSON.stringify(k)} en la salida de la CLI. ` +
        `Un binario más antiguo que este ERP, o una salida truncada, se ve exactamente así.`,
    );
  }
  return o[k];
}

function malTipo(k, esperado, v) {
  return new ErrorDeContrato(
    `${k} tiene que ser ${esperado} y llegó ${v === null ? "null" : typeof v}: ${JSON.stringify(v)}`,
  );
}

/** entero exige un entero DE VERDAD: ni "0", ni 0.5, ni true. */
export function entero(o, k, min = 0) {
  const v = presente(o, k);
  if (typeof v !== "number" || !Number.isInteger(v)) throw malTipo(k, "un entero", v);
  if (v < min) throw new ErrorDeContrato(`${k} = ${v}, y el mínimo es ${min}`);
  return v;
}

/** booleano exige un booleano DE VERDAD: ni "true", ni 1. */
export function booleano(o, k) {
  const v = presente(o, k);
  if (typeof v !== "boolean") throw malTipo(k, "un booleano", v);
  return v;
}

/** cadena exige una cadena; vacia dice si se admite vacía. */
export function cadena(o, k, { vacia = true } = {}) {
  const v = presente(o, k);
  if (typeof v !== "string") throw malTipo(k, "una cadena", v);
  if (!vacia && v === "") throw new ErrorDeContrato(`${k} está vacío`);
  return v;
}

/**
 * hex64 exige 64 caracteres [0-9a-f]. Las mayúsculas se rechazan aunque denoten el
 * mismo valor: CLI-JSON.md fija la minúscula y dos grafías del mismo hash son una de
 * más.
 */
export function hex64(o, k) {
  const v = cadena(o, k);
  if (!/^[0-9a-f]{64}$/.test(v)) {
    throw new ErrorDeContrato(`${k} no es un hash o clave en hex minúsculo de 64 caracteres: ${JSON.stringify(v.slice(0, 80))}`);
  }
  return v;
}

/** objeto exige un objeto JSON, no una lista. */
export function objeto(o, k) {
  const v = presente(o, k);
  if (v === null || typeof v !== "object" || Array.isArray(v)) throw malTipo(k, "un objeto", v);
  return v;
}

/** unoDe exige una de las cadenas permitidas y ninguna más. */
export function unoDe(o, k, permitidas) {
  const v = cadena(o, k);
  if (!permitidas.includes(v)) {
    throw new ErrorDeContrato(`${k} = ${JSON.stringify(v)}, y el contrato solo admite ${permitidas.join(", ")}`);
  }
  return v;
}

/**
 * listaDeEnteros exige una lista de enteros, o [] si el campo no está.
 *
 * Opcional a propósito: `duplicate_of` solo aparece cuando hay duplicados. Lo que no se
 * admite es que aparezca con cualquier cosa dentro.
 */
export function listaDeEnteros(o, k, min = 0) {
  if (!Object.prototype.hasOwnProperty.call(o, k)) return [];
  const v = o[k];
  if (!Array.isArray(v)) throw malTipo(k, "una lista", v);
  return v.map((x, i) => {
    if (typeof x !== "number" || !Number.isInteger(x) || x < min) {
      throw new ErrorDeContrato(`${k}[${i}] no es un entero >= ${min}: ${JSON.stringify(x)}`);
    }
    return x;
  });
}

/** freshness comprueba el objeto compartido de frescura. */
export function frescura(j) {
  const f = objeto(j, "freshness");
  booleano(f, "stale");
  booleano(f, "verified");
  booleano(f, "policy");
  unoDe(f, "source", ["attestation", "local_record", "none"]);
  return f;
}

/** signer comprueba el objeto compartido del firmante. */
export function firmante(j) {
  const s = objeto(j, "signer");
  const estado = unoDe(s, "state", ["none", "unverified", "verified"]);
  const verificado = booleano(s, "verified");
  // verified == (state == verified), y lo dice CLI-JSON.md. Que la salida se contradiga
  // a sí misma no es algo que este ERP deba interpretar.
  if (verificado !== (estado === "verified")) {
    throw new ErrorDeContrato(`signer se contradice: state = ${estado} con verified = ${verificado}`);
  }
  return s;
}

/**
 * sellado lee la salida de `seal`. Todos sus campos son obligatorios.
 *
 * Devuelve además `raw`, el objeto entero, porque un ERP siempre quiere algo que este
 * envoltorio no modela todavía y esconderlo obligaría a tocar el envoltorio para cada
 * campo nuevo.
 */
export function sellado(j) {
  if (booleano(j, "ok") !== true) {
    throw new ErrorDeContrato("la CLI contestó ok: false y eso no es un sellado");
  }
  const attestation = unoDe(j, "attestation", ["none", "unverified", "verified"]);
  const attested = booleano(j, "attested");
  if (attested !== (attestation === "verified")) {
    throw new ErrorDeContrato(`la salida se contradice: attested = ${attested} con attestation = ${attestation}`);
  }
  entero(j, "attested_size");
  return {
    index: entero(j, "index"),
    hash: hex64(j, "hash"),
    payloadHash: hex64(j, "payload_hash"),
    encrypted: booleano(j, "encrypted"),
    idempotent: booleano(j, "idempotent"),
    duplicateOf: listaDeEnteros(j, "duplicate_of"),
    attestation,
    attested,
    // attested_head es de septiembre de 2026 (ensayo de operación): un binario anterior
    // no lo trae, y por eso se lee como opcional. Es la diferencia entre un campo que
    // el contrato promete y uno que se añadió después.
    attestedHead: Object.prototype.hasOwnProperty.call(j, "attested_head") ? booleano(j, "attested_head") : null,
    signerVerified: booleano(firmante(j), "verified"),
    stale: booleano(frescura(j), "stale"),
    rollback: Object.prototype.hasOwnProperty.call(j, "rollback") ? objeto(j, "rollback") : null,
    raw: j,
  };
}

/** estado lee la salida de `status`, que es lo que mira un cron. */
export function estado(j) {
  booleano(j, "ok");
  cadena(j, "dir", { vacia: false });
  cadena(j, "origin", { vacia: false });
  cadena(j, "leaf_rule", { vacia: false });
  hex64(j, "log_pubkey");
  hex64(j, "root");
  const attestation = unoDe(j, "attestation", ["none", "unverified", "verified"]);
  return {
    treeSize: entero(j, "tree_size"),
    origin: j.origin,
    logPubkey: j.log_pubkey,
    attestation,
    attested: booleano(j, "attested"),
    attestedSize: entero(j, "attested_size"),
    attestedHead: Object.prototype.hasOwnProperty.call(j, "attested_head") ? booleano(j, "attested_head") : null,
    signer: firmante(j),
    freshness: frescura(j),
    rollback: Object.prototype.hasOwnProperty.call(j, "rollback") ? objeto(j, "rollback") : null,
    raw: j,
  };
}

/**
 * cotejo lee el informe de `reconcile`.
 *
 * `findings` se lee como array SIN tolerancias: el contrato promete un array y desde
 * septiembre de 2026 lo cumple también cuando está vacío. Antes entregaba `null` en el
 * caso bueno, y este lector fue el que lo descubrió.
 */
export function cotejo(j) {
  const bruto = j.findings;
  if (!Array.isArray(bruto)) {
    throw new ErrorDeContrato(`findings tiene que ser un array y llegó ${bruto === null ? "null" : typeof bruto}`);
  }
  const hallazgos = bruto.map((f, i) => {
    if (f === null || typeof f !== "object" || Array.isArray(f)) {
      throw new ErrorDeContrato(`findings[${i}] no es un objeto`);
    }
    return {
      estado: unoDe(f, "status", ["discrepancia", "faltante", "no sellado"]),
      // El índice va siempre, incluido el 0.
      bloque: entero(f, "index"),
      hashSellado: f.status === "no sellado" ? null : hex64(f, "sealed_hash"),
      hashActual: f.status === "faltante" ? null : hex64(f, "current_hash"),
      selladoEn: f.sealed_at ?? null,
      tenant: f.tenant ?? null,
      tipo: f.type ?? null,
    };
  });
  return {
    cuadra: booleano(j, "ok"),
    treeSize: entero(j, "tree_size"),
    comparados: entero(j, "checked"),
    coincidentes: entero(j, "verified"),
    hallazgos,
    // full_verify sale salvo con --full=false, y en reconcile --full es el valor por
    // omisión: el cotejo recomprueba todas las firmas históricas.
    verificacionCompleta: Object.prototype.hasOwnProperty.call(j, "full_verify")
      ? { ejecutada: booleano(objeto(j, "full_verify"), "run"), ok: booleano(objeto(j, "full_verify"), "ok") }
      : null,
    raw: j,
  };
}

/** error lee el objeto de error de la CLI, que también es contrato. */
export function errorDeLaCLI(j) {
  if (booleano(j, "ok") !== false) throw new ErrorDeContrato("el objeto de error tiene que llevar ok: false");
  const code = entero(j, "exit_code", 1);
  if (![1, 2, 3].includes(code)) {
    throw new ErrorDeContrato(`exit_code = ${code}, y los códigos son 1, 2 y 3`);
  }
  return { error: cadena(j, "error", { vacia: false }), exitCode: code };
}
