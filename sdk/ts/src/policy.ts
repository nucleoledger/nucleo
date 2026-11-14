// La política de verificación como formato de cable (PROTOCOL.md §3.2, ADR-018).
//
// Gemelo de internal/policy en Go, y con la misma gramática escrita a mano. No se
// usa JSON.parse para leer el texto: cuando devuelve, un miembro duplicado ya se ha
// perdido —se queda con el último, en silencio—, y la tercera auditoría usó
// exactamente eso: {"signerKey": A, "signerkey": B} daba una clave a la CLI y otra a
// la página. Los dos lectores pasan por testdata/vectors/policy/ y por el
// diferencial.

import { utf8 } from "./bytes.js";

/** Policy es lo que quien verifica debe conocer de antemano. */
export interface Policy {
  /** origin es el identificador del log esperado. */
  origin: string;
  /** logKey en hexadecimal (minúsculas): la pública Ed25519 del log. */
  logKey: string;
  /**
   * signerKey en hexadecimal (minúsculas): la pública Ed25519 del tenant que FIRMA
   * LOS BLOQUES. Opcional en el formato; obligatoria para verificar un recibo
   * (ADR-017): sin ella, "firmado por el emisor" sería lo que el recibo dice de sí
   * mismo.
   */
  signerKey?: string;
  /**
   * erasureKey en hexadecimal (minúsculas): la pública Ed25519 que autoriza las
   * supresiones (ADR-032). Opcional, y distinta de todas las demás claves del
   * documento. Este verificador la lee y no la usa: un recibo no depende de ella.
   */
  erasureKey?: string;
  /**
   * retiredErasureKeys mapea cada clave de supresión retirada (hexadecimal en
   * minúsculas) a su corte: el índice del último evento de supresión que todavía
   * autoriza (ADR-033, PROTOCOL 0.8-draft §3.2). Opcional; si viene, no está vacío.
   * Este verificador la lee con la gramática de Go y no la usa: no implementa
   * supresión, y un recibo no depende de ella.
   */
  retiredErasureKeys?: Record<string, number>;
  /**
   * logMLDSAKey es la clave pública ML-DSA-44 del log, 2624 caracteres hexadecimales
   * en minúsculas (ADR-034, PROTOCOL 0.8-draft §3.2). Con ella, todo recibo tiene que
   * traer al menos una línea de esa clave y todas tienen que medir 2420 bytes; este
   * verificador NO verifica la firma (no implementa ML-DSA-44) y lo dice: logMLDSA es
   * "present-unverified", nunca "verified".
   */
  logMLDSAKey?: string;
  /** witnesses mapea nombre de testigo → clave pública en hexadecimal (minúsculas). */
  witnesses: Record<string, string>;
  /** quorum es el mínimo de testigos distintos cuya cosignature tiene que verificar. */
  quorum: number;
}

/** MAX_POLICY_BYTES es el tamaño máximo de un documento de política. */
export const MAX_POLICY_BYTES = 65536;

/** MAX_CUTOFF es el mayor corte de una clave retirada: 2^53 − 1 (PROTOCOL §1). */
export const MAX_CUTOFF = Number.MAX_SAFE_INTEGER;

/** LARGO_MLDSA es la longitud en hexadecimal de una clave pública ML-DSA-44: 1312 bytes. */
const LARGO_MLDSA = 2 * 1312;

const MIEMBROS = ["origin", "logKey", "signerKey", "erasureKey", "retiredErasureKeys", "logMLDSAKey", "witnesses", "quorum"];

/**
 * PolicyError es el rechazo de una política. reason es el nombre del motivo: el mismo que
 * el "reason" de los vectores de testdata/vectors/policy/ y que internal/policy.Motivo en
 * Go («hex», «quorum», «cutoff», «duplicate_member»…). El mensaje es para personas; el
 * motivo, para comparar.
 */
export class PolicyError extends Error {
  readonly reason: string;
  constructor(reason: string, message: string) {
    super(message);
    this.name = "PolicyError";
    this.reason = reason;
  }
}

/**
 * Las clases de error del lector, las de internal/estricto en Go. El motivo de un error
 * del lector depende de la clase y de la ruta —qué miembro se estaba leyendo—, con la
 * regla de internal/policy.Motivo: lo que está mal en origin, en quorum o en un corte es
 * de ese miembro, sea del tipo que sea; en lo demás, un null es un null y el resto es un
 * tipo equivocado.
 */
type Clase =
  | "tamaño" | "utf8" | "bom" | "no-objeto" | "sintaxis" | "número" | "detrás"
  | "repetido" | "surrogate" | "null" | "booleano" | "array" | "anidado";

function motivoDelLector(clase: Clase, ruta: readonly string[]): string {
  const deCorte = ruta.length === 2 && ruta[0] === "retiredErasureKeys";
  switch (clase) {
    case "tamaño":
      return "size";
    case "bom":
      return "bom";
    case "no-objeto":
      return "type";
    case "detrás":
      return "trailing";
    case "repetido":
      return "duplicate_member";
    case "surrogate":
      return "surrogate";
    case "número":
      if (ruta[0] === "quorum") return "quorum";
      if (deCorte) return "cutoff";
      return "syntax";
    case "null":
    case "booleano":
    case "array":
    case "anidado":
      if (ruta[0] === "origin") return "origin";
      if (ruta[0] === "quorum") return "quorum";
      if (deCorte) return "cutoff";
      return clase === "null" ? "null" : "type";
    default:
      return "syntax";
  }
}

/** errLector es un error del lector con su motivo. */
function errLector(clase: Clase, ruta: readonly string[], msg: string): PolicyError {
  return new PolicyError(motivoDelLector(clase, ruta), msg);
}

/** rechazo es un error de la tabla de §3.2 con su motivo. */
function rechazo(reason: string, msg: string): PolicyError {
  return new PolicyError(reason, msg);
}

type Valor =
  | { tipo: "s"; cadena: string }
  | { tipo: "n"; numero: string }
  | { tipo: "o"; miembros: Array<{ nombre: string; valor: Valor }> };

/**
 * parsePolicyText lee y valida el TEXTO de una política. Lanza con el motivo si el
 * documento no cumple PROTOCOL.md §3.2. Es lo que la página usa con lo que se pega
 * en el formulario, y lo que un integrador debe usar con un fichero.
 */
export function parsePolicyText(text: string): Policy {
  // El orden de las tres primeras comprobaciones es el de internal/estricto: tamaño,
  // codificación, BOM. Decide el motivo de un documento que falla dos a la vez.
  if (utf8(text).length > MAX_POLICY_BYTES) {
    throw errLector("tamaño", [], `la política mide más de ${MAX_POLICY_BYTES} bytes`);
  }
  for (let i = 0; i < text.length; i++) {
    const c = text.charCodeAt(i);
    if (c >= 0xd800 && c <= 0xdbff) {
      const d = text.charCodeAt(i + 1);
      if (!(d >= 0xdc00 && d <= 0xdfff)) throw errLector("utf8", [], "la política no es Unicode válido");
      i++;
    } else if (c >= 0xdc00 && c <= 0xdfff) {
      throw errLector("utf8", [], "la política no es Unicode válido");
    }
  }
  if (text.charCodeAt(0) === 0xfeff) throw errLector("bom", [], "la política empieza con BOM");
  const p = new Lector(text);
  p.espacios();
  if (p.s[p.i] !== "{") {
    // Otro valor JSON en vez del objeto es un tipo equivocado; lo que no empieza como
    // ningún valor —vacío, un comentario— no es JSON.
    const c = p.s[p.i];
    const clase: Clase = c !== undefined && '["-0123456789tfn'.includes(c) ? "no-objeto" : "sintaxis";
    throw errLector(clase, [], "el documento tiene que ser un objeto JSON");
  }
  const obj = p.objeto(1);
  p.espacios();
  if (p.i !== p.s.length) throw errLector("detrás", [], `hay contenido después del objeto (posición ${p.i})`);
  return construir(obj);
}

class Lector {
  i = 0;
  /** ruta son los nombres de los miembros que se están leyendo, desde el documento. */
  ruta: string[] = [];
  constructor(readonly s: string) {}

  err(msg: string, clase: Clase = "sintaxis"): PolicyError {
    return errLector(clase, this.ruta, `${msg} (posición ${this.i})`);
  }

  espacios(): void {
    while (this.i < this.s.length) {
      const c = this.s[this.i];
      if (c === " " || c === "\t" || c === "\n" || c === "\r") this.i++;
      else return;
    }
  }

  objeto(profundidad: number): Array<{ nombre: string; valor: Valor }> {
    if (profundidad > 2) throw this.err("objeto anidado donde la política no admite ninguno", "anidado");
    this.i++; // '{'
    const out: Array<{ nombre: string; valor: Valor }> = [];
    const vistos = new Set<string>();
    this.espacios();
    if (this.s[this.i] === "}") {
      this.i++;
      return out;
    }
    for (;;) {
      this.espacios();
      if (this.s[this.i] !== '"') throw this.err("se esperaba el nombre de un miembro");
      const nombre = this.cadena();
      if (vistos.has(nombre)) throw this.err(`el miembro ${JSON.stringify(nombre)} está repetido`, "repetido");
      vistos.add(nombre);
      this.espacios();
      if (this.s[this.i] !== ":") throw this.err("se esperaba ':'");
      this.i++;
      this.espacios();
      this.ruta.push(nombre);
      out.push({ nombre, valor: this.valor(profundidad) });
      this.ruta.pop();
      this.espacios();
      const c = this.s[this.i];
      if (c === ",") this.i++;
      else if (c === "}") {
        this.i++;
        return out;
      } else if (c === undefined) throw this.err("objeto sin cerrar");
      else throw this.err("se esperaba ',' o '}'");
    }
  }

  valor(profundidad: number): Valor {
    const c = this.s[this.i];
    if (c === undefined) throw this.err("falta un valor");
    if (c === '"') return { tipo: "s", cadena: this.cadena() };
    if (c === "{") return { tipo: "o", miembros: this.objeto(profundidad + 1) };
    if (c === "-" || (c >= "0" && c <= "9")) return { tipo: "n", numero: this.numero() };
    throw this.err(
      "valor no admitido en una política (solo cadenas, números y los objetos de testigos y de claves retiradas)",
      this.claseDeValor(),
    );
  }

  /** claseDeValor dice qué hay en la posición actual cuando no es cadena, número ni objeto. */
  claseDeValor(): Clase {
    const resto = this.s.slice(this.i, this.i + 5);
    if (resto.startsWith("null")) return "null";
    if (resto.startsWith("true") || resto.startsWith("false")) return "booleano";
    if (resto[0] === "[") return "array";
    return "sintaxis";
  }

  /** cadena lee una cadena JSON; rechaza surrogates sueltos escritos con \u. */
  cadena(): string {
    this.i++; // '"'
    let out = "";
    for (;;) {
      if (this.i >= this.s.length) throw this.err("cadena sin cerrar");
      const c = this.s[this.i]!;
      const code = c.charCodeAt(0);
      if (c === '"') {
        this.i++;
        return out;
      }
      if (code < 0x20) throw this.err("carácter de control sin escapar dentro de una cadena");
      if (c !== "\\") {
        out += c;
        this.i++;
        continue;
      }
      this.i++;
      const e = this.s[this.i];
      this.i++;
      switch (e) {
        case '"':
        case "\\":
        case "/":
          out += e;
          break;
        case "b":
          out += "\b";
          break;
        case "f":
          out += "\f";
          break;
        case "n":
          out += "\n";
          break;
        case "r":
          out += "\r";
          break;
        case "t":
          out += "\t";
          break;
        case "u": {
          const u = this.hex4();
          if (u >= 0xd800 && u <= 0xdbff) {
            if (this.s[this.i] !== "\\" || this.s[this.i + 1] !== "u") {
              throw this.err("surrogate UTF-16 alto sin su pareja", "surrogate");
            }
            this.i += 2;
            const bajo = this.hex4();
            if (bajo < 0xdc00 || bajo > 0xdfff) throw this.err("surrogate UTF-16 alto sin su pareja", "surrogate");
            out += String.fromCharCode(u, bajo);
          } else if (u >= 0xdc00 && u <= 0xdfff) {
            throw this.err("surrogate UTF-16 bajo suelto", "surrogate");
          } else {
            out += String.fromCharCode(u);
          }
          break;
        }
        default:
          throw this.err(`escape desconocido \\${e ?? ""}`);
      }
    }
  }

  hex4(): number {
    const h = this.s.slice(this.i, this.i + 4);
    if (!/^[0-9a-fA-F]{4}$/.test(h)) throw this.err("escape \\u con dígitos no hexadecimales");
    this.i += 4;
    return parseInt(h, 16);
  }

  /** numero lee un número con la gramática de RFC 8259 y devuelve el literal. */
  numero(): string {
    const ini = this.i;
    const digitos = (): number => {
      let n = 0;
      while (this.i < this.s.length && this.s[this.i]! >= "0" && this.s[this.i]! <= "9") {
        this.i++;
        n++;
      }
      return n;
    };
    if (this.s[this.i] === "-") this.i++;
    if (this.s[this.i] === "0") {
      this.i++;
      // RFC 8259 no admite ceros a la izquierda; como en Go, el error es del número —y
      // del miembro que lo lleva—, no un separador que falta después.
      const d = this.s[this.i];
      if (d !== undefined && d >= "0" && d <= "9") throw this.err("número con un cero a la izquierda", "número");
    } else if (digitos() === 0) throw this.err("número mal formado", "número");
    if (this.s[this.i] === ".") {
      this.i++;
      if (digitos() === 0) throw this.err("número mal formado", "número");
    }
    if (this.s[this.i] === "e" || this.s[this.i] === "E") {
      this.i++;
      if (this.s[this.i] === "+" || this.s[this.i] === "-") this.i++;
      if (digitos() === 0) throw this.err("número mal formado", "número");
    }
    return this.s.slice(ini, this.i);
  }
}

const HEX_CLAVE = /^[0-9a-f]{64}$/;
const HEX_MINUSCULAS = /^[0-9a-f]*$/;

/**
 * motivoDeClave es el motivo de un valor que tenía que ser una clave en hexadecimal: un
 * objeto es otro tipo; un número o una cadena que no es la clave, una clave mal escrita.
 * (El null, el booleano y el array los rechaza antes el lector.)
 */
function motivoDeClave(v: Valor): string {
  return v.tipo === "o" ? "type" : "hex";
}

/** recorta acorta un valor del documento para un mensaje. */
function recorta(s: string): string {
  return s.length <= 24 ? s : s.slice(0, 24) + "…";
}

/**
 * corte lee el corte de una clave retirada: el literal 0|[1-9][0-9]*, sin signo, sin
 * fracción, sin exponente, como mucho 2^53 − 1. null si no lo es.
 */
function corte(s: string): number | null {
  if (!/^(0|[1-9][0-9]*)$/.test(s) || s.length > 16) return null;
  const c = Number(s);
  return c <= MAX_CUTOFF ? c : null;
}

function construir(obj: Array<{ nombre: string; valor: Valor }>): Policy {
  const tiene = new Set<string>();
  let origin = "";
  let logKey = "";
  let signerKey: string | undefined;
  let erasureKey: string | undefined;
  let logMLDSAKey: string | undefined;
  let retiradas: Record<string, number> | undefined;
  // Object.create(null) y no {}: con un objeto normal, asignar la clave "__proto__"
  // NO crea un miembro, cambia el prototipo, y ese testigo desaparecía del mapa sin
  // un solo error (H5 de la cuarta auditoría). Un nombre de testigo es texto que
  // elige quien escribe la política, y "__proto__" es un nombre válido para
  // c2sp.org/signed-note.
  const witnesses: Record<string, string> = Object.create(null) as Record<string, string>;
  let quorum = "";
  let nTestigos = 0;
  for (const { nombre, valor } of obj) {
    if (!MIEMBROS.includes(nombre)) {
      const variante = MIEMBROS.find((k) => k.toLowerCase() === asciiMinusculas(nombre));
      if (variante) {
        throw rechazo("case_variant", `el miembro ${JSON.stringify(nombre)} es una variante de mayúsculas de ${JSON.stringify(variante)}`);
      }
      throw rechazo("unknown_member", `miembro desconocido ${JSON.stringify(nombre)}`);
    }
    tiene.add(nombre);
    switch (nombre) {
      case "origin":
        if (valor.tipo !== "s" || valor.cadena === "") throw rechazo("origin", "origin tiene que ser una cadena no vacía");
        origin = valor.cadena;
        break;
      case "logKey":
      case "signerKey":
      case "erasureKey":
        if (valor.tipo !== "s" || !HEX_CLAVE.test(valor.cadena)) {
          throw rechazo(motivoDeClave(valor), `${nombre} tiene que ser una clave de 64 caracteres hexadecimales en minúsculas`);
        }
        if (nombre === "logKey") logKey = valor.cadena;
        else if (nombre === "signerKey") signerKey = valor.cadena;
        else erasureKey = valor.cadena;
        break;
      case "retiredErasureKeys": {
        // ADR-033 §A: un objeto con al menos un miembro; cada nombre, una clave Ed25519
        // en hexadecimal en minúsculas; cada valor, su corte. Una clave repetida ya la
        // rechazó el lector: es un nombre repetido.
        if (valor.tipo !== "o") throw rechazo("type", "retiredErasureKeys tiene que ser un objeto {clave: corte}");
        if (valor.miembros.length === 0) {
          throw rechazo("no_retired_keys", "retiredErasureKeys vacío: significaría lo mismo que no ponerlo; quítalo");
        }
        const r: Record<string, number> = Object.create(null) as Record<string, number>;
        for (const m of valor.miembros) {
          if (!HEX_CLAVE.test(m.nombre)) {
            throw rechazo("hex", `la clave retirada ${JSON.stringify(recorta(m.nombre))} tiene que ser de 64 caracteres hexadecimales en minúsculas`);
          }
          if (m.valor.tipo !== "n") {
            throw rechazo("cutoff", `el corte de la clave retirada ${m.nombre.slice(0, 16)}… tiene que ser un número entero`);
          }
          const c = corte(m.valor.numero);
          if (c === null) {
            throw rechazo(
              "cutoff",
              `el corte ${recorta(m.valor.numero)} de la clave retirada ${m.nombre.slice(0, 16)}… no es un entero sin signo, sin fracción ni exponente, de como mucho 2^53 − 1`,
            );
          }
          r[m.nombre] = c;
        }
        retiradas = r;
        break;
      }
      case "logMLDSAKey":
        if (valor.tipo !== "s" || valor.cadena.length !== LARGO_MLDSA || !HEX_MINUSCULAS.test(valor.cadena)) {
          throw rechazo(
            motivoDeClave(valor),
            `logMLDSAKey tiene que ser la clave pública ML-DSA-44 del log: ${LARGO_MLDSA} caracteres hexadecimales en minúsculas`,
          );
        }
        logMLDSAKey = valor.cadena;
        break;
      case "witnesses": {
        if (valor.tipo !== "o") throw rechazo("type", "witnesses tiene que ser un objeto");
        if (valor.miembros.length === 0) throw rechazo("no_witnesses", "no trae ningún testigo; sin testigos no verifica nada");
        const porClave = new Map<string, string>();
        for (const w of valor.miembros) {
          if (w.nombre === "") throw rechazo("witness_name", "un testigo sin nombre");
          if (w.valor.tipo !== "s" || !HEX_CLAVE.test(w.valor.cadena)) {
            throw rechazo(
              motivoDeClave(w.valor),
              `la clave del testigo ${JSON.stringify(w.nombre)} tiene que ser de 64 caracteres hexadecimales en minúsculas`,
            );
          }
          const otro = porClave.get(w.valor.cadena);
          if (otro !== undefined) {
            throw rechazo("duplicate_key", `la misma clave está bajo dos nombres (${JSON.stringify(otro)} y ${JSON.stringify(w.nombre)})`);
          }
          porClave.set(w.valor.cadena, w.nombre);
          witnesses[w.nombre] = w.valor.cadena;
        }
        nTestigos = valor.miembros.length;
        break;
      }
      case "quorum":
        if (valor.tipo !== "n") throw rechazo("quorum", "quorum tiene que ser un número entero");
        quorum = valor.numero;
        break;
    }
  }
  for (const req of ["origin", "logKey", "witnesses", "quorum"]) {
    if (!tiene.has(req)) throw rechazo("missing", `falta el miembro ${JSON.stringify(req)}`);
  }
  if (!/^(0|[1-9][0-9]*)$/.test(quorum)) throw rechazo("quorum", `quorum ${quorum} no es un entero sin fracción ni exponente`);
  const q = quorum.length > 9 ? Infinity : Number(quorum);
  if (q < 1 || q > nTestigos) throw rechazo("quorum", `quorum ${quorum} con ${nTestigos} testigos`);
  const out: Policy = { origin, logKey, witnesses, quorum: q };
  // Comprobación de que el mapa devuelto tiene EXACTAMENTE los testigos leídos: si
  // alguna clave se hubiera perdido por el camino, la política que se verifica no
  // sería la que se escribió.
  if (Object.keys(witnesses).length !== nTestigos) {
    throw new Error("el mapa de testigos perdió alguna clave al construirse");
  }
  if (signerKey !== undefined) out.signerKey = signerKey;
  const testigosEnOrden = Object.keys(witnesses).sort(compara);
  if (erasureKey !== undefined) {
    // La clave de supresión no puede ser ninguna de las otras (ADR-032 §B): la del log y
    // la del firmante están en el servidor, y una clave de testigo tiene ya su papel.
    if (erasureKey === logKey) {
      throw rechazo("erasure_key_reused", "erasureKey es la clave del log; la clave de supresión no puede estar en el servidor");
    }
    if (erasureKey === signerKey) {
      throw rechazo("erasure_key_reused", "erasureKey es la clave del firmante; la clave de supresión no puede estar en el servidor");
    }
    for (const n of testigosEnOrden) {
      if (witnesses[n] === erasureKey) throw rechazo("erasure_key_reused", `erasureKey es la clave del testigo ${JSON.stringify(n)}`);
    }
    out.erasureKey = erasureKey;
  }
  if (retiradas !== undefined) {
    // La regla de separación de las claves retiradas (ADR-033 §A): ninguna puede ser la
    // erasureKey, la del log, la del firmante ni la de un testigo. Vale también sin
    // erasureKey. En el orden de Go: las claves ordenadas, y para cada una, esas cuatro.
    for (const k of Object.keys(retiradas).sort(compara)) {
      const ini = k.slice(0, 16);
      if (k === erasureKey) {
        throw rechazo("erasure_key_reused", `la clave retirada ${ini}… es la erasureKey: una clave no puede estar retirada y ser la actual`);
      }
      if (k === logKey) {
        throw rechazo("erasure_key_reused", `la clave retirada ${ini}… es la clave del log; una clave de supresión no puede estar en el servidor`);
      }
      if (k === signerKey) {
        throw rechazo("erasure_key_reused", `la clave retirada ${ini}… es la clave del firmante; una clave de supresión no puede estar en el servidor`);
      }
      for (const n of testigosEnOrden) {
        if (witnesses[n] === k) throw rechazo("erasure_key_reused", `la clave retirada ${ini}… es la clave del testigo ${JSON.stringify(n)}`);
      }
    }
    out.retiredErasureKeys = retiradas;
  }
  if (logMLDSAKey !== undefined) out.logMLDSAKey = logMLDSAKey;
  return out;
}

/**
 * compara ordena como slices.Sort de Go cuando todo es ASCII, que es el caso de las
 * claves; en los nombres de testigo solo decide el texto del error, no el motivo.
 */
function compara(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0;
}

/**
 * validatePolicy aplica las MISMAS reglas a una política que ya es un objeto —la
 * que construye un integrador en código—. No puede ver miembros duplicados, porque
 * un objeto de JavaScript no los tiene; todo lo demás, sí. Lanza con el motivo.
 */
export function validatePolicy(p: unknown): Policy {
  if (typeof p !== "object" || p === null || Array.isArray(p)) throw new Error("la política no es un objeto");
  // Se reconstruye el texto y se pasa por el lector: una sola definición de las
  // reglas. JSON.stringify de un objeto sin duplicados no puede introducirlos.
  let texto: string;
  try {
    texto = JSON.stringify(p);
  } catch (e) {
    throw new Error(`la política no se puede serializar: ${e instanceof Error ? e.message : String(e)}`);
  }
  return parsePolicyText(texto);
}

/** asciiMinusculas pasa a minúsculas solo A-Z: solo decide el texto del error. */
function asciiMinusculas(s: string): string {
  return s.replace(/[A-Z]/g, (c) => String.fromCharCode(c.charCodeAt(0) + 32));
}
