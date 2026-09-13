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
  /** witnesses mapea nombre de testigo → clave pública en hexadecimal (minúsculas). */
  witnesses: Record<string, string>;
  /** quorum es el mínimo de testigos distintos cuya cosignature tiene que verificar. */
  quorum: number;
}

/** MAX_POLICY_BYTES es el tamaño máximo de un documento de política. */
export const MAX_POLICY_BYTES = 65536;

const MIEMBROS = ["origin", "logKey", "signerKey", "witnesses", "quorum"];

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
  if (utf8(text).length > MAX_POLICY_BYTES) {
    throw new Error(`la política mide más de ${MAX_POLICY_BYTES} bytes`);
  }
  if (text.charCodeAt(0) === 0xfeff) throw new Error("la política empieza con BOM");
  for (let i = 0; i < text.length; i++) {
    const c = text.charCodeAt(i);
    if (c >= 0xd800 && c <= 0xdbff) {
      const d = text.charCodeAt(i + 1);
      if (!(d >= 0xdc00 && d <= 0xdfff)) throw new Error("la política no es Unicode válido");
      i++;
    } else if (c >= 0xdc00 && c <= 0xdfff) {
      throw new Error("la política no es Unicode válido");
    }
  }
  const p = new Lector(text);
  p.espacios();
  if (p.s[p.i] !== "{") throw new Error("el documento tiene que ser un objeto JSON");
  const obj = p.objeto(1);
  p.espacios();
  if (p.i !== p.s.length) throw new Error(`hay contenido después del objeto (posición ${p.i})`);
  return construir(obj);
}

class Lector {
  i = 0;
  constructor(readonly s: string) {}

  err(msg: string): Error {
    return new Error(`${msg} (posición ${this.i})`);
  }

  espacios(): void {
    while (this.i < this.s.length) {
      const c = this.s[this.i];
      if (c === " " || c === "\t" || c === "\n" || c === "\r") this.i++;
      else return;
    }
  }

  objeto(profundidad: number): Array<{ nombre: string; valor: Valor }> {
    if (profundidad > 2) throw this.err("objeto anidado donde la política no admite ninguno");
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
      if (vistos.has(nombre)) throw this.err(`el miembro ${JSON.stringify(nombre)} está repetido`);
      vistos.add(nombre);
      this.espacios();
      if (this.s[this.i] !== ":") throw this.err("se esperaba ':'");
      this.i++;
      this.espacios();
      out.push({ nombre, valor: this.valor(profundidad) });
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
    throw this.err("valor no admitido en una política (solo cadenas, números y el objeto de testigos)");
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
              throw this.err("surrogate UTF-16 alto sin su pareja");
            }
            this.i += 2;
            const bajo = this.hex4();
            if (bajo < 0xdc00 || bajo > 0xdfff) throw this.err("surrogate UTF-16 alto sin su pareja");
            out += String.fromCharCode(u, bajo);
          } else if (u >= 0xdc00 && u <= 0xdfff) {
            throw this.err("surrogate UTF-16 bajo suelto");
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
    if (this.s[this.i] === "0") this.i++;
    else if (digitos() === 0) throw this.err("número mal formado");
    if (this.s[this.i] === ".") {
      this.i++;
      if (digitos() === 0) throw this.err("número mal formado");
    }
    if (this.s[this.i] === "e" || this.s[this.i] === "E") {
      this.i++;
      if (this.s[this.i] === "+" || this.s[this.i] === "-") this.i++;
      if (digitos() === 0) throw this.err("número mal formado");
    }
    return this.s.slice(ini, this.i);
  }
}

const HEX_CLAVE = /^[0-9a-f]{64}$/;

function construir(obj: Array<{ nombre: string; valor: Valor }>): Policy {
  const tiene = new Set<string>();
  let origin = "";
  let logKey = "";
  let signerKey: string | undefined;
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
      if (variante) throw new Error(`el miembro ${JSON.stringify(nombre)} es una variante de mayúsculas de ${JSON.stringify(variante)}`);
      throw new Error(`miembro desconocido ${JSON.stringify(nombre)}`);
    }
    tiene.add(nombre);
    switch (nombre) {
      case "origin":
        if (valor.tipo !== "s" || valor.cadena === "") throw new Error("origin tiene que ser una cadena no vacía");
        origin = valor.cadena;
        break;
      case "logKey":
      case "signerKey":
        if (valor.tipo !== "s" || !HEX_CLAVE.test(valor.cadena)) {
          throw new Error(`${nombre} tiene que ser una clave de 64 caracteres hexadecimales en minúsculas`);
        }
        if (nombre === "logKey") logKey = valor.cadena;
        else signerKey = valor.cadena;
        break;
      case "witnesses": {
        if (valor.tipo !== "o") throw new Error("witnesses tiene que ser un objeto");
        if (valor.miembros.length === 0) throw new Error("no trae ningún testigo; sin testigos no verifica nada");
        const porClave = new Map<string, string>();
        for (const w of valor.miembros) {
          if (w.nombre === "") throw new Error("un testigo sin nombre");
          if (w.valor.tipo !== "s" || !HEX_CLAVE.test(w.valor.cadena)) {
            throw new Error(`la clave del testigo ${JSON.stringify(w.nombre)} tiene que ser de 64 caracteres hexadecimales en minúsculas`);
          }
          const otro = porClave.get(w.valor.cadena);
          if (otro !== undefined) {
            throw new Error(`la misma clave está bajo dos nombres (${JSON.stringify(otro)} y ${JSON.stringify(w.nombre)})`);
          }
          porClave.set(w.valor.cadena, w.nombre);
          witnesses[w.nombre] = w.valor.cadena;
        }
        nTestigos = valor.miembros.length;
        break;
      }
      case "quorum":
        if (valor.tipo !== "n") throw new Error("quorum tiene que ser un número entero");
        quorum = valor.numero;
        break;
    }
  }
  for (const req of ["origin", "logKey", "witnesses", "quorum"]) {
    if (!tiene.has(req)) throw new Error(`falta el miembro ${JSON.stringify(req)}`);
  }
  if (!/^(0|[1-9][0-9]*)$/.test(quorum)) throw new Error(`quorum ${quorum} no es un entero sin fracción ni exponente`);
  const q = quorum.length > 9 ? Infinity : Number(quorum);
  if (q < 1 || q > nTestigos) throw new Error(`quorum ${quorum} con ${nTestigos} testigos`);
  const out: Policy = { origin, logKey, witnesses, quorum: q };
  // Comprobación de que el mapa devuelto tiene EXACTAMENTE los testigos leídos: si
  // alguna clave se hubiera perdido por el camino, la política que se verifica no
  // sería la que se escribió.
  if (Object.keys(witnesses).length !== nTestigos) {
    throw new Error("el mapa de testigos perdió alguna clave al construirse");
  }
  if (signerKey !== undefined) out.signerKey = signerKey;
  return out;
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
