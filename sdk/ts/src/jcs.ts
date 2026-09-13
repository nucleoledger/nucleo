// Canonicalización JCS (RFC 8785), lo que el verificador necesita para el header.
//
// No se canonicaliza nada aquí: se COMPRUEBA que los bytes recibidos ya sean la forma
// canónica, que es la decisión del lado Go —los bytes exactos son lo firmado—.
//
// Antes esta comprobación era solo el ORDEN de las claves, con JSON.parse y
// Object.keys. La cuarta auditoría (H4.2) señaló lo que eso deja pasar: JSON.parse se
// queda con el último de dos miembros repetidos, y Object.keys no ve ni el espacio en
// blanco entre tokens ni un escape alternativo (A por "A"). Tres formas distintas
// de escribir el mismo objeto que Go rechazaría por no ser byte a byte la forma
// canónica. Ahora se lee el texto con un lector estricto —el mismo criterio que
// policy.ts (ADR-018)— y se vuelve a serializar en forma canónica para compararlo con
// lo que llegó.

/**
 * isCanonicalJCS dice si raw es EXACTAMENTE la serialización JCS de lo que
 * representa: sin espacio en blanco, claves ordenadas por unidades de código UTF-16,
 * sin miembros repetidos, escapes mínimos y enteros sin ceros ni exponente.
 *
 * El header de un bloque es un objeto plano de cadenas y un entero (PROTOCOL.md §1), y
 * eso es lo que se admite: un número que no sea entero seguro no es canonicalizable sin
 * reimplementar la serialización de números de RFC 8785, que es la parte difícil y la
 * que más se equivoca, así que se rechaza en vez de adivinarse.
 */
export function isCanonicalJCS(raw: string): boolean {
  // Todo dentro del try, serialización incluida: serializar lanza ante un número que
  // no se puede canonicalizar aquí, y esta función no puede lanzar nunca. La promesa
  // de verifyReceipt —"no lanza con ninguna entrada"— se sostiene sobre sus piezas.
  try {
    const l = new Lector(raw);
    const valor = l.valor(0);
    l.finDeTexto();
    // El header es un OBJETO (PROTOCOL.md §1): un array o un escalar canónicos no son
    // un header canónico.
    if (valor.t !== "o") return false;
    return serializar(valor) === raw;
  } catch {
    return false;
  }
}

type Valor =
  | { t: "s"; v: string }
  | { t: "n"; v: string }
  | { t: "o"; v: Array<{ k: string; v: Valor }> }
  | { t: "a"; v: Valor[] }
  | { t: "lit"; v: "true" | "false" | "null" };

class Lector {
  i = 0;
  constructor(readonly s: string) {}

  finDeTexto(): void {
    if (this.i !== this.s.length) throw new Error("sobra texto");
  }

  valor(prof: number): Valor {
    if (prof > 32) throw new Error("demasiada anidación");
    const c = this.s[this.i];
    if (c === '"') return { t: "s", v: this.cadena() };
    if (c === "{") return this.objeto(prof);
    if (c === "[") return this.array(prof);
    if (c === "-" || (c !== undefined && c >= "0" && c <= "9")) return { t: "n", v: this.numero() };
    for (const lit of ["true", "false", "null"] as const) {
      if (this.s.startsWith(lit, this.i)) {
        this.i += lit.length;
        return { t: "lit", v: lit };
      }
    }
    throw new Error("valor no reconocido");
  }

  objeto(prof: number): Valor {
    this.i++;
    const out: Array<{ k: string; v: Valor }> = [];
    const vistas = new Set<string>();
    if (this.s[this.i] === "}") {
      this.i++;
      return { t: "o", v: out };
    }
    for (;;) {
      if (this.s[this.i] !== '"') throw new Error("nombre de miembro");
      const k = this.cadena();
      // Un miembro repetido no tiene forma canónica: JSON.parse se quedaría con el
      // último y perdería la pregunta.
      if (vistas.has(k)) throw new Error("miembro repetido");
      vistas.add(k);
      if (this.s[this.i] !== ":") throw new Error("falta ':'");
      this.i++;
      out.push({ k, v: this.valor(prof + 1) });
      const c = this.s[this.i];
      if (c === ",") {
        this.i++;
        continue;
      }
      if (c === "}") {
        this.i++;
        return { t: "o", v: out };
      }
      throw new Error("falta ',' o '}'");
    }
  }

  array(prof: number): Valor {
    this.i++;
    const out: Valor[] = [];
    if (this.s[this.i] === "]") {
      this.i++;
      return { t: "a", v: out };
    }
    for (;;) {
      out.push(this.valor(prof + 1));
      const c = this.s[this.i];
      if (c === ",") {
        this.i++;
        continue;
      }
      if (c === "]") {
        this.i++;
        return { t: "a", v: out };
      }
      throw new Error("falta ',' o ']'");
    }
  }

  cadena(): string {
    this.i++;
    let out = "";
    for (;;) {
      const c = this.s[this.i];
      if (c === undefined) throw new Error("cadena sin cerrar");
      if (c === '"') {
        this.i++;
        return out;
      }
      if (c.charCodeAt(0) < 0x20) throw new Error("control sin escapar");
      if (c !== "\\") {
        out += c;
        this.i++;
        continue;
      }
      this.i++;
      const e = this.s[this.i];
      this.i++;
      const simples: Record<string, string> = { '"': '"', "\\": "\\", "/": "/", b: "\b", f: "\f", n: "\n", r: "\r", t: "\t" };
      if (e !== undefined && e in simples) {
        out += simples[e];
        continue;
      }
      if (e !== "u") throw new Error("escape desconocido");
      const h = this.s.slice(this.i, this.i + 4);
      if (!/^[0-9a-fA-F]{4}$/.test(h)) throw new Error("escape \\u inválido");
      this.i += 4;
      out += String.fromCharCode(parseInt(h, 16));
    }
  }

  numero(): string {
    const ini = this.i;
    if (this.s[this.i] === "-") this.i++;
    while (this.i < this.s.length && this.s[this.i]! >= "0" && this.s[this.i]! <= "9") this.i++;
    if (this.i === ini) throw new Error("número vacío");
    // La fracción y el exponente se consumen para que el texto se lea entero; la
    // serialización los rechaza después, porque canonicalizarlos exige el algoritmo
    // de números de RFC 8785.
    if (this.s[this.i] === ".") {
      this.i++;
      while (this.i < this.s.length && this.s[this.i]! >= "0" && this.s[this.i]! <= "9") this.i++;
    }
    if (this.s[this.i] === "e" || this.s[this.i] === "E") {
      this.i++;
      if (this.s[this.i] === "+" || this.s[this.i] === "-") this.i++;
      while (this.i < this.s.length && this.s[this.i]! >= "0" && this.s[this.i]! <= "9") this.i++;
    }
    return this.s.slice(ini, this.i);
  }
}

/** serializar devuelve la forma canónica JCS del valor leído. */
function serializar(v: Valor): string {
  switch (v.t) {
    case "s":
      return escapar(v.v);
    case "n":
      // Solo enteros seguros: es lo que el header usa (index ≤ 2^53-1).
      if (!/^-?(0|[1-9][0-9]*)$/.test(v.v) || !Number.isSafeInteger(Number(v.v))) {
        throw new Error("número no canonicalizable aquí");
      }
      return v.v;
    case "lit":
      return v.v;
    case "a":
      return "[" + v.v.map(serializar).join(",") + "]";
    case "o": {
      const miembros = [...v.v].sort((a, b) => compareUTF16(a.k, b.k));
      return "{" + miembros.map((m) => escapar(m.k) + ":" + serializar(m.v)).join(",") + "}";
    }
  }
}

/** escapar aplica los escapes mínimos de RFC 8785 §3.2.2.2. */
function escapar(s: string): string {
  let out = '"';
  for (const ch of s) {
    const c = ch.codePointAt(0)!;
    if (ch === '"') out += '\\"';
    else if (ch === "\\") out += "\\\\";
    else if (ch === "\b") out += "\\b";
    else if (ch === "\f") out += "\\f";
    else if (ch === "\n") out += "\\n";
    else if (ch === "\r") out += "\\r";
    else if (ch === "\t") out += "\\t";
    else if (c < 0x20) out += "\\u" + c.toString(16).padStart(4, "0");
    else out += ch;
  }
  return out + '"';
}

/** compareUTF16 ordena por unidades de código, como manda RFC 8785. */
function compareUTF16(a: string, b: string): number {
  const n = Math.min(a.length, b.length);
  for (let i = 0; i < n; i++) {
    const d = a.charCodeAt(i) - b.charCodeAt(i);
    if (d !== 0) return d;
  }
  return a.length - b.length;
}
