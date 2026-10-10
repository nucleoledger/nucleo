// valida.mjs — falla si un bloque ```mermaid de los ficheros dados no es Mermaid válido.
//
// El mapa del sistema (docs/ARQUITECTURA.md) tiene sus figuras en Mermaid, y Mermaid no
// avisa de nada al escribirlo: un bloque roto se ve como texto en GitHub y nadie lo nota
// hasta que alguien lo abre. El Sprint 16 las validaba con esta misma lógica desde un
// directorio temporal; el Sprint 17 la trae aquí, con su lockfile, y la pone en el CI.
//
// Usa el parser del propio Mermaid (mermaid.parse), el mismo que dibuja. Mermaid espera un
// navegador; jsdom le da lo justo para parsear, sin dibujar.
//
//   node valida.mjs ../../docs/ARQUITECTURA.md
//   node valida.mjs --autoprueba     # demuestra que un bloque roto se rechaza
//
// Un fichero sin bloques es un fallo: un validador que no encuentra nada no ha validado
// nada, y es justo lo que pasaría si cambiara la forma de abrir los bloques.
import { JSDOM } from "jsdom";
import fs from "node:fs";

const dom = new JSDOM("<!doctype html><html><body></body></html>");
globalThis.window = dom.window;
globalThis.document = dom.window.document;
globalThis.DOMParser = dom.window.DOMParser;
const { default: mermaid } = await import("mermaid");
mermaid.initialize({ startOnLoad: false });

// Los bloques de un Markdown. Admite CRLF: un checkout en Windows con autocrlf los trae así.
export function bloques(md) {
  return [...md.matchAll(/^```mermaid\r?\n([\s\S]*?)^```/gm)].map((m) => m[1]);
}

async function esValido(b) {
  try {
    await mermaid.parse(b);
    return null;
  } catch (e) {
    return String(e?.message ?? e).split("\n").slice(0, 3).join(" | ");
  }
}

async function autoprueba() {
  const bueno = "```mermaid\nflowchart LR\n  a --> b\n```\n";
  const roto = "```mermaid\nflowchart LR\n  a --> \n  b -->> --> c[\n```\n";
  const crlf = bueno.replaceAll("\n", "\r\n");
  const casos = [
    ["un bloque válido pasa", bueno, 1, true],
    ["un bloque roto se rechaza", roto, 1, false],
    ["un bloque con CRLF se encuentra y pasa", crlf, 1, true],
    ["un texto sin bloques no tiene bloques", "texto\n```js\nx\n```\n", 0, true],
  ];
  let mal = 0;
  for (const [nombre, md, n, valido] of casos) {
    const bs = bloques(md);
    const errores = await Promise.all(bs.map(esValido));
    const ok = bs.length === n && errores.every((e) => (e === null) === valido);
    if (!ok) mal++;
    console.log(`${ok ? "✔" : "✘"} autoprueba: ${nombre}`);
  }
  return mal;
}

const args = process.argv.slice(2);
if (args.length === 0) {
  console.error("uso: node valida.mjs <fichero.md>… | --autoprueba");
  process.exit(1);
}

let fallos = 0;
let total = 0;
if (args.includes("--autoprueba")) {
  fallos += await autoprueba();
}
for (const f of args.filter((a) => a !== "--autoprueba")) {
  const bs = bloques(fs.readFileSync(f, "utf8"));
  if (bs.length === 0) {
    fallos++;
    console.log(`✘ ${f}: no tiene ningún bloque mermaid`);
  }
  for (const [i, b] of bs.entries()) {
    total++;
    const err = await esValido(b);
    if (err) fallos++;
    console.log(err ? `✘ ${f} bloque ${i + 1}: ${err}` : `✔ ${f} bloque ${i + 1}: ${b.split(/\r?\n/)[0]}`);
  }
}
console.log(`${total} bloques, ${fallos} fallos`);
process.exit(fallos ? 1 : 0);
