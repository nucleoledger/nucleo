// El HTML. Sin plantillas, sin framework y sin red: son cadenas.
//
// La regla de diseño de estas páginas es una sola: EL COMANDO SE VE. Cada pantalla
// enseña la orden de `nucleo` que ejecutó y la respuesta que recibió, porque el
// integrador que mira este ejemplo no viene a aprender un ERP, viene a ver qué hace
// Núcleo y cómo lo llamaría desde el suyo. Un ejemplo que esconde el comando detrás de
// una abstracción bonita le quita justo lo que buscaba.

/** esc escapa para HTML. Todo lo que venga de datos pasa por aquí. */
export function esc(s) {
  return String(s ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
}

const CSS = `
:root {
  --fondo: #fbfaf8; --papel: #fff; --tinta: #1a1a1a; --suave: #5c5c5c;
  --linea: #e3e0da; --acento: #7a5cff; --ok: #0a7d4b; --mal: #b3261e; --medio: #8a6100;
  --codigo: #f4f2ee;
}
@media (prefers-color-scheme: dark) {
  :root:not([data-theme="light"]) {
    --fondo: #16161a; --papel: #1d1d22; --tinta: #ecebe8; --suave: #a3a2a0;
    --linea: #33333a; --acento: #a892ff; --ok: #4cc38a; --mal: #ff8a80; --medio: #e3b341;
    --codigo: #111115;
  }
}
* { box-sizing: border-box; }
body {
  margin: 0; background: var(--fondo); color: var(--tinta);
  font: 16px/1.55 system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
}
.marco { max-width: 860px; margin: 0 auto; padding: 24px 16px 64px; }
header.barra { border-bottom: 1px solid var(--linea); margin-bottom: 24px; }
header.barra h1 { font-size: 20px; margin: 0 0 4px; }
header.barra p { color: var(--suave); margin: 0 0 12px; font-size: 14px; }
nav a { color: var(--tinta); text-decoration: none; padding: 8px 0; margin-right: 18px;
  display: inline-block; border-bottom: 2px solid transparent; font-size: 15px; }
nav a.activo { border-color: var(--acento); }
nav a:hover { border-color: var(--linea); }
h2 { font-size: 17px; margin: 28px 0 10px; }
.tarjeta { background: var(--papel); border: 1px solid var(--linea); border-radius: 10px;
  padding: 16px; margin: 0 0 16px; }
pre, code, .cmd { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }
pre { background: var(--codigo); border: 1px solid var(--linea); border-radius: 8px;
  padding: 12px; overflow-x: auto; font-size: 13px; margin: 8px 0; }
pre.recibo { max-height: 340px; overflow-y: auto; white-space: pre; }
.cmd { display: block; background: var(--codigo); border-left: 3px solid var(--acento);
  border-radius: 4px; padding: 10px 12px; font-size: 13px; overflow-x: auto;
  white-space: pre-wrap; word-break: break-all; margin: 8px 0; }
.cmd::before { content: "$ "; color: var(--suave); }
table { border-collapse: collapse; width: 100%; font-size: 14px; }
th, td { text-align: left; padding: 8px 10px; border-bottom: 1px solid var(--linea);
  vertical-align: top; }
th { color: var(--suave); font-weight: 600; }
td.num, th.num { text-align: right; font-variant-numeric: tabular-nums; }
.ok { color: var(--ok); } .mal { color: var(--mal); } .medio { color: var(--medio); }
label { display: block; font-size: 14px; color: var(--suave); margin: 10px 0 4px; }
input, textarea, select { width: 100%; padding: 9px 10px; border: 1px solid var(--linea);
  border-radius: 8px; background: var(--papel); color: var(--tinta); font: inherit; }
textarea { min-height: 220px; font-family: ui-monospace, Menlo, Consolas, monospace;
  font-size: 12.5px; }
button, .boton {
  background: var(--acento); color: #fff; border: 0; border-radius: 8px;
  padding: 10px 16px; font: inherit; cursor: pointer; text-decoration: none;
  display: inline-block; margin: 12px 8px 0 0;
}
button.suave, .boton.suave { background: transparent; color: var(--tinta);
  border: 1px solid var(--linea); }
.fila { display: flex; gap: 12px; flex-wrap: wrap; }
.fila > * { flex: 1 1 200px; }
.nota { font-size: 14px; color: var(--suave); }
.aviso { border-left: 3px solid var(--medio); padding-left: 12px; }
.grave { border-left: 3px solid var(--mal); padding-left: 12px; }
dl.pares { margin: 0; }
dl.pares div { display: flex; gap: 12px; padding: 6px 0; border-bottom: 1px solid var(--linea); }
dl.pares dt { color: var(--suave); flex: 0 0 210px; font-size: 14px; }
dl.pares dd { margin: 0; flex: 1 1 auto; word-break: break-all; font-size: 14px; }
`;

const MENU = [
  ["/", "Facturas"],
  ["/estado", "Estado del ledger"],
  ["/verificar", "Verificar un recibo"],
  ["/reconciliar", "Reconciliar"],
];

/** pagina envuelve el cuerpo en la plantilla común. */
export function pagina({ titulo, ruta, cuerpo }) {
  const nav = MENU.map(
    ([r, t]) => `<a href="${r}"${r === ruta ? ' class="activo"' : ""}>${t}</a>`,
  ).join("");
  return `<!doctype html>
<html lang="es"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>${esc(titulo)} — ERP de ejemplo</title>
<style>${CSS}</style>
</head><body><div class="marco">
<header class="barra">
  <h1>Facturación S.A. <span class="nota">— ERP de ejemplo</span></h1>
  <p>Cada factura que emite este ERP se sella en Núcleo. Las pantallas enseñan el comando.</p>
  <nav>${nav}</nav>
</header>
${cuerpo}
</div></body></html>`;
}

/** comando pinta una orden de la CLI tal como se ejecutó. */
export function comando(linea) {
  return `<span class="cmd">${esc(linea)}</span>`;
}

/** pares pinta una lista de campo → valor. */
export function pares(items) {
  const filas = items
    .filter(Boolean)
    .map(([k, v]) => `<div><dt>${esc(k)}</dt><dd>${v}</dd></div>`)
    .join("");
  return `<dl class="pares">${filas}</dl>`;
}

/** marca pinta un booleano como lo pinta la CLI: ✔ / ✘ / ◐. */
export function marca(b, siSi, siNo) {
  if (b === null || b === undefined) return `<span class="medio">◐ ${esc(siNo)}</span>`;
  return b
    ? `<span class="ok">✔ ${esc(siSi)}</span>`
    : `<span class="mal">✘ ${esc(siNo)}</span>`;
}

/**
 * paginaDeError es la respuesta del ERP a un fallo de Núcleo.
 *
 * Tiene tres partes a propósito, y las tres hacen falta: QUÉ PASÓ (el mensaje que dio
 * Núcleo, sin traducir: es el que el operador va a buscar), QUÉ HIZO EL ERP (si la
 * factura se emitió o no, que es lo que el usuario necesita saber) y QUÉ HACER. Un ERP
 * que enseña "error interno" convierte un problema con arreglo conocido en una llamada
 * de teléfono.
 */
export function paginaDeError({ ruta, titulo, clase, mensaje, queHizoElERP, queHacer, detalle }) {
  const cuerpo = `
<div class="tarjeta grave">
  <h2 style="margin-top:0">${esc(titulo)}</h2>
  <p class="nota">Tipo de fallo: <code>${esc(clase)}</code></p>
  <pre>${esc(mensaje)}</pre>
</div>
<div class="tarjeta">
  <h2 style="margin-top:0">Qué hizo el ERP</h2>
  <p>${queHizoElERP}</p>
  <h2>Qué hacer</h2>
  ${queHacer}
</div>
${detalle ? `<div class="tarjeta"><h2 style="margin-top:0">Detalle técnico</h2><pre>${esc(detalle)}</pre></div>` : ""}
<a class="boton suave" href="/">Volver a las facturas</a>`;
  return pagina({ titulo, ruta, cuerpo });
}
