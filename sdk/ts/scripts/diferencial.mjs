// DIFERENCIAL Go ↔ TypeScript (C.4 del Sprint 7c).
//
// Lee el catálogo de mutaciones que genera internal/receipt/diferencial_test.go
// —cada una con el veredicto de Go ya anotado— y pasa cada recibo por el BUNDLE
// que sirve la página web. Cualquier divergencia de veredicto hace fallar el
// proceso. Una divergencia es un bug aunque los dos rechacen por motivos
// distintos: dos verificadores que no opinan lo mismo son dos verificadores en los
// que no se puede confiar por igual.
//
// Uso:  node scripts/diferencial.mjs <catalogo.json>
// Cómo añadir mutaciones: en catalogoDeMutaciones, en el test de Go. Este script
// no genera nada; solo compara.
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { runInNewContext } from "node:vm";

const [, , catalogoPath] = process.argv;
if (!catalogoPath) {
  console.error("uso: node scripts/diferencial.mjs <catalogo.json>");
  process.exit(2);
}
const here = dirname(fileURLToPath(import.meta.url));
// El bundle y no la biblioteca: es lo que corre en el navegador de la contraparte.
const bundle = readFileSync(join(here, "..", "..", "..", "web", "verify", "nucleo-verify.js"), "utf8");
const sandbox = { crypto, console, TextEncoder, TextDecoder, atob, btoa };
sandbox.globalThis = sandbox;
runInNewContext(bundle, sandbox, { filename: "nucleo-verify.js" });
const { verifyReceipt } = sandbox.NucleoVerify;

const catalogo = JSON.parse(readFileSync(catalogoPath, "utf8"));
const divergencias = [];
let lanzo = 0;
let tsAcepta = 0;
for (const c of catalogo.casos) {
  let tsValid = false;
  let tsErr = "";
  try {
    const r = await verifyReceipt(c.receipt, c.policy);
    tsValid = r.valid;
    tsErr = r.reasons.join(" | ");
  } catch (e) {
    // verifyReceipt promete no lanzar nunca. Si lanza, es un hallazgo aparte.
    lanzo++;
    tsErr = "LANZÓ: " + (e && e.message);
  }
  if (tsValid) tsAcepta++;
  if (tsValid !== c.go_valid) {
    divergencias.push({ nombre: `${c.vector}: ${c.nombre}`, go: c.go_valid, ts: tsValid, goErr: c.go_err ?? "", tsErr });
  }
}

const goAcepta = catalogo.casos.filter((c) => c.go_valid).length;
console.log(`mutaciones: ${catalogo.casos.length}   Go acepta: ${goAcepta}   TS acepta: ${tsAcepta}`);
console.log(`divergencias de veredicto: ${divergencias.length}   excepciones en TS: ${lanzo}`);
for (const d of divergencias) {
  console.log(`\n✘ ${d.nombre}\n    go=${d.go}  ts=${d.ts}\n    go: ${d.goErr.slice(0, 120)}\n    ts: ${d.tsErr.slice(0, 120)}`);
}
if (divergencias.length > 0 || lanzo > 0) process.exit(1);
console.log("✔ los dos verificadores coinciden en todas las mutaciones");
