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
const NucleoVerify = sandbox.NucleoVerify;

const catalogo = JSON.parse(readFileSync(catalogoPath, "utf8"));
const divergencias = [];
let lanzo = 0;
let tsAcepta = 0;
// CATEGORIAS traduce el motivo de rechazo de TypeScript al vocabulario compartido con
// Go. Comparar solo "valid" acreditaba "los dos aceptan o los dos rechazan"; no decía
// nada de si leen la misma política, cuentan los mismos testigos o dan la misma fecha
// (cuarta auditoría). Dos verificadores que aceptan el mismo recibo y difieren en el
// tiempo demostrable son dos verificadores distintos.
const CATEGORIAS = [
  ["la política no se pudo leer", "policy"],
  ["el texto del recibo no coincide", "text"],
  ["el recibo no se pudo leer", "format"],
  ["el header del bloque no está en forma canónica", "format"],
  ["el bloque no está firmado por la clave del emisor que fija la política", "signer"],
  ["el índice de la prueba", "index"],
  ["quórum de testigos no alcanzado", "quorum"],
  ["la prueba de inclusión no verifica", "inclusion"],
  ["el recibo es del log", "origin"],
  ["el checkpoint no está firmado por la clave del log", "origin"],
  ["la firma del log no verifica", "signature"],
  ["la cosignature de", "signature"],
  ["la firma del bloque no verifica", "signature"],
  ["la firma del emisor sobre el recibo no verifica", "signature"],
  ["el recibo no lleva firma del emisor", "signature"],
  ["signer_pubkey del header no es una clave Ed25519", "format"],
];

function categorias(reasons) {
  const out = new Set();
  for (const r of reasons) {
    const hit = CATEGORIAS.find(([prefijo]) => r.includes(prefijo));
    out.add(hit ? hit[1] : "other");
  }
  return out;
}

/** dictamenTS reconstruye el veredicto estructurado con la forma que emite Go. */
function dictamenTS(r) {
  if (!r.valid) return { valid: false, categorias: categorias(r.reasons) };
  return {
    valid: true,
    declared_time: r.declaredTime ?? "",
    provable_time: r.provableTime ?? "",
    block_index: r.blockIndex === null ? "" : String(r.blockIndex),
    recipient: r.recipient ?? "",
    signer_pubkey: r.signerPubKey ?? "",
    cosigners: r.cosigners,
    ignored: r.ignoredSignatures,
    checkpoint: r.checkpoint ? `${r.checkpoint.origin}/${r.checkpoint.size}/${r.checkpoint.rootHash}` : "",
  };
}

// clase agrupa las categorías que son la misma ETAPA del trabajo: leer el documento y
// derivar su texto son dos puntos de lo mismo.
const clase = (c) => (c === "format" || c === "text" ? "documento" : c);

// etapas cuenta, cuando los DOS rechazan, en qué punto se para cada uno. No es una
// divergencia: ante un recibo roto, Go deriva el encabezado y ve que no cuadra mientras
// TypeScript ni siquiera llega a leer el magic, y las dos cosas son correctas. Se cuenta
// para que la deriva se vea, no para fallar por ella.
const etapas = new Map();

/**
 * compara devuelve la lista de campos en los que los dos dictámenes difieren.
 *
 * Lo que se exige, y es lo nuevo de la cuarta auditoría: cuando los dos ACEPTAN, todo lo
 * que afirman tiene que ser idéntico —los dos tiempos, el índice, el destinatario, la
 * clave del firmante, los testigos que cuentan, las firmas ignoradas y el checkpoint—.
 * Comparar solo "valid" acreditaba "los dos aceptan o los dos rechazan", que es mucho
 * menos: dos verificadores que aceptan el mismo recibo y dan distinto tiempo demostrable
 * son dos verificadores distintos.
 */
function compara(go, ts) {
  if (go.valid !== ts.valid) return [`valid: go=${go.valid} ts=${ts.valid}`];
  if (!go.valid) {
    const suyas = [...new Set([...ts.categorias].map(clase))].sort().join(",") || "(ninguna)";
    const par = `go=${clase(go.categoria ?? "")} ts=${suyas}`;
    etapas.set(par, (etapas.get(par) ?? 0) + 1);
    return [];
  }
  const dif = [];
  for (const campo of ["declared_time", "provable_time", "block_index", "recipient", "signer_pubkey", "checkpoint"]) {
    if ((go[campo] ?? "") !== (ts[campo] ?? "")) {
      dif.push(`${campo}: go=${JSON.stringify(go[campo] ?? "")} ts=${JSON.stringify(ts[campo] ?? "")}`);
    }
  }
  for (const campo of ["cosigners", "ignored"]) {
    const a = JSON.stringify(go[campo] ?? []);
    const b = JSON.stringify(ts[campo] ?? []);
    if (a !== b) dif.push(`${campo}: go=${a} ts=${b}`);
  }
  return dif;
}

for (const c of catalogo.casos) {
  let tsValid = false;
  let tsErr = "";
  let dif = [];
  try {
    const r = await verifyReceipt(c.receipt, c.policy);
    tsValid = r.valid;
    tsErr = r.reasons.join(" | ");
    dif = compara(c.go_dictamen ?? { valid: c.go_valid }, dictamenTS(r));
  } catch (e) {
    // verifyReceipt promete no lanzar nunca. Si lanza, es un hallazgo aparte.
    lanzo++;
    tsErr = "LANZÓ: " + (e && e.message);
    dif = ["LANZÓ"];
  }
  if (tsValid) tsAcepta++;
  if (dif.length > 0) {
    divergencias.push({ nombre: `${c.vector}: ${c.nombre}`, go: c.go_valid, ts: tsValid, goErr: c.go_err ?? "", tsErr: dif.join(" ; ") + " || " + tsErr });
  }
}

// Tercer catálogo: la POLÍTICA como formato de cable (ADR-018 E). Mismo texto por
// internal/policy (Go, ya anotado) y por parsePolicyText del bundle.
const politicas = catalogo.politicas ?? [];
let polTsAcepta = 0;
for (const c of politicas) {
  let ok = false;
  let err = "";
  try {
    NucleoVerify.parsePolicyText(c.texto);
    ok = true;
  } catch (e) {
    err = e && e.message;
  }
  if (ok) polTsAcepta++;
  if (ok !== c.go_valid) {
    divergencias.push({ nombre: `política: ${c.nombre}`, go: c.go_valid, ts: ok, goErr: c.go_err ?? "", tsErr: err });
  }
}
console.log(`  catálogo de políticas: ${politicas.length} (Go acepta ${politicas.filter((c) => c.go_valid).length}, TS acepta ${polTsAcepta})`);
if (politicas.length === 0) {
  console.error("✘ el catálogo no trae políticas: el generador de Go no está escribiendo el tercer catálogo");
  process.exit(1);
}

const goAcepta = catalogo.casos.filter((c) => c.go_valid).length;
// Los catálogos se distinguen por el prefijo del vector: "refirmado/…" son las
// mutaciones de nota que el emisor volvió a firmar (ADR-018 E).
const porCatalogo = new Map();
for (const c of catalogo.casos) {
  const k = c.vector.startsWith("refirmado/") ? "re-firmadas por el emisor" : "bytes del recibo";
  porCatalogo.set(k, (porCatalogo.get(k) ?? 0) + 1);
}
for (const [k, n] of porCatalogo) console.log(`  catálogo ${k}: ${n}`);
console.log(`mutaciones: ${catalogo.casos.length}   Go acepta: ${goAcepta}   TS acepta: ${tsAcepta}`);
console.log(`divergencias de DICTAMEN (veredicto, tiempos, firmantes, firmas ignoradas, categoría de rechazo, campos autenticados): ${divergencias.length}   excepciones en TS: ${lanzo}`);
if (etapas.size > 0) {
  console.log("dónde se para cada verificador cuando los dos rechazan (no es divergencia):");
  for (const [par, n] of [...etapas].sort((a, b) => b[1] - a[1])) {
    console.log(`  ${String(n).padStart(5)}  ${par}`);
  }
}
for (const d of divergencias) {
  console.log(`\n✘ ${d.nombre}\n    go=${d.go}  ts=${d.ts}\n    go: ${d.goErr.slice(0, 120)}\n    ts: ${d.tsErr.slice(0, 120)}`);
}
if (divergencias.length > 0 || lanzo > 0) process.exit(1);
console.log("✔ los dos verificadores coinciden en todas las mutaciones");
