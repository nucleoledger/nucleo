// DIFERENCIAL Go ↔ TypeScript ↔ PHP (C.4 del Sprint 7c; PHP en el Sprint 8, ADR-021 §F).
//
// Lee el catálogo de mutaciones que genera internal/receipt/diferencial_test.go
// —cada una con el veredicto de Go ya anotado— y pasa cada recibo por el BUNDLE
// que sirve la página web y por el SDK de PHP. Cualquier divergencia de veredicto
// hace fallar el proceso. Una divergencia es un bug aunque los dos rechacen por
// motivos distintos: dos verificadores que no opinan lo mismo son dos verificadores
// en los que no se puede confiar por igual.
//
// PHP entra con un solo proceso y no uno por caso: trece mil arranques serían veinte
// minutos de compuerta. Si no hay PHP en la máquina, se DICE en voz alta y se sigue
// con dos de tres; una compuerta que no distingue "coinciden" de "no se comprobó" no
// es una compuerta. Se busca en $NUCLEO_PHP (puede llevar argumentos) o en `php`.
//
// Con NUCLEO_DIFERENCIAL_EXIGE_PHP=1, no seguir: la ausencia de PHP pasa de aviso a
// fallo. Lo pone el CI, donde el tercer verificador no es opcional. Una máquina de
// desarrollo sin PHP sigue pudiendo correr el diferencial de dos.
//
// Uso:  node scripts/diferencial.mjs <catalogo.json>
// Cómo añadir mutaciones: en catalogoDeMutaciones, en el test de Go. Este script
// no genera nada; solo compara.
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
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
  ["la firma post-cuántica del log (ML-DSA-44) de la clave que fija la política mide", "mldsa_signature_invalid"],
  ["la política fija la clave ML-DSA-44 del log (logMLDSAKey) y el checkpoint no trae su firma", "mldsa_signature_missing"],
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
    log_mldsa: r.logMLDSA ?? "",
  };
}

// ---- La divergencia declarada de ML-DSA-44 (ADR-034, decisión 5, opción B) ----------
//
// Es la ÚNICA permitida: Go verifica la firma ML-DSA-44 del log y rechaza con
// ErrMLDSASignature (categoría "mldsa_signature_invalid"); TypeScript y PHP no la
// verifican y aceptan con logMLDSA "present-unverified". Pero Go usa el MISMO error para
// "firma mala" y para "longitud mala", y TS y PHP sí tienen que rechazar una línea de la
// clave fijada que no mide 2420 bytes. Así que el arnés lo comprueba POR SU CUENTA, sin
// el SDK —node:crypto y el texto del recibo—: si alguna línea del key ID fijado no mide
// 2420 bytes, no hay excepción y los tres tienen que rechazar.
const MLDSA_FIRMA = 2420;

/** idMLDSA es el key ID de la clave fijada: SHA-256(origin‖"\n"‖0xff‖id‖"\n"‖P)[:4]. */
function idMLDSA(origin, claveHex) {
  return createHash("sha256")
    .update(Buffer.from(origin + "\n", "utf8"))
    .update(Buffer.from([0xff]))
    .update(Buffer.from("nucleoledger.com/sig/ml-dsa-44@v1\n", "utf8"))
    .update(Buffer.from(claveHex, "hex"))
    .digest()
    .subarray(0, 4);
}

/**
 * longitudesDeLaClave devuelve lo que mide la firma de cada línea del recibo con el
 * nombre del origin y el key ID de la clave fijada, sin el key ID. Lee las líneas
 * «— nombre base64» tal cual; una que no decodifica no es de nadie y no cuenta.
 */
function longitudesDeLaClave(recibo, origin, claveHex) {
  const id = idMLDSA(origin, claveHex);
  const out = [];
  for (const l of recibo.split("\n")) {
    if (!l.startsWith("— " + origin + " ")) continue;
    const b64 = l.slice(("— " + origin + " ").length);
    if (!/^[A-Za-z0-9+/]+={0,2}$/.test(b64)) continue;
    const blob = Buffer.from(b64, "base64");
    if (blob.toString("base64") !== b64 || blob.length < 4) continue;
    if (blob.subarray(0, 4).equals(id)) out.push(blob.length - 4);
  }
  return out;
}

/**
 * excepcionMLDSA dice si la divergencia entre Go y otro verificador es la declarada. Las
 * tres condiciones, y ninguna sobra: Go rechaza por la firma ML-DSA, el otro acepta sin
 * verificarla, y TODAS las líneas de la clave fijada miden 2420 bytes.
 */
function excepcionMLDSA(c, otro) {
  const go = c.go_dictamen ?? { valid: c.go_valid };
  if (go.valid || go.categoria !== "mldsa_signature_invalid") return false;
  if (!otro.valid || otro.log_mldsa !== "present-unverified") return false;
  const clave = c.policy?.logMLDSAKey;
  if (!clave) return false;
  const ls = longitudesDeLaClave(c.receipt, c.policy.origin, clave);
  return ls.length > 0 && ls.every((n) => n === MLDSA_FIRMA);
}

// Autocomprobación del arnés: en todo caso del catálogo con una línea de la clave fijada
// que NO mide 2420 bytes, la excepción tiene que negarse aunque el otro verificador
// acepte. Un arnés que la concediera —que perdonara cualquier divergencia con motivo
// ML-DSA de Go— taparía a un TS o un PHP que se saltan la longitud.
const autocomprobacion = { casos: 0, concedidas: [] };
for (const c of catalogo.casos) {
  const clave = c.policy?.logMLDSAKey;
  if (!clave) continue;
  const ls = longitudesDeLaClave(c.receipt, c.policy.origin, clave);
  if (!ls.some((n) => n !== MLDSA_FIRMA)) continue;
  autocomprobacion.casos++;
  const fingido = { ...c, go_dictamen: { ...(c.go_dictamen ?? {}), valid: false, categoria: "mldsa_signature_invalid" } };
  if (excepcionMLDSA(fingido, { valid: true, log_mldsa: "present-unverified" })) {
    autocomprobacion.concedidas.push(`${c.vector}: ${c.nombre} (líneas de ${ls.join(", ")} bytes)`);
  }
}
const excepciones = { ts: 0, php: 0 };

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
function compara(go, otro, etiq = "ts", etapasDe = etapas, caso = null) {
  if (go.valid !== otro.valid) {
    if (caso && excepcionMLDSA(caso, otro)) {
      excepciones[etiq]++;
      return [];
    }
    return [`valid: go=${go.valid} ${etiq}=${otro.valid}`];
  }
  if (!go.valid) {
    const suyas = [...new Set([...otro.categorias].map(clase))].sort().join(",") || "(ninguna)";
    const par = `go=${clase(go.categoria ?? "")} ${etiq}=${suyas}`;
    etapasDe.set(par, (etapasDe.get(par) ?? 0) + 1);
    return [];
  }
  const dif = [];
  for (const campo of ["declared_time", "provable_time", "block_index", "recipient", "signer_pubkey", "checkpoint"]) {
    if ((go[campo] ?? "") !== (otro[campo] ?? "")) {
      dif.push(`${campo}: go=${JSON.stringify(go[campo] ?? "")} ${etiq}=${JSON.stringify(otro[campo] ?? "")}`);
    }
  }
  for (const campo of ["cosigners", "ignored"]) {
    const a = JSON.stringify(go[campo] ?? []);
    const b = JSON.stringify(otro[campo] ?? []);
    if (a !== b) dif.push(`${campo}: go=${a} ${etiq}=${b}`);
  }
  // logMLDSA: igual, salvo la parte declarada de la decisión 5 —con la clave en la
  // política, Go dice "verified" y TS y PHP "present-unverified"—. TS y PHP nunca dicen
  // "verified".
  const gm = go.log_mldsa ?? "";
  const om = otro.log_mldsa ?? "";
  const conClave = Boolean(caso?.policy?.logMLDSAKey);
  if (om === "verified") dif.push(`log_mldsa: ${etiq} dice "verified" y no implementa ML-DSA-44`);
  else if (conClave ? !(gm === "verified" && om === "present-unverified") : gm !== om) {
    dif.push(`log_mldsa: go=${JSON.stringify(gm)} ${etiq}=${JSON.stringify(om)}`);
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
    dif = compara(c.go_dictamen ?? { valid: c.go_valid }, dictamenTS(r), "ts", etapas, c);
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

// ---- PHP, el tercer verificador (ADR-021 §F) --------------------------------
// Escrito desde PROTOCOL.md y no portado de aquí: dos implementaciones con el mismo
// linaje comparten errores, y lo que este diferencial mide es si coinciden de todas
// formas.
const etapasPHP = new Map();
let phpEstado = "";
// El CI lo pone; una máquina de desarrollo, no.
const exigePHP = process.env.NUCLEO_DIFERENCIAL_EXIGE_PHP === "1";
{
  const cmd = (process.env.NUCLEO_PHP ?? "php").split(/\s+/).filter(Boolean);
  // La raíz del repositorio y una ruta RELATIVA al script: en WSL con el PHP de
  // Windows, una ruta absoluta de WSL (/mnt/c/…) no la puede abrir php.exe, y una de
  // Windows no la puede resolver Node. El directorio de trabajo lo comparten los dos.
  const raiz = join(here, "..", "..", "..");
  const dictamenPHP = join("sdk", "php", "bin", "dictamen.php");
  const sonda = spawnSync(cmd[0], [...cmd.slice(1), "-r", "echo PHP_VERSION;"], { encoding: "utf8" });
  if (sonda.error || sonda.status !== 0) {
    phpEstado = `NO SE COMPROBÓ: no hay PHP ejecutable (${cmd.join(" ")}). Define NUCLEO_PHP si está en otro sitio.`;
    if (exigePHP) {
      divergencias.push({
        nombre: "php: EXIGIDO y ausente",
        go: "",
        ts: "",
        goErr: "",
        tsErr: phpEstado,
      });
    }
  } else {
    // El catálogo va por la entrada estándar y no por una ruta: en WSL con el PHP de
    // Windows no hay ninguna ruta que sirva para los dos procesos, y por stdin no hay
    // nada que traducir.
    const r = spawnSync(cmd[0], [...cmd.slice(1), dictamenPHP, "-"], {
      cwd: raiz,
      encoding: "utf8",
      input: readFileSync(catalogoPath),
      maxBuffer: 512 * 1024 * 1024,
    });
    if (r.status !== 0) {
      phpEstado = `FALLÓ (código ${r.status}, señal ${r.signal}): ${(r.stderr || r.error?.message || "sin mensaje").slice(0, 400)}`;
      divergencias.push({ nombre: "php: el dictamen no se pudo generar", go: "", ts: "", goErr: "", tsErr: phpEstado });
    } else {
      const php = JSON.parse(r.stdout);
      if (php.casos.length !== catalogo.casos.length) {
        divergencias.push({
          nombre: "php: el dictamen no cubre el catálogo",
          go: catalogo.casos.length,
          ts: php.casos.length,
          goErr: "",
          tsErr: "",
        });
      }
      let phpAcepta = 0;
      for (let i = 0; i < php.casos.length; i++) {
        const c = catalogo.casos[i];
        const d = php.casos[i];
        if (d.valid) phpAcepta++;
        const dic = d.valid ? d : { valid: false, categorias: categorias(d.reasons ?? []) };
        const dif = compara(c.go_dictamen ?? { valid: c.go_valid }, dic, "php", etapasPHP, c);
        if (dif.length > 0) {
          divergencias.push({
            nombre: `php ${c.vector}: ${c.nombre}`,
            go: c.go_valid,
            ts: d.valid,
            goErr: c.go_err ?? "",
            tsErr: dif.join(" ; ") + " || " + (d.reasons ?? []).join(" | "),
          });
        }
      }
      let phpPol = 0;
      for (let i = 0; i < politicas.length; i++) {
        const esperado = politicas[i].go_valid;
        const obtenido = php.politicas[i]?.ok ?? null;
        if (obtenido) phpPol++;
        if (obtenido !== esperado) {
          divergencias.push({
            nombre: `php política: ${politicas[i].nombre}`,
            go: esperado,
            ts: obtenido,
            goErr: politicas[i].go_err ?? "",
            tsErr: php.politicas[i]?.err ?? "(sin dictamen)",
          });
        }
      }
      phpEstado = `${sonda.stdout.trim()} · acepta ${phpAcepta} recibos y ${phpPol} políticas`;
    }
  }
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
console.log(`PHP: ${phpEstado}`);
console.log(
  `divergencia declarada de ML-DSA-44 (Go rechaza la firma; TS y PHP, present-unverified, todas las líneas de 2420 bytes): ` +
    `TS ${excepciones.ts}, PHP ${excepciones.php}`,
);
console.log(
  `autocomprobación del arnés: ${autocomprobacion.casos} casos con una línea de la clave fijada que no mide 2420 bytes; ` +
    `excepción concedida a ${autocomprobacion.concedidas.length}`,
);
if (autocomprobacion.casos === 0) {
  divergencias.push({ nombre: "arnés: el catálogo no trae ninguna línea ML-DSA de otra longitud", go: "", ts: "", goErr: "",
    tsErr: "sin esos casos la autocomprobación no comprueba nada: ¿se quitaron las mutaciones 2419 y 2421?" });
}
for (const x of autocomprobacion.concedidas) {
  divergencias.push({ nombre: "arnés: concede la excepción de ML-DSA a una línea que no mide 2420 bytes", go: "", ts: "", goErr: "", tsErr: x });
}
if (excepciones.ts === 0 || excepciones.php === 0 && !phpEstado.startsWith("NO SE COMPROBÓ")) {
  divergencias.push({ nombre: "arnés: la divergencia declarada no apareció", go: "", ts: excepciones.ts, goErr: "",
    tsErr: `PHP ${excepciones.php}: el catálogo tiene firmas ML-DSA alteradas con la clave fijada; si nadie las acepta, algo cambió` });
}
console.log(`divergencias de DICTAMEN (veredicto, tiempos, firmantes, firmas ignoradas, categoría de rechazo, campos autenticados): ${divergencias.length}   excepciones en TS: ${lanzo}`);
for (const [cual, mapa] of [["TypeScript", etapas], ["PHP", etapasPHP]]) {
  if (mapa.size === 0) continue;
  console.log(`dónde se para cada verificador cuando los dos rechazan, Go vs ${cual} (no es divergencia):`);
  for (const [par, n] of [...mapa].sort((a, b) => b[1] - a[1])) {
    console.log(`  ${String(n).padStart(5)}  ${par}`);
  }
}
for (const d of divergencias) {
  console.log(`\n✘ ${d.nombre}\n    go=${d.go}  ts=${d.ts}\n    go: ${d.goErr.slice(0, 120)}\n    ts: ${d.tsErr.slice(0, 120)}`);
}
if (divergencias.length > 0 || lanzo > 0) process.exit(1);
console.log(
  phpEstado.startsWith("NO SE COMPROBÓ")
    ? "✔ Go y TypeScript coinciden en todas las mutaciones — PHP no se comprobó (ver arriba)"
    : "✔ los TRES verificadores coinciden en todas las mutaciones",
);
