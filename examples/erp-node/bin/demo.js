#!/usr/bin/env node
// npm run demo — el recorrido completo, sin navegador y sin manos.
//
// Es lo que corre el CI, y por eso comprueba en vez de solo imprimir: cada paso tiene su
// aserción, y si una falla el proceso sale con 1. Un ejemplo que "arranca" pero ya no
// verifica nada se pudre sin que nadie se entere, y este es justo el artefacto que no
// puede pudrirse: es el que va a mirar un integrador.
//
// Recorre el criterio de éxito de la v1 dentro de una aplicación:
//
//   1. sella tres facturas al emitirlas, con clave de idempotencia
//   2. reintenta una con LA MISMA clave: no duplica
//   3. consigue atestación de un testigo
//   4. emite el recibo del cliente y lo verifica con @nucleoledger/verify, sin red
//   5. le cambia un byte al recibo: el verificador lo rechaza y dice por qué
//   6. coteja el ERP contra el ledger: cuadra
//   7. altera una factura en el ERP y vuelve a cotejar: sale el hallazgo
//   8. y enseña qué pasa cuando el binario falta y cuando el testigo no está

import { spawn } from "node:child_process";
import { randomBytes } from "node:crypto";
import { existsSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const RAIZ = dirname(dirname(fileURLToPath(import.meta.url)));

// El despliegue de la demo es SUYO y se rehace en cada pasada: así la demo es
// repetible y no le toca nada al de la interfaz. El ledger es append-only, no se
// "limpia": se crea otro.
const DATOS = join(RAIZ, "datos", "demo");
process.env.NUCLEO_EJEMPLO_DATOS = DATOS;
process.env.NUCLEO_ORIGIN ??= "ejemplo.local/demo";
process.env.NUCLEO_TESTIGO ??= "http://127.0.0.1:8098";

const cronometro = Date.now();

// Las importaciones van DESPUÉS de fijar el entorno, y por eso son dinámicas: config.js
// lee las variables al cargarse, y un import estático se evalúa antes de esta línea.
const cfg = await import("../src/config.js");
const { ERP } = await import("../src/erp.js");
const { dirDelTestigo, levanta, responde } = await import("../src/testigo.js");
const { ErrorDeEntorno, ErrorDeSincronizacion, Nucleo } = await import("../src/nucleo.js");
const { parsePolicyText, verifyReceipt } = await import("@nucleoledger/verify");

// Se borra el despliegue Y LA MEMORIA DEL TESTIGO. Lo segundo no es limpieza estética:
// un testigo que recuerda tres bloques de un ledger que acaba de nacer con cero es
// exactamente un retroceso, y Núcleo lo denuncia con código 2 —lo hizo en la primera
// pasada de esta demo—. Dejar el ledger nuevo con el testigo viejo es la forma más fácil
// de fabricar una falsa alarma.
rmSync(DATOS, { recursive: true, force: true });
rmSync(dirDelTestigo(), { recursive: true, force: true });
await corre(process.execPath, [join(RAIZ, "bin", "setup.js")]);

const nucleo = cfg.nucleo();
const erp = new ERP({ fichero: cfg.FICHERO_FACTURAS, nucleo, dirDocumentos: cfg.DIR_DOCUMENTOS });
const politica = parsePolicyText(readFileSync(cfg.FICHERO_POLITICA, "utf8"));

let fallos = 0;
const tiempos = [];

// ————— 1. sellar al emitir —————

paso("1", "Emitir tres facturas. Cada una se sella al emitirse.");
const emitidas = [];
for (const [cliente, ruc, concepto, cantidad, precio] of [
  ["Constructora del Litoral S.A.", "0992345678001", "Hormigón premezclado f'c=210", 12, 8650],
  ["Ferretería El Cisne", "0102345678001", "Varilla corrugada 12mm", 40, 1275],
  ["Hacienda La Josefina", "1791234567001", "Fertilizante NPK 15-15-15", 25, 3890],
]) {
  const t0 = Date.now();
  const { factura, sellado } = await erp.emite({
    cliente,
    ruc,
    items: [{ concepto, cantidad, precioCentavos: precio }],
  });
  tiempos.push(Date.now() - t0);
  emitidas.push(factura);
  dice(`  factura ${factura.numero} → bloque ${sellado.index}  (${Date.now() - t0} ms)`);
  dice(`    ${factura.comandoDeSellado}`);
  comprueba(sellado.index === emitidas.length - 1, `el bloque debería ser ${emitidas.length - 1} y es ${sellado.index}`);
  comprueba(!sellado.idempotent, "una factura nueva no puede contestar idempotente");
  comprueba(/^[0-9a-f]{64}$/.test(sellado.payloadHash), "el payload_hash no es hex de 64");
}

// ————— 2. el reintento no duplica —————

paso("2", "Reintentar el sellado de la primera factura, con la MISMA clave.");
const doc = join(cfg.DIR_DOCUMENTOS, `factura-${emitidas[0].numero}.json`);
const otraVez = await nucleo.sella({
  payloadFile: doc,
  tipo: "sri.factura.v1",
  tenant: "1790012345001",
  idempotencyKey: `factura-${emitidas[0].numero}`,
});
dice(`  contestó bloque ${otraVez.index}, idempotent: ${otraVez.idempotent}`);
comprueba(otraVez.idempotent === true, "el segundo seal con la misma clave tenía que ser idempotente");
comprueba(otraVez.index === emitidas[0].nucleo.bloque, "y tenía que contestar el bloque del primero");
const trasReintento = await nucleo.estado();
comprueba(trasReintento.treeSize === 3, `el ledger creció a ${trasReintento.treeSize}: el reintento duplicó`);
dice("  el ledger sigue en 3 bloques: no se duplicó nada (ADR-020)");

// ————— 2b. el recibo ANTES de sincronizar: "todavía no" no es "has llamado mal" —————

paso("2b", "Pedir el recibo antes de que ningún testigo haya visto el log.");
try {
  await nucleo.recibo({ bloque: 0, destinatario: "Cliente" });
  comprueba(false, "se emitió un recibo sin checkpoint, y eso no debería poder pasar");
} catch (e) {
  dice(`  código ${e.exitCode}, clase ${e.clase}: ${e.message.split("\n")[0]}`);
  comprueba(e.exitCode === 1, `código ${e.exitCode}, want 1`);
  // EL CASO QUE ORIGINÓ ADR-027: código 1, como una bandera mal escrita, y no tiene nada
  // que ver. La clase lo dice sin leer el texto, y el ERP sabe que la respuesta es
  // sincronizar y reintentar.
  comprueba(e.clase === "transient", `clase ${e.clase}, want transient`);
  comprueba(e.esReintentable() === true, "un transitorio tiene que ser reintentable");
}

// ————— 3. atestación —————

paso("3", "Pedir atestación a un testigo.");
let testigo = null;
if (!(await responde(cfg.TESTIGO))) {
  testigo = await levanta({
    puerto: new URL(cfg.TESTIGO).port,
    logKey: politica.logKey,
    origin: politica.origin,
  });
}
try {
  const sync = await nucleo.sincroniza({ witnessURL: cfg.TESTIGO });
  dice(`  ${sync.origin}: ${sync.localSize} bloques aquí, ${sync.witnessSize} cosignados por el testigo`);
  comprueba(sync.attested, "la cosignature del testigo no verificó");
  comprueba(sync.replaySuspect === false, "el testigo devolvió una cosignature que ya nacía vieja");
  // `witness_size` es lo que el testigo tenía ANTES de este intercambio, no después:
  // aquí venía de la política recién creada, con el ledger vacío. Se ve pidiéndoselo
  // otra vez, que además es lo que hará el cron cada hora.
  comprueba(sync.witnessSize < sync.localSize, `witness_size ${sync.witnessSize} >= local_size ${sync.localSize}`);
  const otraSync = await nucleo.sincroniza({ witnessURL: cfg.TESTIGO });
  dice(`  segunda pasada: el testigo ya tenía ${otraSync.witnessSize} bloques cosignados`);
  comprueba(otraSync.witnessSize === 3, `el testigo tenía ${otraSync.witnessSize} bloques, want 3`);

  const est = await nucleo.estado();
  comprueba(est.attested && est.attestedHead === true, "la cabeza del ledger quedó sin atestiguar");
  dice("  status: atestación verificada y la cabeza cubierta");

  // ————— 4. el recibo del cliente, verificado sin red —————

  paso("4", "Emitir el recibo de la segunda factura y verificarlo con @nucleoledger/verify.");
  const f2 = emitidas[1];
  const recibo = await nucleo.recibo({ bloque: f2.nucleo.bloque, destinatario: f2.cliente });
  dice(`  recibo de ${recibo.bytes ?? recibo.texto.length} bytes para ${recibo.destinatario}`);
  dice(`  tiempo demostrable: ${recibo.tiempoDemostrable || "(ninguno)"}`);
  comprueba(recibo.texto.startsWith("nucleo.org/receipt@v2"), "el recibo no empieza por su magia @v2");

  const v = await verifyReceipt(recibo.texto, politica);
  dice(`  veredicto: valid=${v.valid}  bloque=${v.blockIndex}  testigos=[${v.cosigners.join(", ")}]`);
  dice(`  firma del bloque: ${v.blockSignatureVerified}   firma del recibo: ${v.receiptSignatureVerified}`);
  comprueba(v.valid === true, `el recibo no verificó: ${v.reasons.join(" | ")}`);
  comprueba(v.blockIndex === BigInt(f2.nucleo.bloque), "el recibo apunta a otro bloque");
  comprueba(v.provableTime !== null, "el recibo verificó pero sin tiempo demostrable");
  comprueba(v.blockSignatureVerified === true && v.receiptSignatureVerified === true, "faltó una de las dos firmas");
  comprueba(v.cosigners.length >= 1, "ningún testigo cosignó lo que respalda el recibo");

  // ————— 5. un byte cambiado —————

  paso("5", "Cambiarle un byte al recibo.");
  // Se le cambia UN carácter al primer hash del recibo. No hace falta saber qué hash es:
  // todo lo que va dentro está cubierto por una firma o por la prueba de inclusión, y
  // por eso cualquier byte vale para esta demostración.
  const roto = recibo.texto.replace(/[0-9a-f]{64}/, (h) => h.slice(0, 63) + (h[63] === "0" ? "1" : "0"));
  comprueba(roto !== recibo.texto, "el recibo de prueba no se pudo alterar; revisa la demo");
  const vRoto = await verifyReceipt(roto, politica);
  dice(`  veredicto: valid=${vRoto.valid}`);
  for (const r of vRoto.reasons) dice(`    · ${r}`);
  comprueba(vRoto.valid === false, "un recibo con un byte cambiado verificó, y eso es grave");
  comprueba(vRoto.reasons.length > 0, "lo rechazó sin decir por qué");

  // ————— 6 y 7. reconciliar —————

  paso("6", "Cotejar el ERP contra el ledger.");
  erp.vivoJSONL(cfg.FICHERO_VIVO);
  const limpio = await nucleo.reconcilia({ sourceFile: cfg.FICHERO_VIVO });
  dice(`  ${limpio.comparados} comparados, ${limpio.coincidentes} coincidentes, ${limpio.hallazgos.length} hallazgos`);
  comprueba(limpio.cuadra === true, "el cotejo no cuadra sobre una base intacta");
  comprueba(Array.isArray(limpio.hallazgos) && limpio.hallazgos.length === 0, "hallazgos sobre una base intacta");
  comprueba(limpio.verificacionCompleta?.ok === true, "la verificación exhaustiva no pasó");

  paso("7", "Alterar la PRIMERA factura en el ERP —el bloque 0— y volver a cotejar.");
  erp.altera(emitidas[0].numero, { total: "1.00" });
  erp.vivoJSONL(cfg.FICHERO_VIVO);
  const sucio = await nucleo.reconcilia({ sourceFile: cfg.FICHERO_VIVO });
  dice(`  cuadra: ${sucio.cuadra}   hallazgos: ${sucio.hallazgos.length}`);
  for (const h of sucio.hallazgos) {
    dice(`    · ${h.estado} en el bloque ${h.bloque}`);
    dice(`      sellado: ${h.hashSellado}`);
    dice(`      hoy    : ${h.hashActual}`);
    dice(`      sellado el ${h.selladoEn} (tiempo DECLARADO)`);
  }
  comprueba(sucio.cuadra === false, "la alteración pasó desapercibida");
  comprueba(sucio.hallazgos.length === 1, `${sucio.hallazgos.length} hallazgos, want 1`);
  comprueba(sucio.hallazgos[0].estado === "discrepancia", `estado ${sucio.hallazgos[0].estado}`);
  comprueba(sucio.hallazgos[0].bloque === 0, "el hallazgo del bloque 0 llegó sin su índice");
  comprueba(sucio.hallazgos[0].hashSellado !== sucio.hallazgos[0].hashActual, "los dos hashes son iguales");

  // Y el recibo que ya se entregó sigue verificando: no depende del ERP.
  const vDespues = await verifyReceipt(recibo.texto, politica);
  comprueba(vDespues.valid === true, "alterar el ERP invalidó un recibo ya entregado");
  dice("  el recibo entregado antes de la alteración sigue verificando: no depende del ERP");
} finally {
  testigo?.para();
}

// ————— 8. los fallos, que también hay que enseñar —————

paso("8", "Qué contesta el ERP cuando el despliegue está mal.");

const sinBinario = new Nucleo({
  binario: join(cfg.DATOS, "no-existe-ningun-nucleo-aqui"),
  dir: cfg.DIR_LEDGER,
  passphraseFile: cfg.FICHERO_PASSPHRASE,
  policyFile: cfg.FICHERO_POLITICA,
  log: () => {},
});
try {
  await sinBinario.estado();
  comprueba(false, "un binario que no existe no dio error");
} catch (e) {
  comprueba(e instanceof ErrorDeEntorno, `esperaba ErrorDeEntorno y llegó ${e?.name}`);
  dice("  binario que falta → ErrorDeEntorno:");
  for (const l of e.message.split("\n")) dice(`    ${l}`);
}

// El testigo ya está apagado: este es el caso de "el testigo no responde".
try {
  await nucleo.sincroniza({ witnessURL: cfg.TESTIGO, timeoutMs: 10_000 });
  comprueba(false, "sincronizar contra un testigo apagado no dio error");
} catch (e) {
  comprueba(e instanceof ErrorDeSincronizacion, `esperaba ErrorDeSincronizacion y llegó ${e?.name}`);
  comprueba(e.exitCode === 3, `código ${e.exitCode}, want 3`);
  // Un testigo apagado vuelve; uno cuya clave no es la de la política, no. Los dos salen
  // con 3 y la clase los separa (ADR-027).
  comprueba(e.clase === "transient", `clase ${e.clase}, want transient`);
  comprueba(e.esReintentable() === true, "un testigo caído se reintenta");
  dice(`  testigo apagado → ErrorDeSincronizacion, código 3, clase ${e.clase}:`);
  for (const l of e.message.split("\n")) dice(`    ${l}`);
  dice("  y el ledger sigue sellando: el sello no depende del testigo");
}
const trasElCorte = await nucleo.estado();
comprueba(trasElCorte.treeSize === 3, "el corte del testigo cambió el ledger");

// ————— 9. la alarma de frescura: el testigo lleva caído más que el umbral —————

paso("9", "El testigo sigue caído y la atestación envejece: se sigue sellando, y alguien se entera.");
// El umbral se baja a 2 s para no esperar tres días; es el mismo mecanismo que en
// producción con 72 h (--stale-after). El testigo está apagado desde el paso 8.
const avisos = [];
const vigilado = cfg.nucleo({ staleAfter: "2s", onStale: (a) => avisos.push(a) });
await new Promise((r) => setTimeout(r, 3_000));

const docAlarma = join(cfg.DIR_DOCUMENTOS, "alarma-1.json");
writeFileSync(docAlarma, JSON.stringify({ alarma: 1, nonce: randomBytes(16).toString("hex") }));
const conAlarma = await vigilado.sella({ payloadFile: docAlarma, tipo: "sri.factura.v1", tenant: "1790012345001", idempotencyKey: "alarma-1" });
dice(`  sellado igual, bloque ${conAlarma.index}: un registro que no se sella se pierde (ADR-028 §A)`);
comprueba(conAlarma.index === 3, `bloque ${conAlarma.index}, want 3`);
comprueba(conAlarma.alerta?.state === "open", `alert = ${JSON.stringify(conAlarma.alerta)}`);
comprueba(avisos.length === 1, `el hook se llamó ${avisos.length} veces, want 1`);
dice(`  el hook se enteró: atestación vieja desde ${avisos[0]?.stale_since} (${avisos[0]?.reason})`);
dice("  —sin leer stderr: la alarma vive en el ledger y viaja en el JSON—");

const estadoAlarma = await vigilado.estadoDeAlarma();
comprueba(estadoAlarma.state === "open", `alert status = ${estadoAlarma.state}`);
comprueba(avisos.length === 2, "el hook tiene que repetirse en cada operación mientras nadie la reconozca");

const ack = await vigilado.reconoceAlarma({ por: "demo" });
comprueba(ack.reconocida && ack.alerta?.state === "acked", `ack = ${JSON.stringify(ack)}`);
dice(`  reconocida por «demo»: el hook deja de avisar, y la alarma sigue abierta hasta un sync bueno`);

const docAlarma2 = join(cfg.DIR_DOCUMENTOS, "alarma-2.json");
writeFileSync(docAlarma2, JSON.stringify({ alarma: 2, nonce: randomBytes(16).toString("hex") }));
await vigilado.sella({ payloadFile: docAlarma2, tipo: "sri.factura.v1", tenant: "1790012345001", idempotencyKey: "alarma-2" });
comprueba(avisos.length === 2, `reconocida, el hook se llamó otra vez (${avisos.length})`);

// fallaSiVieja: para quien tiene cola. No escribe, y lo dice con el tipo y la clase.
const docAlarma3 = join(cfg.DIR_DOCUMENTOS, "alarma-3.json");
writeFileSync(docAlarma3, JSON.stringify({ alarma: 3, nonce: randomBytes(16).toString("hex") }));
const antes = (await vigilado.estado()).treeSize;
try {
  await vigilado.sella({ payloadFile: docAlarma3, tipo: "sri.factura.v1", tenant: "1790012345001", idempotencyKey: "alarma-3", fallaSiVieja: true });
  comprueba(false, "fallaSiVieja selló con la atestación vieja");
} catch (e) {
  comprueba(e instanceof ErrorDeSincronizacion && e.clase === "transient", `llegó ${e?.name} clase ${e?.clase}`);
  dice(`  con fallaSiVieja: no sella, ${e.name} clase ${e.clase} —para reintentar tras un sync—`);
}
comprueba((await vigilado.estado()).treeSize === antes, "fallaSiVieja escribió un bloque");

// ————— el resumen —————

const segundos = ((Date.now() - cronometro) / 1000).toFixed(1);
console.log(`
———————————————————————————————————————————————————————————————
  ${fallos === 0 ? "TODO CORRECTO" : `${fallos} COMPROBACIONES FALLARON`}

  despliegue, sellado, atestación, recibo, verificación y cotejo
  en ${segundos} s de reloj, sobre ${cfg.DIR_LEDGER}

  sellar una factura: ${tiempos.map((t) => `${t} ms`).join(", ")}
———————————————————————————————————————————————————————————————
`);
process.exit(fallos === 0 ? 0 : 1);

// ————— utilidades —————

function paso(n, t) {
  console.log(`\n[${n}] ${t}`);
}

function dice(s) {
  console.log(s);
}

function comprueba(cond, mensaje) {
  if (cond) return;
  fallos++;
  console.error(`  ✘ COMPROBACIÓN FALLIDA: ${mensaje}`);
}

function corre(bin, args) {
  return new Promise((resolve, reject) => {
    const p = spawn(bin, args, { cwd: RAIZ, stdio: ["ignore", "inherit", "inherit"] });
    p.on("error", reject);
    p.on("close", (c) => (c === 0 ? resolve() : reject(new Error(`${bin} ${args.join(" ")} salió con ${c}`))));
  });
}
