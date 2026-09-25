#!/usr/bin/env node
// npm run setup — deja el despliegue listo para operar.
//
// Hace, en este orden y diciéndolo en voz alta, lo que un integrador haría a mano la
// primera vez:
//
//   1. comprueba que hay un binario de Núcleo y que se puede ejecutar
//   2. instala el verificador TypeScript desde npm, fijado por versión y por hash
//   3. crea el vault y el ledger con `nucleo init`, y guarda las tarjetas de respaldo
//   4. consigue la PRIMERA atestación de un testigo y escribe datos/politica.json
//
// El paso 4 no es opcional por capricho: la política es lo único en lo que se confía
// después, y `sync` es el único comando que la entrega completa —con el testigo dentro—.

import { spawn } from "node:child_process";
import { chmodSync, existsSync, lstatSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import * as cfg from "../src/config.js";
import { claveDelTestigo, dirDelTestigo, levanta, responde } from "../src/testigo.js";

const PASSPHRASE_DE_JUGUETE = "ejemplo-erp-node-no-usar-en-produccion";

async function main() {
  paso(1, "El binario de Núcleo");
  if (!existsSync(cfg.BINARIO)) {
    fatal(
      `no hay binario en ${cfg.BINARIO}.\n` +
        `  Constrúyelo desde la raíz del repositorio:\n\n` +
        `      go build -o nucleo ./cmd/nucleo\n\n` +
        `  o baja el release firmado y apunta NUCLEO_BIN a él.`,
    );
  }
  const v = await corre(cfg.BINARIO, ["--json", "status", "--dir", cfg.DIR_LEDGER], { tolera: true });
  dice(`  ${cfg.BINARIO}`);
  dice(`  ejecutable: sí${v.code === 0 ? " (y ya hay un ledger ahí)" : ""}`);

  paso(2, "El verificador TypeScript, del registro de npm");
  // Del REGISTRO, fijado por versión exacta y por hash en package-lock.json: lo mismo
  // que instalaría cualquiera que clone esto. Hasta el 25 de septiembre de 2026 el
  // ejemplo dependía del SDK del repositorio (file:../../sdk/ts), porque la versión
  // publicada era anterior al recibo @v2 (ADR-026). Ya no: 0.2.0-alpha.0 está en npm
  // con procedencia, y el ejemplo comprueba lo que un tercero de verdad obtiene.
  await corre(npm(), ["ci", "--no-audit", "--no-fund"], { cwd: cfg.RAIZ, heredaSalida: true });
  const instalado = join(cfg.RAIZ, "node_modules", "@nucleoledger", "verify");
  if (lstatSync(instalado).isSymbolicLink()) {
    fatal("@nucleoledger/verify es un enlace a una carpeta local, no el paquete de npm");
  }
  const version = JSON.parse(readFileSync(join(instalado, "package.json"), "utf8")).version;
  dice(`  @nucleoledger/verify ${version}, instalado desde el registro`);
  dice("  su procedencia se comprueba con:  npm audit signatures");

  paso(3, "El vault y el ledger");
  mkdirSync(cfg.DATOS, { recursive: true });
  mkdirSync(cfg.DIR_LEDGER, { recursive: true });
  if (!existsSync(cfg.FICHERO_PASSPHRASE)) {
    writeFileSync(cfg.FICHERO_PASSPHRASE, PASSPHRASE_DE_JUGUETE + "\n", { mode: 0o600 });
    dice(`  passphrase de juguete escrita en ${cfg.FICHERO_PASSPHRASE} (modo 0600)`);
    dice("  en producción NO se genera así: la elige una persona y no vive en el repositorio");
  } else {
    chmodSync(cfg.FICHERO_PASSPHRASE, 0o600);
    dice("  la passphrase ya estaba");
  }

  let logKey;
  if (existsSync(join(cfg.DIR_LEDGER, "nucleo.db"))) {
    dice("  el ledger ya existe: no se vuelve a inicializar (append-only, ADR-001)");
    const est = JSON.parse(
      (await corre(cfg.BINARIO, ["--dir", cfg.DIR_LEDGER, "--json", "status"])).salida,
    );
    logKey = est.log_pubkey;
  } else {
    const r = await corre(cfg.BINARIO, [
      "--dir", cfg.DIR_LEDGER, "--json", "init",
      "--origin", cfg.ORIGIN,
      "--passphrase-file", cfg.FICHERO_PASSPHRASE,
      "--assume-confirmed",
    ]);
    const init = JSON.parse(r.salida);
    logKey = init.log_pubkey;
    // Las tarjetas SLIP-0039 son EL secreto: reconstruyen la KEK. Se escriben aquí para
    // que el ejemplo sea reproducible, y por eso datos/ está en .gitignore y el fichero
    // va en 0600. En producción van a papel y nunca a un disco con el ledger.
    writeFileSync(
      join(cfg.DATOS, "tarjetas-DE-JUGUETE.txt"),
      init.shares.join("\n") + "\n",
      { mode: 0o600 },
    );
    dice(`  ledger creado. origin: ${init.origin}`);
    dice(`  clave del log: ${logKey}`);
    dice(`  ${init.threshold} de ${init.shares.length} tarjetas guardadas en datos/tarjetas-DE-JUGUETE.txt`);
  }

  paso(4, "La primera atestación y la política");
  const yaHabia = await responde(cfg.TESTIGO);
  let testigo = null;
  if (yaHabia) {
    dice(`  hay un testigo escuchando en ${cfg.TESTIGO}: se usa ese`);
  } else {
    dice(`  nadie contesta en ${cfg.TESTIGO}: levanto uno de juguete solo para este paso`);
    dice("  (en producción el testigo es de un TERCERO: su valor está en que no es tuyo)");
    testigo = await levanta({ puerto: new URL(cfg.TESTIGO).port || 8099, logKey });
  }
  try {
    // La PRIMERA vez hay que decirle a `sync` en qué testigo confiar por su nombre y su
    // clave: todavía no hay política donde mirarlo. Es el único momento de confianza
    // inicial del despliegue, y se resuelve fuera de banda —aquí, leyendo la clave del
    // testigo que acabamos de levantar; en producción, de la página del que lo opera—.
    // A partir de la segunda vez la política ya lo lleva dentro y basta --policy-file.
    const clave =
      process.env.NUCLEO_TESTIGO_CLAVE ??
      (await claveDelTestigo(testigo?.db ?? join(dirDelTestigo(), "testigo.db"))).public_key;
    const nombre = process.env.NUCLEO_TESTIGO_NOMBRE ?? "testigo-local";
    dice(`  confianza inicial en el testigo ${nombre}: ${clave}`);
    const r = await corre(cfg.BINARIO, [
      "--dir", cfg.DIR_LEDGER, "--json", "sync",
      "--witness", cfg.TESTIGO,
      "--witness-name", nombre,
      "--witness-key", clave,
      "--passphrase-file", cfg.FICHERO_PASSPHRASE,
    ]);
    const sync = JSON.parse(r.salida);
    if (!sync.policy) fatal("sync no devolvió la política, y es el único comando que la entrega");
    writeFileSync(cfg.FICHERO_POLITICA, JSON.stringify(sync.policy, null, 2) + "\n");
    dice(`  política escrita en ${cfg.FICHERO_POLITICA}`);
    dice(`  testigos que acepta: ${Object.keys(sync.policy.witnesses ?? {}).join(", ") || "ninguno"}`);
  } finally {
    testigo?.para();
  }

  console.log(`
Listo. Lo que hay ahora:

  ${cfg.DIR_LEDGER}/nucleo.db     el ledger (append-only)
  ${cfg.FICHERO_POLITICA}   la política: lo ÚNICO en lo que se confía
  ${cfg.FICHERO_PASSPHRASE}  la passphrase (juguete, modo 0600)

Siguiente paso, y en este orden:

  npm run testigo     en otra terminal: el testigo, para que el botón "Sincronizar" haga algo
  npm start           el ERP en http://127.0.0.1:${cfg.PUERTO}

O todo el recorrido de una vez, sin navegador:

  npm run demo
`);
}

// ————— utilidades de arranque, sin dependencias —————

function npm() {
  return process.platform === "win32" ? "npm.cmd" : "npm";
}

function paso(n, t) {
  console.log(`\n[${n}/4] ${t}`);
}

function dice(s) {
  console.log(s);
}

function fatal(s) {
  console.error(`\n✘ ${s}\n`);
  process.exit(1);
}

function corre(bin, args, { cwd = cfg.RAIZ, tolera = false, heredaSalida = false } = {}) {
  return new Promise((resolve, reject) => {
    const p = spawn(bin, args, {
      cwd,
      stdio: heredaSalida ? ["ignore", "inherit", "inherit"] : ["ignore", "pipe", "pipe"],
      // npm en Windows es un .cmd y sin shell no se ejecuta. Solo para npm: el binario
      // de Núcleo se lanza siempre sin shell.
      shell: process.platform === "win32" && bin.endsWith(".cmd"),
    });
    let out = "";
    let err = "";
    p.stdout?.on("data", (d) => (out += d));
    p.stderr?.on("data", (d) => (err += d));
    p.on("error", (e) => reject(new Error(`no se pudo ejecutar ${bin}: ${e.message}`)));
    p.on("close", (code) => {
      if (code === 0 || tolera) return resolve({ code, salida: out, error: err });
      reject(new Error(`${bin} ${args.join(" ")}\n  salió con ${code}\n  ${err.trim() || out.trim()}`));
    });
  });
}

main().catch((e) => fatal(e.message));
