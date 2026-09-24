#!/usr/bin/env node
// npm run testigo — un testigo escuchando, para que el ERP tenga a quién pedirle fe.
//
// Es un proceso aparte a propósito. En producción el testigo NO corre en tu máquina: es
// de un tercero, y ahí está todo su valor. Tenerlo en otra terminal, con su propia
// salida, es lo más parecido a eso que cabe en un portátil.

import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import * as cfg from "../src/config.js";
import { claveDelTestigo, levanta } from "../src/testigo.js";

const db = join(cfg.DIR_LEDGER, "nucleo.db");
if (!existsSync(db)) {
  console.error(`No hay ledger en ${cfg.DIR_LEDGER}. Ejecuta primero:  npm run setup`);
  process.exit(1);
}

// El testigo necesita saber a qué log sirve: su origin y su clave pública. No las
// adivina, y no debería: un testigo que cosigna cualquier cosa que le llegue no sirve
// de testigo de nada.
const politica = existsSync(cfg.FICHERO_POLITICA)
  ? JSON.parse(readFileSync(cfg.FICHERO_POLITICA, "utf8"))
  : null;
if (!politica?.logKey) {
  console.error(`No hay política en ${cfg.FICHERO_POLITICA}. Ejecuta primero:  npm run setup`);
  process.exit(1);
}

const puerto = new URL(cfg.TESTIGO).port || 8099;
const t = await levanta({ puerto, logKey: politica.logKey, origin: politica.origin });
const clave = await claveDelTestigo(t.db);
console.log(`\nTestigo escuchando en ${t.url}`);
console.log(`  sirve al log : ${politica.origin}`);
console.log(`  su clave     : ${clave.public_key}`);
console.log(`  en la política del ERP: ${Object.keys(politica.witnesses ?? {}).join(", ") || "ninguno"}`);

// Si la clave de este testigo no es la que lleva la política, el ERP rechazará sus
// cosignatures —y hará bien—. Pasa cuando la memoria del testigo se pierde: al arrancar
// se crea una clave nueva, y la anterior no vuelve. Decirlo aquí ahorra el paseo por
// "lo que contestó el testigo no es una cosignature válida", que es un mensaje correcto
// y desconcertante si no sabes que cambiaste de testigo.
const enPolitica = Object.values(politica.witnesses ?? {});
if (enPolitica.length && !enPolitica.includes(clave.public_key)) {
  console.error(`
✘ OJO: la política del ERP espera otra clave de testigo.
    espera : ${enPolitica.join(", ")}
    esta es: ${clave.public_key}
  El ERP rechazará las cosignatures de este testigo, y hará bien: la política es lo
  único en lo que confía. Pasa cuando la memoria del testigo se pierde y arranca con
  una clave nueva.
  Arreglo en el ejemplo: borra datos/ y vuelve a ejecutar  npm run setup
`);
}

console.log("\nCtrl-C para pararlo.\n");

for (const s of ["SIGINT", "SIGTERM"]) {
  process.on(s, () => {
    t.para();
    process.exit(0);
  });
}
