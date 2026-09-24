#!/usr/bin/env node
// npm run cron -- sync | semanal | estado
//
// La receta que dejó funcionando el ensayo de operación (Sprint 10), envuelta para que
// se pueda pegar en un crontab sin pensar:
//
//   0 * * * * cd /ruta/al/ejemplo && node bin/cron.js sync     >> datos/cron.log 2>&1
//   0 3 * * 0 cd /ruta/al/ejemplo && node bin/cron.js semanal  >> datos/cron.log 2>&1
//
// Tres cosas que el ensayo dejó claras y que este script respeta:
//
//   · stderr NO se redirige a stdout dentro del script. Los avisos de frescura y de
//     rollback salen por ahí también con --json, y un cron con stderr al correo hace
//     sonar la alarma sin programar nada. Mezclarlos con la salida normal la apaga.
//   · `sync` FIRMA un checkpoint, así que necesita la passphrase por fichero. `status`
//     no la necesita: no firma nada. Un cron que pide la passphrase por terminal se
//     queda colgado para siempre, porque no hay terminal.
//   · el código de salida se propaga tal cual. 0 todo bien, 2 integridad, 3 el testigo
//     no contestó. Un cron que siempre sale 0 no se puede vigilar.

import * as cfg from "../src/config.js";
import { ErrorDeIntegridad, ErrorDeNucleo, ErrorDeSincronizacion } from "../src/nucleo.js";

const tarea = process.argv[2] ?? "sync";
const nucleo = cfg.nucleo();
const sello = new Date().toISOString();

try {
  switch (tarea) {
    case "sync": {
      const s = await nucleo.sincroniza({ witnessURL: cfg.TESTIGO });
      console.log(`${sello} sync ok: ${s.localSize} bloques aquí, el testigo tenía ${s.witnessSize}, atestiguado=${s.attested}`);
      if (s.replaySuspect) {
        console.log(`${sello} OJO: la cosignature del testigo ya nacía vieja (replay_suspect)`);
      }
      break;
    }
    case "semanal": {
      const v = await nucleo.verifica({ completa: true });
      console.log(`${sello} verify --full ok: ${v.treeSize} bloques, modo ${v.modo}`);
      const e = await nucleo.estado();
      console.log(`${sello} status: atestación=${e.attestation} cabeza=${e.attestedHead} vieja=${e.freshness.stale}`);
      break;
    }
    case "estado": {
      const e = await nucleo.estado();
      console.log(`${sello} ${e.origin}: ${e.treeSize} bloques, atestación ${e.attestation}, firmante verificado=${e.signer.verified}`);
      if (e.rollback) console.log(`${sello} ✘ ROLLBACK REGISTRADO: ${JSON.stringify(e.rollback)}`);
      break;
    }
    default:
      console.error(`tareas: sync | semanal | estado  (llegó ${JSON.stringify(tarea)})`);
      process.exit(1);
  }
} catch (e) {
  // El cron no "gestiona" el error: lo escribe y propaga el código. Quien decide qué
  // hacer con un 2 es una persona, y con un 3, el siguiente sync.
  console.error(`${sello} ${tarea} FALLÓ: ${e.message}`);
  if (e instanceof ErrorDeIntegridad) {
    console.error(`${sello} código 2: es un incidente de integridad. No reintentes: mira qué pasó.`);
  } else if (e instanceof ErrorDeSincronizacion) {
    console.error(`${sello} código 3: incidente operativo. El sellado no depende de esto y sigue.`);
  }
  process.exit(e instanceof ErrorDeNucleo && e.exitCode > 0 ? e.exitCode : 1);
}
