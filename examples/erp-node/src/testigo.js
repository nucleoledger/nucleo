// Levantar un testigo de juguete.
//
// En producción el testigo es de OTRO: su valor entero está en que no es tuyo (ADR-003).
// Aquí se levanta uno local porque el ejemplo tiene que poder correr en un portátil sin
// pedirle nada a nadie, y porque sin cosignature no hay tiempo demostrable y el recibo
// del cliente se queda sin la mitad de lo que promete.

import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdirSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import * as cfg from "./config.js";

/** claveDelTestigo lee la clave pública del testigo de su base. */
export async function claveDelTestigo(db) {
  const { salida } = await ejecuta(cfg.BINARIO, ["--json", "witness", "key", "--db", db]);
  return JSON.parse(salida);
}

/**
 * levanta un testigo escuchando en `puerto` y espera a que conteste.
 *
 * Devuelve `{ url, para }`. `para()` lo mata: quien lo levanta lo apaga, también si la
 * demo se va por una excepción.
 */
export async function levanta({ puerto = 8099, logKey, origin = cfg.ORIGIN, nombre = "testigo-local" } = {}) {
  const db = join(dirDelTestigo(), "testigo.db");
  const p = spawn(
    cfg.BINARIO,
    ["witness", "serve", "--addr", `127.0.0.1:${puerto}`, "--db", db,
      "--name", nombre, "--log-origin", origin, "--log-key", logKey],
    { stdio: ["ignore", "inherit", "inherit"] },
  );
  const url = `http://127.0.0.1:${puerto}`;
  let vivo = true;
  p.on("exit", (c) => {
    vivo = false;
    if (c !== 0 && c !== null) console.error(`[testigo] terminó con código ${c}`);
  });

  // Espera activa con tope: un testigo que no arranca en cinco segundos no va a
  // arrancar, y colgarse esperándolo es peor que decirlo.
  const limite = Date.now() + 5_000;
  for (;;) {
    if (!vivo) throw new Error("el testigo no arrancó; mira su salida más arriba");
    if (await responde(url)) break;
    if (Date.now() > limite) {
      p.kill("SIGKILL");
      throw new Error(`el testigo no contestó en ${url} en cinco segundos`);
    }
    await new Promise((r) => setTimeout(r, 120));
  }
  return { url, db, para: () => p.kill("SIGTERM") };
}

/**
 * dirDelTestigo elige dónde vive la memoria —y la CLAVE PRIVADA— del testigo.
 *
 * Núcleo se niega a servir con una clave privada que otros usuarios puedan leer, y hace
 * bien. El problema es que en un directorio que no guarda permisos POSIX —/mnt/c bajo
 * WSL, un recurso compartido de red— todo fichero se reporta 0777 y `chmod 600` no lo
 * cambia: el testigo arranca la primera vez, cuando crea la clave, y no vuelve a
 * arrancar nunca. Lo encontró este ejemplo, y de ahí salió el mensaje que hoy da la CLI.
 *
 * Así que el ejemplo se aparta: si el directorio de datos no guarda permisos, la memoria
 * del testigo se va a un temporal que sí los guarda, y se dice en voz alta. Los datos del
 * ERP —ledger incluido— se quedan donde están: eso no lo impide nada.
 */
export function dirDelTestigo() {
  if (process.env.NUCLEO_TESTIGO_DB) {
    const d = process.env.NUCLEO_TESTIGO_DB;
    mkdirSync(d, { recursive: true });
    return d;
  }
  const preferido = join(cfg.DATOS, "testigo");
  mkdirSync(preferido, { recursive: true });
  // En Windows no se comprueba nada, por lo mismo que no lo comprueba la CLI: el control
  // de acceso está en la ACL y los permisos que expone el sistema son una traducción.
  if (process.platform === "win32" || guardaPermisos(preferido)) return preferido;
  // El nombre lleva un resumen del directorio de datos: dos despliegues del ejemplo
  // —el de la interfaz y el de la demo— no pueden compartir la memoria del testigo. Un
  // testigo que ya cosignó otra historia con el mismo origin vería un retroceso donde
  // solo hay otro ledger.
  const marca = createHash("sha256").update(cfg.DATOS).digest("hex").slice(0, 8);
  const alterna = join(tmpdir(), `nucleo-ejemplo-testigo-${marca}`);
  mkdirSync(alterna, { recursive: true });
  console.error(
    `[testigo] ${preferido}\n` +
      "          no guarda permisos POSIX (típico de /mnt/c en WSL), y la clave privada del\n" +
      "          testigo se reportaría legible por otros usuarios. Núcleo se negaría a servir.\n" +
      `          Su memoria va entonces a ${alterna}.`,
  );
  return alterna;
}

/** guardaPermisos prueba si un directorio conserva lo que se le pide con chmod. */
function guardaPermisos(dir) {
  const f = join(dir, ".prueba-de-permisos");
  try {
    rmSync(f, { force: true });
    writeFileSync(f, "x", { mode: 0o600 });
    return (statSync(f).mode & 0o777) === 0o600;
  } catch {
    // Si no se puede probar, se prefiere el directorio de datos: inventar una mudanza
    // porque no se pudo escribir un fichero de prueba sería peor.
    return true;
  } finally {
    rmSync(f, { force: true });
  }
}

/** responde dice si hay un testigo escuchando. No le pide nada: solo mira. */
export async function responde(url) {
  try {
    // Cualquier respuesta HTTP sirve: lo que se comprueba es que alguien escucha. Un
    // 404 de un testigo vivo es una respuesta.
    await fetch(new URL("/", url), { signal: AbortSignal.timeout(800) });
    return true;
  } catch {
    return false;
  }
}

function ejecuta(bin, args) {
  return new Promise((resolve, reject) => {
    const p = spawn(bin, args, { stdio: ["ignore", "pipe", "pipe"] });
    let out = "";
    let err = "";
    p.stdout.on("data", (d) => (out += d));
    p.stderr.on("data", (d) => (err += d));
    p.on("error", reject);
    p.on("close", (c) =>
      c === 0 ? resolve({ salida: out }) : reject(new Error(`${args.join(" ")} salió con ${c}: ${(err + out).trim()}`)),
    );
  });
}
