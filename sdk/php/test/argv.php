<?php

declare(strict_types=1);

// Qué línea de comandos construye el Sealer, comprobada con un binario FALSO.
//
// Es la prueba que faltaba y por la que el hallazgo alto de la auditoría del 2026-09-19
// llegó a existir: el constructor aceptaba una política, la guardaba, y ni seal() ni
// status() la pasaban al binario. Ninguna prueba miraba la línea de comandos, así que
// nada podía cazarlo — el sellado funcionaba, solo que sin raíz de confianza.
//
// El binario falso escribe su argv, un argumento por línea, y contesta un JSON válido.
// No hace falta un ledger, ni un vault, ni el binario de verdad para comprobar qué se le
// pide: solo hace falta mirar.

use Nucleo\SealEnvironmentError;
use Nucleo\Sealer;

/** entorno crea el despliegue falso y devuelve sus rutas. */
function entornoFalso(string $nombre): array
{
    $dir = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'nucleo-argv-' . $nombre . '-' . bin2hex(random_bytes(4));
    mkdir($dir, 0700, true);
    $ventanas = DIRECTORY_SEPARATOR === '\\';
    $bin = $dir . DIRECTORY_SEPARATOR . ($ventanas ? 'falso.cmd' : 'falso.sh');
    $argv = $dir . DIRECTORY_SEPARATOR . 'argv.txt';
    $salida = $dir . DIRECTORY_SEPARATOR . 'salida.json';

    if ($ventanas) {
        // UNA sola escritura, con la línea entera. La versión que escribía un argumento
        // por línea en un bucle se topó con "Acceso denegado" a partir del segundo
        // `>>`: algo del sistema —el antivirus, lo más probable— se queda un instante
        // con el fichero recién creado en Temp. Escribir una vez lo esquiva, y la prueba
        // no está aquí para pelearse con eso.
        $script = "@echo off\r\necho %* > \"%~dp0argv.txt\"\r\ntype \"%~dp0salida.json\"\r\n";
    } else {
        $script = "#!/bin/sh\nprintf '%s\\n' \"\$@\" > \"\$(dirname \"\$0\")/argv.txt\"\n"
            . "cat \"\$(dirname \"\$0\")/salida.json\"\n";
    }
    file_put_contents($bin, $script);
    if (!$ventanas) {
        chmod($bin, 0700);
    }
    // La salida del binario falso sale de los VECTORES DEL CONTRATO, no de una lista de
    // campos escrita aquí: `seal` y `status` mezclados en un objeto, que es legítimo
    // porque el contrato ignora lo que no conoce (ADR-025 §B). Así el falso contesta lo
    // que contesta la CLI de verdad, y si el contrato cambia, cambia aquí también.
    $vectores = dirname(__DIR__, 3) . '/testdata/vectors/cli-json';
    $deSeal = json_decode(json_decode(file_get_contents($vectores . '/valido-seal.json'), true)['stdout'], true);
    $deStatus = json_decode(json_decode(file_get_contents($vectores . '/valido-status-vacio.json'), true)['stdout'], true);
    file_put_contents($salida, json_encode(array_merge($deStatus, $deSeal)));

    $pass = $dir . DIRECTORY_SEPARATOR . 'pass.txt';
    file_put_contents($pass, "correcta caballo bateria grapa\n");
    $politica = $dir . DIRECTORY_SEPARATOR . 'politica.json';
    file_put_contents($politica, json_encode([
        'origin' => 'nucleoledger.com/pruebas',
        'logKey' => str_repeat('11', 32),
        'signerKey' => str_repeat('22', 32),
        'witnesses' => ['witness.example/w1' => str_repeat('33', 32)],
        'quorum' => 1,
    ]));
    if (!$ventanas) {
        chmod($pass, 0600);
    }
    return ['dir' => $dir, 'bin' => $bin, 'pass' => $pass, 'politica' => $politica, 'argv' => $argv];
}

/**
 * argvDe devuelve la línea de comandos que recibió el binario falso, como lista.
 *
 * Los dos sistemas escriben distinto y se leen distinto: Unix un argumento por línea,
 * Windows la línea entera —donde cmd.exe conserva las comillas que puso PHP—. Lo que la
 * prueba compara después es lo mismo en los dos.
 */
function argvDe(array $e): array
{
    $raw = file_get_contents($e['argv']);
    if ($raw === false) {
        return [];
    }
    $out = [];
    if (DIRECTORY_SEPARATOR === '\\') {
        preg_match_all('/"([^"]*)"|(\S+)/', trim($raw), $m, PREG_SET_ORDER);
        foreach ($m as $t) {
            $out[] = $t[1] !== '' ? $t[1] : ($t[2] ?? '');
        }
        return $out;
    }
    foreach (preg_split("/\r\n|\n|\r/", $raw) as $l) {
        if ($l !== '') {
            $out[] = $l;
        }
    }
    return $out;
}

function pruebasDeArgv(): void
{
    grupo('el Sealer construye la línea de comandos que dice construir');

    // ---- con política: el hallazgo alto ---------------------------------------------
    $e = entornoFalso('conpolitica');
    $sealer = new Sealer($e['bin'], $e['dir'], $e['pass'], $e['politica']);

    @unlink($e['argv']);
    $sealer->status();
    $argv = argvDe($e);
    comprueba('status: --policy-file va en la línea', in_array('--policy-file', $argv, true), implode(' ', $argv));
    $i = array_search('--policy-file', $argv, true);
    comprueba(
        'status: la ruta de la política viene detrás de la bandera',
        $i !== false && ($argv[$i + 1] ?? '') === $e['politica'],
        implode(' ', $argv)
    );
    // El orden NO es cosmético: --dir y --json son globales y van antes del subcomando;
    // --policy-file lo registra el subcomando y va después. Al revés, la CLI contesta
    // "subcomando desconocido" y el envoltorio parecería roto por otro motivo.
    $sub = array_search('status', $argv, true);
    comprueba('status: el subcomando va antes de --policy-file', $sub !== false && $i !== false && $sub < $i, implode(' ', $argv));
    comprueba('status: --dir y --json van antes del subcomando',
        array_search('--dir', $argv, true) < $sub && array_search('--json', $argv, true) < $sub, implode(' ', $argv));

    @unlink($e['argv']);
    $sealer->sealBytes('{"x":1}', 'sri.factura.v1', '1790012345001', 'factura-001');
    $argv = argvDe($e);
    $i = array_search('--policy-file', $argv, true);
    comprueba('seal: --policy-file va en la línea', $i !== false, implode(' ', $argv));
    comprueba('seal: con su ruta detrás', ($argv[$i + 1] ?? '') === $e['politica'], implode(' ', $argv));
    comprueba('seal: el subcomando va primero', ($argv[array_search('--json', $argv, true) + 1] ?? '') === 'seal', implode(' ', $argv));
    comprueba('seal: la clave de idempotencia se pasa', in_array('--idempotency-key', $argv, true) && in_array('factura-001', $argv, true), implode(' ', $argv));
    comprueba('seal: la passphrase va por FICHERO', in_array('--passphrase-file', $argv, true), implode(' ', $argv));
    // La passphrase misma no puede aparecer en argv: la lista de procesos la ve toda la
    // máquina. Es una promesa del README y aquí se comprueba, no se supone.
    comprueba('seal: la passphrase NO aparece en los argumentos',
        !in_array('correcta caballo bateria grapa', $argv, true), implode(' ', $argv));

    // ---- sin política: no se inventa ninguna ---------------------------------------
    $e2 = entornoFalso('sinpolitica');
    (new Sealer($e2['bin'], $e2['dir'], $e2['pass']))->status();
    $argv2 = argvDe($e2);
    comprueba('sin política: no aparece --policy-file', !in_array('--policy-file', $argv2, true), implode(' ', $argv2));

    // ---- --no-encrypt -------------------------------------------------------------
    @unlink($e2['argv']);
    (new Sealer($e2['bin'], $e2['dir'], $e2['pass']))->sealBytes('{"x":2}', 't.v1', 'T1', null, false);
    $argv3 = argvDe($e2);
    comprueba('--no-encrypt se pasa cuando se pide', in_array('--no-encrypt', $argv3, true), implode(' ', $argv3));
    comprueba('sin clave de idempotencia no se pasa la bandera', !in_array('--idempotency-key', $argv3, true), implode(' ', $argv3));

    // ---- la política que no está no se ignora -------------------------------------
    // Seguir sin ella sería volver al hallazgo por otro camino: el integrador pidió una
    // raíz de confianza y el sellado se haría sin verificar nada.
    try {
        (new Sealer($e2['bin'], $e2['dir'], $e2['pass'], $e2['dir'] . '/no-existe.json'))->status();
        comprueba('una política que no existe aborta el sellado', false, 'debería haber lanzado');
    } catch (SealEnvironmentError $ex) {
        comprueba('una política que no existe aborta el sellado',
            str_contains($ex->getMessage(), 'no hay fichero de política'), $ex->getMessage());
    }

    borrarArbol($e['dir']);
    borrarArbol($e2['dir']);
}
