<?php

declare(strict_types=1);

// El sellado de punta a punta: PHP ejecutando el binario de verdad.
//
// Se separa de run.php porque necesita un binario y un despliegue nuevo, y porque así
// se ve de un vistazo qué parte de la suite depende de algo externo. Se activa con
// NUCLEO_BIN apuntando al ejecutable `nucleo`.

use Nucleo\SealError;
use Nucleo\SealUsageError;
use Nucleo\Sealer;

function selladoDePuntaAPunta(string $bin): void
{
    grupo('sellador de punta a punta (NUCLEO_BIN=' . $bin . ')');

    $dir = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'nucleo-php-' . bin2hex(random_bytes(6));
    if (!mkdir($dir, 0700, true)) {
        comprueba('crear el despliegue', false, 'no se pudo crear ' . $dir);
        return;
    }
    $pass = $dir . DIRECTORY_SEPARATOR . 'pass.txt';
    file_put_contents($pass, "correcta caballo bateria grapa\n");
    if (DIRECTORY_SEPARATOR !== '\\') {
        chmod($pass, 0600);
    }

    // init lo hace la CLI directamente: crear el vault no es trabajo del sellador.
    $init = [$bin, '--dir', $dir, '--json', 'init', '--origin', 'nucleoledger.com/php',
        '--passphrase-file', $pass, '--assume-confirmed'];
    $proc = proc_open($init, [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
    if (!is_resource($proc)) {
        comprueba('init', false, 'no se pudo ejecutar ' . $bin);
        return;
    }
    fclose($pipes[0]);
    $salida = stream_get_contents($pipes[1]);
    $errInit = stream_get_contents($pipes[2]);
    fclose($pipes[1]);
    fclose($pipes[2]);
    $codigo = proc_close($proc);
    comprueba('init', $codigo === 0, 'código ' . $codigo . ': ' . substr($errInit, 0, 300));
    if ($codigo !== 0) {
        return;
    }
    unset($salida);

    $sealer = new Sealer($bin, $dir, $pass);
    $documento = '{"factura":"001","total":"120.50"}';

    // 1. Un sellado normal.
    $r = $sealer->sealBytes($documento, 'sri.factura.v1', '1790012345001');
    comprueba('sellar', $r->index === 0 && $r->hash !== '', 'índice ' . $r->index);
    comprueba('sellar: hash del contenido', $r->payloadHash === hash('sha256', $documento), $r->payloadHash);
    comprueba('sellar: no es idempotente', !$r->idempotent);
    comprueba('sellar: sin atestación todavía', !$r->attested && $r->stale);

    // 2. El mismo contenido otra vez: bloque NUEVO, y lo dice (ADR-020 §A).
    $r2 = $sealer->sealBytes($documento, 'sri.factura.v1', '1790012345001');
    comprueba('re-sellar: bloque nuevo', $r2->index === 1, 'índice ' . $r2->index);
    comprueba('re-sellar: dice de qué es duplicado', $r2->duplicateOf === [0], json_encode($r2->duplicateOf));

    // 3. Con clave de idempotencia: el reintento NO escribe nada (ADR-020 §D). Es el
    // caso del ERP que reintenta tras un timeout, que es el motivo del sprint.
    $r3 = $sealer->sealBytes($documento, 'sri.factura.v1', '1790012345001', 'factura-001');
    comprueba('clave nueva: sella', !$r3->idempotent && $r3->index === 2, 'índice ' . $r3->index);
    $r4 = $sealer->sealBytes($documento, 'sri.factura.v1', '1790012345001', 'factura-001');
    comprueba('reintento: idempotente', $r4->idempotent, 'idempotent=' . var_export($r4->idempotent, true));
    comprueba('reintento: el mismo bloque', $r4->index === $r3->index, $r4->index . ' vs ' . $r3->index);

    // 4. La misma clave para otro documento es un error de USO, tipado.
    try {
        $sealer->sealBytes('{"otro":"documento"}', 'sri.factura.v1', '1790012345001', 'factura-001');
        comprueba('clave reutilizada para otro documento', false, 'debería haber lanzado');
    } catch (SealUsageError $e) {
        comprueba(
            'clave reutilizada para otro documento',
            str_contains($e->getMessage(), 'ya se usó para otro documento'),
            $e->getMessage()
        );
        comprueba('el error lleva el código de salida', $e->exitCode === 1, (string) $e->exitCode);
    } catch (SealError $e) {
        comprueba('clave reutilizada para otro documento', false, 'tipo ' . get_class($e) . ': ' . $e->getMessage());
    }

    // 5. status como lo miraría un cron.
    $st = $sealer->status();
    comprueba('status: tamaño del árbol', ($st['tree_size'] ?? -1) === 3, json_encode($st['tree_size'] ?? null));

    // Y el despliegue se borra: es un test, no un despliegue.
    borrarArbol($dir);
}

function borrarArbol(string $dir): void
{
    foreach (scandir($dir) ?: [] as $f) {
        if ($f === '.' || $f === '..') {
            continue;
        }
        $ruta = $dir . DIRECTORY_SEPARATOR . $f;
        is_dir($ruta) ? borrarArbol($ruta) : @unlink($ruta);
    }
    @rmdir($dir);
}
