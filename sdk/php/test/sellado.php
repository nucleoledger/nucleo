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

    // 6. LA POLÍTICA LLEGA AL BINARIO (hallazgo alto del 2026-09-19).
    //
    // El test de argv demuestra que la bandera se construye; esto demuestra que la CLI
    // la HONRA, que es la otra mitad. Se mira por tres sitios, de menos a más duro:
    //
    //   freshness.policy   la propia salida dice si hubo política
    //   signer.verified    la identidad del firmante solo se verifica CON política
    //   exit 2             una política de otro log no abre el ledger
    //
    // Lo que no se comprueba aquí es la atestación verificada: eso exige un testigo
    // cosignando, y ese camino lo cubren la suite de Go y el criterio de éxito. Lo que
    // faltaba —y es lo que se arregla— era saber si la bandera llegaba.
    comprueba('sin política: la salida dice que no hubo política',
        ($st['freshness']['policy'] ?? null) === false, json_encode($st['freshness'] ?? null));
    comprueba('sin política: el firmante NO está verificado',
        ($st['signer']['verified'] ?? null) === false, json_encode($st['signer'] ?? null));

    $politica = $dir . DIRECTORY_SEPARATOR . 'politica.json';
    $buena = [
        'origin' => (string) $st['origin'],
        'logKey' => (string) $st['log_pubkey'],
        'signerKey' => (string) $st['signer_pubkey'],
        // Un testigo cualquiera: la política exige al menos uno (PROTOCOL §3.2) y para
        // esta comprobación da igual quién sea, porque no hay checkpoint que cosignar.
        'witnesses' => ['witness.example/w1' => str_repeat('33', 32)],
        'quorum' => 1,
    ];
    file_put_contents($politica, json_encode($buena));
    if (DIRECTORY_SEPARATOR !== '\\') {
        chmod($politica, 0600);
    }

    $conPolitica = new Sealer($bin, $dir, $pass, $politica);
    $st2 = $conPolitica->status();
    comprueba('con política: la salida dice que SÍ hubo política',
        ($st2['freshness']['policy'] ?? null) === true, json_encode($st2['freshness'] ?? null));
    comprueba('con política: el firmante queda VERIFICADO',
        ($st2['signer']['verified'] ?? null) === true, json_encode($st2['signer'] ?? null));
    comprueba('con política: la clave publicada es la que fija la política',
        ($st2['signer']['pubkey'] ?? '') === $buena['signerKey'], json_encode($st2['signer'] ?? null));

    // Y sellar con la política puesta sigue funcionando, con la política dentro.
    $r5 = $conPolitica->sealBytes('{"con":"politica"}', 'sri.factura.v1', '1790012345001', 'factura-pol');
    comprueba('sellar con política: entra', $r5->index === 3, 'índice ' . $r5->index);
    comprueba('sellar con política: la salida lo refleja',
        ($r5->raw['freshness']['policy'] ?? null) === true, json_encode($r5->raw['freshness'] ?? null));

    // 7. Una política de OTRO log no abre este ledger: exit 2, excepción tipada.
    $mala = $buena;
    $mala['logKey'] = str_repeat('44', 32);
    $politicaMala = $dir . DIRECTORY_SEPARATOR . 'politica-ajena.json';
    file_put_contents($politicaMala, json_encode($mala));
    try {
        (new Sealer($bin, $dir, $pass, $politicaMala))->status();
        comprueba('política de otro log: se rechaza', false, 'debería haber lanzado');
    } catch (Nucleo\SealIntegrityError $e) {
        comprueba('política de otro log: se rechaza con código 2',
            $e->exitCode === 2 && str_contains($e->getMessage(), 'clave del log'), $e->getMessage());
    } catch (SealError $e) {
        comprueba('política de otro log: se rechaza', false, 'tipo ' . get_class($e) . ': ' . $e->getMessage());
    }

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
