<?php

declare(strict_types=1);

// El PHP del diferencial: un proceso, no uno por caso (ADR-021 §F).
//
// Lee el catálogo de mutaciones que genera internal/receipt/diferencial_test.go —cada
// una con el veredicto de Go ya anotado— y escribe por la salida estándar el dictamen de
// PHP para cada caso, en el mismo orden. Quien compara es scripts/diferencial.mjs.
//
// Un proceso por caso serían trece mil arranques de PHP: veinte minutos de compuerta
// para lo que así son segundos. La forma del dictamen es la de Result::toArray, que es
// la que emiten Go y TypeScript.
//
// Uso:  php sdk/php/bin/dictamen.php <catalogo.json>
//       php sdk/php/bin/dictamen.php -        (el catálogo por la entrada estándar)
//
// El "-" no es adorno: en WSL con el PHP de Windows, ninguna ruta sirve para los dos
// —Node quiere /tmp/… y php.exe quiere C:\…— y por la entrada estándar no hay ruta que
// traducir. Es también lo que usa el diferencial.

require dirname(__DIR__) . '/autoload.php';

use Nucleo\Policy;
use Nucleo\Verifier;

// El catálogo son 15 MB de JSON y decodificarlo cuesta memoria. Se sube el límite aquí
// y no en el php.ini de nadie: es una herramienta de desarrollo del propio repositorio.
ini_set('memory_limit', '1G');

$catalogoPath = $argv[1] ?? '';
if ($catalogoPath === '') {
    fwrite(STDERR, "uso: php bin/dictamen.php <catalogo.json|->\n");
    exit(2);
}
$raw = $catalogoPath === '-' ? stream_get_contents(STDIN) : file_get_contents($catalogoPath);
if ($raw === false || $raw === '') {
    fwrite(STDERR, sprintf("no se pudo leer %s\n", $catalogoPath === '-' ? 'el catálogo de la entrada estándar' : $catalogoPath));
    exit(2);
}
$catalogo = json_decode($raw, true);
unset($raw);
if (!is_array($catalogo) || !isset($catalogo['casos'])) {
    fwrite(STDERR, "el catálogo no tiene la forma esperada\n");
    exit(2);
}

$salida = ['casos' => [], 'politicas' => []];
foreach ($catalogo['casos'] as $c) {
    // La política del catálogo ya viene en el formato de cable (camelCase), que es lo
    // que el verificador acepta.
    $r = Verifier::verify((string) $c['receipt'], $c['policy']);
    $salida['casos'][] = $r->toArray();
}
foreach ($catalogo['politicas'] ?? [] as $p) {
    $ok = true;
    $err = '';
    try {
        Policy::fromText((string) $p['texto']);
    } catch (\Throwable $e) {
        $ok = false;
        $err = $e->getMessage();
    }
    $salida['politicas'][] = ['ok' => $ok, 'err' => $err];
}

$json = json_encode($salida, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_PARTIAL_OUTPUT_ON_ERROR);
if ($json === false) {
    fwrite(STDERR, 'no se pudo serializar el dictamen: ' . json_last_error_msg() . "\n");
    exit(2);
}
print($json);
