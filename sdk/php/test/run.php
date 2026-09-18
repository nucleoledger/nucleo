<?php

declare(strict_types=1);

// La suite del SDK de PHP: los MISMOS vectores compartidos que verifican Go y
// TypeScript (testdata/vectors/), sin PHPUnit y sin composer.
//
// Sin PHPUnit a propósito: este paquete existe para no pedirle dependencias a nadie, y
// una suite que necesita composer para correr contradice al paquete que prueba. Lo que
// hace falta de un framework de test —comparar, contar y salir con código— son treinta
// líneas.
//
// Uso:  php sdk/php/test/run.php

require __DIR__ . '/../autoload.php';

use Nucleo\Bytes;
use Nucleo\Jcs;
use Nucleo\Merkle;
use Nucleo\Policy;
use Nucleo\Receipt;
use Nucleo\Verifier;
use Nucleo\VerifyError;

$vectores = dirname(__DIR__, 3) . '/testdata/vectors';
$fallos = [];
$pasan = 0;
$grupoActual = '';

function grupo(string $n): void
{
    global $grupoActual;
    $grupoActual = $n;
    printf("\n%s\n", $n);
}

function comprueba(string $caso, bool $ok, string $detalle = ''): void
{
    global $fallos, $pasan, $grupoActual;
    if ($ok) {
        $pasan++;
        return;
    }
    $fallos[] = sprintf('%s · %s%s', $grupoActual, $caso, $detalle === '' ? '' : ': ' . $detalle);
    printf("  ✘ %s %s\n", $caso, $detalle);
}

function igual(string $caso, $esperado, $obtenido): void
{
    comprueba($caso, $esperado === $obtenido, sprintf('esperado %s, obtenido %s', json_encode($esperado), json_encode($obtenido)));
}

function leerJSON(string $path): array
{
    $raw = file_get_contents($path);
    if ($raw === false) {
        throw new RuntimeException('no se pudo leer ' . $path);
    }
    $d = json_decode($raw, true);
    if (!is_array($d)) {
        throw new RuntimeException('JSON inválido en ' . $path);
    }
    return $d;
}

/**
 * politicaDelVector traduce la política de un vector al FORMATO DE CABLE.
 *
 * Los vectores la escriben en snake_case porque son un fichero de datos del proyecto;
 * la política de PROTOCOL.md §3.2 usa camelCase. Los tests de TypeScript hacen la misma
 * traducción. Que el verificador RECHACE la forma snake_case es lo correcto: un miembro
 * desconocido invalida la política (ADR-018).
 */
function politicaDelVector(array $p): array
{
    $out = ['origin' => $p['origin'], 'logKey' => $p['log_key']];
    if (($p['signer_key'] ?? '') !== '') {
        $out['signerKey'] = $p['signer_key'];
    }
    $out['witnesses'] = $p['witnesses'];
    $out['quorum'] = $p['quorum'];
    return $out;
}

// ---------------------------------------------------------------- leaf/v2
grupo('hoja leaf/v2 (testdata/vectors/leaf/v2.json)');
$leaf = leerJSON($vectores . '/leaf/v2.json');
igual('regla', 'leaf/v2', $leaf['leaf_rule']);
foreach ($leaf['cases'] as $c) {
    $hash = Bytes::hexToBin($c['hash_hex']);
    $sig = Bytes::hexToBin($c['signature_hex']);
    comprueba('hoja ' . $c['name'] . ': leaf_data', $hash . $sig === Bytes::hexToBin($c['leaf_data_hex']));
    igual('hoja ' . $c['name'] . ': leaf_hash', $c['leaf_hash_hex'], Bytes::binToHex(Merkle::leafHash($hash . $sig)));
}

// ---------------------------------------------------------------- Merkle
grupo('Merkle RFC 6962 (testdata/vectors/merkle/rfc6962)');
$hojas = leerJSON($vectores . '/merkle/rfc6962/leaves.json')['leaves_hex'];
$raices = leerJSON($vectores . '/merkle/rfc6962/roots.json')['roots_hex'];
$pruebas = leerJSON($vectores . '/merkle/rfc6962/inclusion.json')['proofs'];
foreach ($pruebas as $p) {
    $data = $hojas[$p['leaf_index']] === '' ? '' : Bytes::hexToBin($hojas[$p['leaf_index']]);
    $nodos = array_map(static fn(string $h): string => Bytes::hexToBin($h), $p['proof_hex']);
    $root = Bytes::hexToBin($raices[$p['tree_size'] - 1]);
    $caso = sprintf('inclusión m=%d n=%d', $p['leaf_index'], $p['tree_size']);
    comprueba($caso, Merkle::verifyInclusion($data, $p['leaf_index'], $p['tree_size'], $nodos, $root));
    // Y la misma prueba con un nodo de más: sobrar es tan inválido como faltar.
    comprueba(
        $caso . ' + nodo de relleno',
        !Merkle::verifyInclusion($data, $p['leaf_index'], $p['tree_size'], array_merge($nodos, [str_repeat("\x00", 32)]), $root)
    );
}

// ---------------------------------------------------------------- JCS
grupo('canonicidad JCS (testdata/vectors/jcs)');
// utf16-key-order es EL vector que importa aquí: el orden de claves de RFC 8785 es por
// unidades de código UTF-16, no por puntos de código, y es lo que separa una
// implementación correcta de una que "parece" correcta con claves ASCII.
$canon = file_get_contents($vectores . '/jcs/utf16-key-order/canonical.json');
$input = file_get_contents($vectores . '/jcs/utf16-key-order/input.json');
comprueba('utf16-key-order: la forma canónica se reconoce', Jcs::isCanonical(rtrim($canon, "\n")));
comprueba('utf16-key-order: el otro orden se rechaza', !Jcs::isCanonical(rtrim($input, "\n")));

// rfc8785-3.2.3 es el vector de NÚMEROS, y este verificador no los juzga: canonicalizar
// un número con fracción o exponente exige el algoritmo de RFC 8785 §3.2.2.3, que es la
// parte difícil y la que más se equivoca. Un header solo lleva cadenas y un entero
// (PROTOCOL.md §1), así que se RECHAZA en vez de adivinarse —lo mismo que hace
// TypeScript—. Se comprueba que se rechaza, para que nadie lo lea como un olvido.
$numeros = rtrim(file_get_contents($vectores . '/jcs/rfc8785-3.2.3/canonical.json'), "\n");
comprueba('rfc8785-3.2.3: los números con fracción o exponente no se juzgan', !Jcs::isCanonical($numeros));
foreach ([
    ['{"a":1,"b":"x"}', true],
    ['{"b":1,"a":2}', false],
    ['{"a": 1}', false],
    ['{"a":1,"a":2}', false],
    ['{"a":01}', false],
    ['{"a":1.0}', false],
    ['{"a":1e2}', false],
    ['[1,2]', false],
    ['{"\\u00e9":1}', false], // el escape alternativo de é no es la forma mínima
    ['{"é":1}', true],
    ['{}', true],
    ['{"a":1} ', false],
    ['', false],
] as [$txt, $want]) {
    igual('canónico ' . json_encode($txt), $want, Jcs::isCanonical($txt));
}

// ---------------------------------------------------------------- política
grupo('política, formato de cable (testdata/vectors/policy)');
$n = 0;
foreach (glob($vectores . '/policy/*.json') as $f) {
    $v = leerJSON($f);
    $n++;
    $ok = true;
    $err = '';
    try {
        Policy::fromText($v['text']);
    } catch (VerifyError $e) {
        $ok = false;
        $err = $e->getMessage();
    }
    comprueba(
        'política ' . $v['name'],
        $ok === $v['valid'],
        $v['valid'] ? 'debería valer y dice: ' . $err : 'debería fallar por: ' . $v['reason']
    );
}
comprueba('hay vectores de política', $n >= 60, sprintf('solo %d', $n));

// ---------------------------------------------------------------- recibos
grupo('recibos receipt@v2 (testdata/vectors/receipt)');
$n = 0;
foreach (glob($vectores . '/receipt/*.json') as $f) {
    $v = leerJSON($f);
    $n++;
    $r = Verifier::verify($v['receipt'], politicaDelVector($v['policy']));
    comprueba(
        'recibo ' . $v['name'],
        $r->valid === $v['valid'],
        sprintf('esperado valid=%s; razones: %s', var_export($v['valid'], true), implode(' | ', $r->reasons))
    );
    if (!$v['valid']) {
        continue;
    }
    igual('recibo ' . $v['name'] . ': tiempo declarado', $v['declared_time'], $r->declaredTime ?? '');
    igual('recibo ' . $v['name'] . ': tiempo demostrable', $v['provable_time'], $r->provableTime ?? '');
    igual('recibo ' . $v['name'] . ': índice', $v['block_index'], $r->blockIndex);
    // El dato de hoja y la firma del bloque son los del vector: si el verificador los
    // recompusiera de otra manera, la inclusión no habría verificado.
    igual('recibo ' . $v['name'] . ': regla de hoja', 'leaf/v2', $v['leaf_rule']);
}
comprueba('hay vectores de recibo', $n >= 17, sprintf('solo %d', $n));

// ---------------------------------------------------------------- no lanza nunca
grupo('el verificador no lanza con ninguna entrada');
$politica = politicaDelVector(leerJSON($vectores . '/receipt/valido-1-cosignature.json')['policy']);
$basura = [
    '',
    "\x00\x01\x02",
    Receipt::MAGIC,
    Receipt::MAGIC . "\n" . Receipt::SEPARATOR . "\n",
    Receipt::MAGIC_V1 . "\ndestinatario      : X\n" . Receipt::SEPARATOR . "\n{}\n",
    str_repeat('a', 100000),
    "\xC3", // UTF-8 truncado
];
foreach ($basura as $i => $b) {
    $r = Verifier::verify($b, $politica);
    comprueba('basura #' . $i, !$r->valid && count($r->reasons) > 0);
}
// Y con políticas rotas, que también son entrada de fuera.
$recibo = leerJSON($vectores . '/receipt/valido-1-cosignature.json')['receipt'];
foreach ([[], ['origin' => 'x'], 'no soy json', '{"origin":"x"}', ['origin' => 'x', 'logKey' => 'zz'], 42] as $i => $pol) {
    $r = Verifier::verify($recibo, $pol);
    comprueba('política rota #' . $i, !$r->valid && count($r->reasons) > 0);
}
// Sin signerKey no se verifica un recibo, aunque la política sea válida (ADR-017).
$sinSigner = $politica;
unset($sinSigner['signerKey']);
$r = Verifier::verify($recibo, $sinSigner);
comprueba('sin signerKey no hay veredicto positivo', !$r->valid);

// ---------------------------------------------------------------- sellador
grupo('sellador: el entorno se comprueba antes de sellar');
$tmp = sys_get_temp_dir();
$passOK = $tmp . '/nucleo-pass-test.txt';
file_put_contents($passOK, "correcta caballo bateria grapa\n");
if (DIRECTORY_SEPARATOR !== '\\') {
    chmod($passOK, 0600);
}
$casos = [
    ['binario que no existe', new Nucleo\Sealer($tmp . '/no-existe-nucleo', $tmp, $passOK), 'no hay ningún fichero en'],
    ['directorio que no existe', new Nucleo\Sealer($tmp . '/no-existe-nucleo', $tmp . '/tampoco', $passOK), 'no hay ningún fichero en'],
];
foreach ($casos as [$nombre, $sealer, $dice]) {
    try {
        $sealer->status();
        comprueba('sellador ' . $nombre, false, 'debería haber lanzado');
    } catch (Nucleo\SealEnvironmentError $e) {
        comprueba('sellador ' . $nombre, str_contains($e->getMessage(), $dice), $e->getMessage());
    }
}
// Y el fichero de passphrase legible por otros, donde los permisos significan algo.
if (DIRECTORY_SEPARATOR !== '\\') {
    $passMal = $tmp . '/nucleo-pass-abierta.txt';
    file_put_contents($passMal, "x\n");
    chmod($passMal, 0644);
    try {
        (new Nucleo\Sealer(PHP_BINARY, $tmp, $passMal))->status();
        comprueba('sellador passphrase legible por otros', false, 'debería haber lanzado');
    } catch (Nucleo\SealEnvironmentError $e) {
        comprueba('sellador passphrase legible por otros', str_contains($e->getMessage(), 'lo puede leer alguien más'), $e->getMessage());
    }
    @unlink($passMal);
}
@unlink($passOK);

// El sellado de punta a punta solo si hay binario: NUCLEO_BIN lo dice. Sin él no se
// silencia nada, se AVISA de que esa parte no se comprobó.
$bin = getenv('NUCLEO_BIN');
if ($bin === false || $bin === '') {
    printf("  ⚠ NUCLEO_BIN no está definida: el sellado de punta a punta NO se comprobó\n");
} else {
    require __DIR__ . '/sellado.php';
    selladoDePuntaAPunta($bin);
}

printf("\n%d comprobaciones, %d fallos\n", $pasan + count($fallos), count($fallos));
if (count($fallos) > 0) {
    print("\nfallos:\n");
    foreach ($fallos as $f) {
        printf("  - %s\n", $f);
    }
    exit(1);
}
print("✔ el SDK de PHP coincide con los vectores compartidos\n");
