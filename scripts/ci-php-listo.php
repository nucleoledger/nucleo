<?php

declare(strict_types=1);

// ¿Está este PHP en condiciones de ser el TERCER verificador? (ADR-021 §F)
//
// Existe como FICHERO y no como `php -r '…'` dentro del workflow por un defecto real:
// en el run 35314100642 la línea
//
//     php -r 'exit(extension_loaded("sodium") ? 0 : 1)'
//
// llegó a PHP truncada —"syntax error, unexpected end of file"— porque las comillas no
// sobreviven al paso por YAML y por el shell. Un fichero no tiene comillas que anidar.
//
// Y comprueba, no instala: la extensión la entrega shivammathur/setup-php, que es
// determinista. Si lo prometido no está, este script lo dice y el job FALLA. En el CI el
// tercer verificador no es opcional; el diferencial sí tolera su ausencia en una máquina
// de desarrollo, y entonces lo dice en voz alta.
//
// Uso:  php scripts/ci-php-listo.php

$fallos = [];

// La versión mínima que el SDK declara (sdk/php/README.md).
if (PHP_VERSION_ID < 80000) {
    $fallos[] = sprintf('PHP %s: el SDK necesita 8.0 o superior', PHP_VERSION);
}

foreach (['sodium' => 'Ed25519', 'json' => 'JSON'] as $ext => $para) {
    if (!extension_loaded($ext)) {
        $fallos[] = sprintf('falta la extensión %s (%s)', $ext, $para);
    }
}

// Que la extensión esté cargada no es lo mismo que que funcione: se firma y se verifica
// una vez, que es lo que el verificador hará tres mil veces dentro de un minuto.
if (extension_loaded('sodium')) {
    $par = sodium_crypto_sign_keypair();
    $firma = sodium_crypto_sign_detached('nucleo', sodium_crypto_sign_secretkey($par));
    if (!sodium_crypto_sign_verify_detached($firma, 'nucleo', sodium_crypto_sign_publickey($par))) {
        $fallos[] = 'sodium está cargada pero una firma Ed25519 recién hecha no verifica';
    }
}

if ($fallos !== []) {
    fwrite(STDERR, "este PHP no puede ser el tercer verificador del diferencial:\n");
    foreach ($fallos as $f) {
        fwrite(STDERR, '  - ' . $f . "\n");
    }
    fwrite(STDERR, "\nLo entrega shivammathur/setup-php en .github/workflows/ci.yml; si esto falla,\n");
    fwrite(STDERR, "la acción no dio lo prometido y hay que arreglarlo ahí, no saltarse el verificador.\n");
    exit(1);
}

printf("PHP %s con sodium y json: listo para el diferencial\n", PHP_VERSION);
