<?php

declare(strict_types=1);

// Autoload a mano: nueve líneas y ninguna dependencia.
//
// No hay composer a propósito (ADR-021 §D). Este paquete existe para que quien recibe
// una factura pueda comprobarla sin instalar nada, y un árbol de dependencias en un
// verificador es exactamente lo que no queremos pedirle.

spl_autoload_register(static function (string $class): void {
    $prefix = 'Nucleo\\';
    if (!str_starts_with($class, $prefix)) {
        return;
    }
    $rel = str_replace('\\', '/', substr($class, strlen($prefix)));
    $file = __DIR__ . '/src/' . $rel . '.php';
    if (is_file($file)) {
        require $file;
    }
});

// Las extensiones se comprueban al cargar, no al fallar. Un proveedor puede desactivar
// sodium, y el error natural sería "función no definida" en medio de una verificación.
foreach (['sodium' => 'Ed25519', 'json' => 'JSON'] as $ext => $para) {
    if (!extension_loaded($ext)) {
        throw new RuntimeException(sprintf(
            'el SDK de Núcleo necesita la extensión PHP "%s" (%s) y no está cargada. ' .
            'Viene con PHP desde 7.2; si tu proveedor la ha desactivado, pídele que la habilite.',
            $ext,
            $para
        ));
    }
}
