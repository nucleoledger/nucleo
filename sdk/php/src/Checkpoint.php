<?php

declare(strict_types=1);

namespace Nucleo;

/**
 * Checkpoint lee el cuerpo de una nota de c2sp.org/tlog-checkpoint: origin, tamaño y
 * raíz.
 *
 * Estricto con la codificación: exactamente tres líneas, decimal sin ceros a la
 * izquierda y base64 canónico. Núcleo emite el formato mínimo y su parser rechaza líneas
 * de extensión (PROTOCOL.md §3, fallo cerrado); aceptar variantes abriría dos formas de
 * escribir el mismo checkpoint, y dos formas es una de más cuando lo que se compara son
 * bytes firmados.
 */
final class Checkpoint
{
    public string $origin;
    public int $size;
    public string $rootHash;

    private function __construct(string $origin, int $size, string $rootHash)
    {
        $this->origin = $origin;
        $this->size = $size;
        $this->rootHash = $rootHash;
    }

    public static function parse(string $text): self
    {
        if ($text === '' || substr($text, -1) !== "\n") {
            throw new VerifyError('el checkpoint no termina en salto de línea');
        }
        $lines = explode("\n", substr($text, 0, -1));
        if (count($lines) !== 3) {
            throw new VerifyError(sprintf('el checkpoint tiene %d líneas, se esperaban 3', count($lines)));
        }
        [$origin, $sizeLine, $rootLine] = $lines;
        if ($origin === '') {
            throw new VerifyError('origin vacío');
        }
        $size = Bytes::decimalCanonical($sizeLine);
        if ($size === null) {
            throw new VerifyError(sprintf('tamaño no canónico o fuera de rango: %s', json_encode($sizeLine)));
        }
        $root = Bytes::base64Canonical($rootLine);
        if ($root === null) {
            throw new VerifyError('la raíz no está en base64 canónico');
        }
        if (strlen($root) !== 32) {
            throw new VerifyError(sprintf('la raíz mide %d bytes, se esperaban 32', strlen($root)));
        }
        return new self($origin, $size, $root);
    }
}
