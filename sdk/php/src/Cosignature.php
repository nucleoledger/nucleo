<?php

declare(strict_types=1);

namespace Nucleo;

/**
 * Cosignature es una cosignature de c2sp.org/tlog-cosignature@v1.
 *
 * El blob son 72 bytes: un u64 big-endian con el instante Unix y la firma Ed25519 de 64.
 * Lo firmado NO es el cuerpo de la nota a secas, sino "cosignature/v1\ntime <unix>\n"
 * seguido del cuerpo: el testigo firma QUÉ vio y CUÁNDO, y las dos cosas van dentro del
 * mismo mensaje para que no se puedan separar.
 */
final class Cosignature
{
    public const SIZE = 72;

    public int $timestamp;
    public string $signature;

    private function __construct(int $timestamp, string $signature)
    {
        $this->timestamp = $timestamp;
        $this->signature = $signature;
    }

    /** parse devuelve null si el blob no es una cosignature v1. */
    public static function parse(string $blob): ?self
    {
        if (strlen($blob) !== self::SIZE) {
            return null;
        }
        $ts = Bytes::uint64BE($blob, 0);
        if ($ts === null) {
            return null; // un instante que no cabe en 63 bits no es una fecha
        }
        return new self($ts, substr($blob, 8));
    }

    /** message arma el mensaje que el testigo firmó. */
    public static function message(int $timestamp, string $noteText): string
    {
        return "cosignature/v1\ntime " . $timestamp . "\n" . $noteText;
    }
}
