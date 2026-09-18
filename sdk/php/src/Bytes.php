<?php

declare(strict_types=1);

namespace Nucleo;

/**
 * Bytes son las conversiones de codificación, todas ESTRICTAS.
 *
 * Estrictas no por gusto: un decodificador que tolera lo que su codificador no
 * reproduce crea dos textos para los mismos bytes, y un recibo con dos
 * representaciones no se puede archivar ni comparar. El diferencial Go↔TS encontró
 * justamente eso con un \r al final de una línea de firma.
 */
final class Bytes
{
    /** hexToBin acepta solo hexadecimal en MINÚSCULA, que es la forma canónica del proyecto. */
    public static function hexToBin(string $hex): ?string
    {
        if ($hex === '' || strlen($hex) % 2 !== 0) {
            return null;
        }
        if (preg_match('/\A[0-9a-f]*\z/', $hex) !== 1) {
            return null;
        }
        $raw = @hex2bin($hex);
        return $raw === false ? null : $raw;
    }

    public static function binToHex(string $raw): string
    {
        return bin2hex($raw);
    }

    /**
     * base64Canonical decodifica base64 estándar (RFC 4648 §4) y exige que el texto sea
     * EXACTAMENTE la codificación de lo que decodifica: relleno presente y bits de
     * relleno a cero.
     */
    public static function base64Canonical(string $s): ?string
    {
        if ($s === '' || strlen($s) % 4 !== 0) {
            return null;
        }
        if (preg_match('/\A[A-Za-z0-9+\/]+={0,2}\z/', $s) !== 1) {
            return null;
        }
        $raw = base64_decode($s, true);
        if ($raw === false || base64_encode($raw) !== $s) {
            return null;
        }
        return $raw;
    }

    /**
     * uint64BE lee un entero de 64 bits big-endian.
     *
     * Devuelve null si no cabe en un entero de PHP —64 bits CON signo—, en vez de
     * convertirlo a coma flotante y perder precisión en silencio (ADR-021 §E). El
     * límite real es 9,2·10^18 y decirlo es mejor que redondearlo.
     */
    public static function uint64BE(string $b, int $at): ?int
    {
        if (strlen($b) < $at + 8) {
            return null;
        }
        $n = 0;
        for ($i = 0; $i < 8; $i++) {
            $byte = ord($b[$at + $i]);
            if ($i === 0 && $byte >= 0x80) {
                return null; // el bit de signo: no cabe en un int de PHP
            }
            $n = $n * 256 + $byte;
        }
        return $n;
    }

    /** uint32BE lee un entero de 32 bits big-endian, que siempre cabe. */
    public static function uint32BE(string $b, int $at): int
    {
        return ord($b[$at]) * 16777216 + ord($b[$at + 1]) * 65536 + ord($b[$at + 2]) * 256 + ord($b[$at + 3]);
    }

    /**
     * decimalCanonical lee un entero decimal sin ceros a la izquierda y sin signo.
     * Devuelve null si no lo es o si no cabe en un entero de PHP.
     */
    public static function decimalCanonical(string $s): ?int
    {
        if (preg_match('/\A(0|[1-9][0-9]*)\z/', $s) !== 1) {
            return null;
        }
        // strlen antes de la conversión: 19 dígitos es el máximo seguro y a partir de
        // ahí se compara con la representación, que es lo único fiable.
        $n = (int) $s;
        return (string) $n === $s ? $n : null;
    }

    /** equal compara en tiempo constante, que aquí es gratis y nunca sobra. */
    public static function equal(string $a, string $b): bool
    {
        return hash_equals($a, $b);
    }
}
