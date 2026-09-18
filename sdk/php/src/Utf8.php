<?php

declare(strict_types=1);

namespace Nucleo;

/**
 * Utf8 decodifica y valida UTF-8 a mano.
 *
 * A mano y no con mbstring o iconv porque ninguna de las dos está garantizada en un
 * hosting compartido, y ADR-021 §D fija las extensiones en sodium y json. Lo que hace
 * falta es poco: recorrer puntos de código y pasar a unidades UTF-16, que es el dominio
 * en el que RFC 8785 ordena las claves.
 */
final class Utf8
{
    /**
     * codepoints devuelve los puntos de código, o null si la cadena no es UTF-8 válido.
     *
     * Rechaza lo de siempre y por lo de siempre: secuencias sobrelargas (dos formas de
     * escribir el mismo carácter), sustitutos codificados en UTF-8 (CESU-8) y valores
     * por encima de U+10FFFF. Cada una de esas tolerancias es una segunda
     * representación de los mismos datos.
     */
    public static function codepoints(string $s): ?array
    {
        $out = [];
        $n = strlen($s);
        for ($i = 0; $i < $n;) {
            $c = ord($s[$i]);
            if ($c < 0x80) {
                $out[] = $c;
                $i++;
                continue;
            }
            if ($c >= 0xC2 && $c <= 0xDF) {
                $len = 2;
                $cp = $c & 0x1F;
            } elseif ($c >= 0xE0 && $c <= 0xEF) {
                $len = 3;
                $cp = $c & 0x0F;
            } elseif ($c >= 0xF0 && $c <= 0xF4) {
                $len = 4;
                $cp = $c & 0x07;
            } else {
                return null; // continuación suelta, 0xC0/0xC1 sobrelargos, 0xF5+
            }
            if ($i + $len > $n) {
                return null;
            }
            for ($k = 1; $k < $len; $k++) {
                $cc = ord($s[$i + $k]);
                if ($cc < 0x80 || $cc > 0xBF) {
                    return null;
                }
                $cp = ($cp << 6) | ($cc & 0x3F);
            }
            if ($len === 3 && $cp < 0x800) {
                return null;
            }
            if ($len === 4 && $cp < 0x10000) {
                return null;
            }
            if ($cp > 0x10FFFF || ($cp >= 0xD800 && $cp <= 0xDFFF)) {
                return null;
            }
            $out[] = $cp;
            $i += $len;
        }
        return $out;
    }

    /**
     * decodeAt decodifica el punto de código que empieza en $i y devuelve [cp, bytes],
     * o null si no hay ninguno válido ahí. Es codepoints() para un solo carácter, y
     * existe para poder leer una cadena JSON byte a byte sin trocearla antes.
     */
    public static function decodeAt(string $s, int $i): ?array
    {
        $trozo = substr($s, $i, 4);
        for ($len = 1; $len <= strlen($trozo); $len++) {
            $cps = self::codepoints(substr($trozo, 0, $len));
            if ($cps !== null && count($cps) === 1) {
                return [$cps[0], $len];
            }
        }
        return null;
    }

    /** valid dice si la cadena es UTF-8 válido. */
    public static function valid(string $s): bool
    {
        return self::codepoints($s) !== null;
    }

    /**
     * utf16Units convierte puntos de código en unidades de código UTF-16, con pares
     * sustitutos para los de encima de U+FFFF.
     *
     * Es el dominio de comparación de RFC 8785 §3.2.3: las claves de un objeto se
     * ordenan por sus unidades UTF-16, no por sus puntos de código. La diferencia
     * aparece con un carácter suplementario frente a uno en U+E000–U+FFFF.
     */
    public static function utf16Units(array $codepoints): array
    {
        $out = [];
        foreach ($codepoints as $cp) {
            if ($cp <= 0xFFFF) {
                $out[] = $cp;
                continue;
            }
            $v = $cp - 0x10000;
            $out[] = 0xD800 + (($v >> 10) & 0x3FF);
            $out[] = 0xDC00 + ($v & 0x3FF);
        }
        return $out;
    }

    /**
     * fromUnits recompone UTF-8 desde unidades UTF-16. Devuelve null ante un sustituto
     * suelto: no representa ningún carácter y no tiene forma en UTF-8.
     */
    public static function fromUnits(array $units): ?string
    {
        $out = '';
        $n = count($units);
        for ($i = 0; $i < $n; $i++) {
            $u = $units[$i];
            if ($u >= 0xD800 && $u <= 0xDBFF) {
                if ($i + 1 >= $n || $units[$i + 1] < 0xDC00 || $units[$i + 1] > 0xDFFF) {
                    return null;
                }
                $cp = 0x10000 + (($u - 0xD800) << 10) + ($units[$i + 1] - 0xDC00);
                $i++;
            } elseif ($u >= 0xDC00 && $u <= 0xDFFF) {
                return null;
            } else {
                $cp = $u;
            }
            $out .= self::encode($cp);
        }
        return $out;
    }

    /** encode escribe un punto de código en UTF-8. */
    public static function encode(int $cp): string
    {
        if ($cp < 0x80) {
            return chr($cp);
        }
        if ($cp < 0x800) {
            return chr(0xC0 | ($cp >> 6)) . chr(0x80 | ($cp & 0x3F));
        }
        if ($cp < 0x10000) {
            return chr(0xE0 | ($cp >> 12)) . chr(0x80 | (($cp >> 6) & 0x3F)) . chr(0x80 | ($cp & 0x3F));
        }
        return chr(0xF0 | ($cp >> 18)) . chr(0x80 | (($cp >> 12) & 0x3F))
            . chr(0x80 | (($cp >> 6) & 0x3F)) . chr(0x80 | ($cp & 0x3F));
    }

    /**
     * compareUtf16 ordena dos cadenas por unidades UTF-16, como manda RFC 8785.
     *
     * Las cadenas llegan como arrays de unidades: quien llama ya las tiene decodificadas
     * y volver a decodificarlas aquí sería una segunda oportunidad de divergir.
     */
    public static function compareUtf16(array $a, array $b): int
    {
        $n = min(count($a), count($b));
        for ($i = 0; $i < $n; $i++) {
            if ($a[$i] !== $b[$i]) {
                return $a[$i] < $b[$i] ? -1 : 1;
            }
        }
        return count($a) <=> count($b);
    }
}
