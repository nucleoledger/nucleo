<?php

declare(strict_types=1);

namespace Nucleo;

/**
 * Merkle verifica pruebas de inclusión de RFC 9162 §2.1.3.2.
 *
 * Los prefijos de dominio son los de RFC 6962: 0x00 para hojas y 0x01 para nodos
 * internos. Sin ellos, un atacante podría presentar el hash de un nodo interno como si
 * fuera una hoja.
 */
final class Merkle
{
    /** leafHash calcula MTH de una hoja: SHA-256(0x00 ‖ dato). */
    public static function leafHash(string $data): string
    {
        return hash('sha256', "\x00" . $data, true);
    }

    /** nodeHash combina dos hijos: SHA-256(0x01 ‖ izquierdo ‖ derecho). */
    public static function nodeHash(string $left, string $right): string
    {
        return hash('sha256', "\x01" . $left . $right, true);
    }

    /**
     * verifyInclusion comprueba que $leafData está en el índice $m de un árbol de tamaño
     * $n con la raíz dada.
     *
     * $leafData es el DATO de la hoja, no su hash: el prefijo 0x00 se aplica aquí dentro.
     * En Núcleo el dato de hoja es hash ‖ signature (leaf/v2, PROTOCOL.md §2.1), así que
     * la hoja acaba siendo SHA-256(0x00 ‖ SHA-256(JCS(header)) ‖ firma). El convenio es
     * el mismo que en Go y en TypeScript a propósito: dos implementaciones que difieran
     * en dónde se aplica el prefijo producen raíces distintas y el fallo aparece lejos de
     * su causa.
     */
    public static function verifyInclusion(string $leafData, int $m, int $n, array $proof, string $root): bool
    {
        if ($m < 0 || $n <= 0 || $m >= $n) {
            return false;
        }
        $fn = $m;
        $sn = $n - 1;
        $r = self::leafHash($leafData);

        foreach ($proof as $p) {
            // Sobrar nodos es tan inválido como faltar: una prueba con relleno
            // permitiría fabricar variantes de una prueba legítima.
            if ($sn === 0) {
                return false;
            }
            if ($fn % 2 === 1 || $fn === $sn) {
                $r = self::nodeHash($p, $r);
                while ($fn % 2 === 0 && $fn !== 0) {
                    $fn = intdiv($fn, 2);
                    $sn = intdiv($sn, 2);
                }
            } else {
                $r = self::nodeHash($r, $p);
            }
            $fn = intdiv($fn, 2);
            $sn = intdiv($sn, 2);
        }
        if ($sn !== 0) {
            return false;
        }
        return Bytes::equal($r, $root);
    }
}
