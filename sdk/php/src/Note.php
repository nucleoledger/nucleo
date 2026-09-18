<?php

declare(strict_types=1);

namespace Nucleo;

/**
 * Note lee el bloque de firmas de una nota de c2sp.org/signed-note con las reglas de
 * PROTOCOL.md §3.3, que son NORMATIVAS y no las de ninguna biblioteca.
 *
 * Esa distinción es el hallazgo del Sprint 7e: `x/mod/sumdb/note` de Go descarta las
 * firmas repetidas de una clave conocida ANTES de verificarlas, y una implementación que
 * "deja pasar lo que no entiende" acepta notas que otra rechaza. Aquí cada línea tiene
 * que cumplir la forma o la nota entera es inválida.
 */
final class Note
{
    /** SIG_PREFIX abre cada línea de firma: em-dash U+2014 y un espacio. */
    public const SIG_PREFIX = "\u{2014} ";

    /** MAX_SIGS es el máximo de líneas de firma (regla 5). */
    public const MAX_SIGS = 100;

    /** ALG_ED25519 es el tipo de una firma Ed25519 de nota. */
    public const ALG_ED25519 = 0x01;

    /** ALG_COSIGNATURE_V1 es el de una tlog-cosignature@v1 con timestamp. */
    public const ALG_COSIGNATURE_V1 = 0x04;

    /**
     * ESPACIOS son los puntos de código con la propiedad Unicode White_Space, que es lo
     * que `unicode.IsSpace` de Go considera espacio (regla 3).
     *
     * Enumerados a mano y no con \s: la clase de PCRE con /u no coincide exactamente con
     * la de Go, y esa diferencia es justo el tipo de divergencia que el diferencial
     * existe para cazar.
     */
    private const ESPACIOS = [
        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x20, 0x85, 0xA0, 0x1680, 0x2000, 0x2001, 0x2002,
        0x2003, 0x2004, 0x2005, 0x2006, 0x2007, 0x2008, 0x2009, 0x200A, 0x2028, 0x2029,
        0x202F, 0x205F, 0x3000,
    ];

    /** @var string el cuerpo firmado, con su salto de línea final */
    public string $text;

    /** @var array<int, array{name: string, keyId: int, signature: string, line: string}> */
    public array $sigs;

    private function __construct(string $text, array $sigs)
    {
        $this->text = $text;
        $this->sigs = $sigs;
    }

    /**
     * parse separa una nota en cuerpo y firmas.
     *
     * Se corta por la ÚLTIMA línea en blanco y no por la primera: el cuerpo puede llevar
     * líneas vacías, y cortar por la primera partiría la nota en el sitio equivocado.
     */
    public static function parse(string $msg): self
    {
        $cps = Utf8::codepoints($msg);
        if ($cps === null) {
            throw new VerifyError('la nota no es UTF-8 válido');
        }
        foreach ($cps as $cp) {
            if ($cp < 0x20 && $cp !== 0x0A) {
                throw new VerifyError('la nota contiene caracteres de control');
            }
        }
        $at = strrpos($msg, "\n\n");
        if ($at === false) {
            throw new VerifyError('la nota no separa cuerpo y firmas');
        }
        $text = substr($msg, 0, $at + 1);
        $sigBlock = substr($msg, $at + 2);
        if ($sigBlock === '' || substr($sigBlock, -1) !== "\n") {
            throw new VerifyError('el bloque de firmas está vacío o no termina en salto de línea');
        }

        $sigs = [];
        foreach (explode("\n", substr($sigBlock, 0, -1)) as $line) {
            if (!str_starts_with($line, self::SIG_PREFIX)) {
                throw new VerifyError('línea de firma sin el prefijo de signed-note');
            }
            $rest = substr($line, strlen(self::SIG_PREFIX));
            $sp = strpos($rest, ' ');
            if ($sp === false) {
                throw new VerifyError('línea de firma sin nombre y firma');
            }
            $name = substr($rest, 0, $sp);
            if (!self::validName($name)) {
                throw new VerifyError(sprintf('nombre de firma inválido: %s', json_encode($name)));
            }
            $blob = Bytes::base64Canonical(substr($rest, $sp + 1));
            if ($blob === null) {
                throw new VerifyError(sprintf('firma de %s: base64 no canónico', $name));
            }
            if (strlen($blob) < 5) {
                throw new VerifyError(sprintf('firma de %s: menos de 5 bytes', $name));
            }
            if (count($sigs) === self::MAX_SIGS) {
                throw new VerifyError(sprintf('más de %d líneas de firma', self::MAX_SIGS));
            }
            $sigs[] = [
                'name' => $name,
                'keyId' => Bytes::uint32BE($blob, 0),
                'signature' => substr($blob, 4),
                'line' => $line,
            ];
        }
        return new self($text, $sigs);
    }

    /** validName es la regla 3 de PROTOCOL.md §3.3. */
    public static function validName(string $name): bool
    {
        if ($name === '' || str_contains($name, '+')) {
            return false;
        }
        $cps = Utf8::codepoints($name);
        if ($cps === null) {
            return false;
        }
        foreach ($cps as $cp) {
            if (in_array($cp, self::ESPACIOS, true)) {
                return false;
            }
        }
        return true;
    }

    /**
     * keyId calcula el identificador de clave de signed-note: los 4 primeros bytes, en
     * big-endian, de SHA-256(name ‖ "\n" ‖ alg ‖ pubkey).
     */
    public static function keyId(string $name, int $alg, string $publicKey): int
    {
        $h = hash('sha256', $name . "\n" . chr($alg) . $publicKey, true);
        return Bytes::uint32BE($h, 0);
    }
}
