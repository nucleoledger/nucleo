<?php

declare(strict_types=1);

namespace Nucleo;

/**
 * Jcs comprueba canonicidad JCS (RFC 8785). No canonicaliza nada.
 *
 * La decisión es la misma que en Go y en TypeScript: los bytes exactos del header son lo
 * que se firmó, así que la pregunta no es "¿qué representa este texto?" sino "¿es este
 * texto la forma canónica de lo que representa?". Se lee con un lector estricto y se
 * vuelve a serializar para comparar con lo que llegó.
 *
 * Por qué el lector propio y no json_decode: json_decode se queda con el ÚLTIMO de dos
 * miembros repetidos —y la pregunta se pierde—, acepta espacio en blanco entre tokens y
 * no distingue un escape alternativo de su carácter. Tres formas de escribir el mismo
 * objeto que Go rechazaría por no ser byte a byte la canónica.
 */
final class Jcs
{
    /** profundidadMaxima acota la anidación, que es lo que acota la recursión. */
    private const MAX_DEPTH = 32;

    /**
     * isCanonical dice si $raw es EXACTAMENTE la serialización JCS de lo que representa:
     * sin espacio en blanco, claves ordenadas por unidades UTF-16, sin miembros
     * repetidos, escapes mínimos y enteros sin ceros ni exponente.
     *
     * Nunca lanza: el header de un recibo es entrada de fuera, y quien verifica no puede
     * tener que envolver esto en un try.
     */
    public static function isCanonical(string $raw): bool
    {
        try {
            $l = new JcsReader($raw);
            $v = $l->value(0, self::MAX_DEPTH);
            $l->endOfText();
            // El header es un OBJETO (PROTOCOL.md §1): un array o un escalar canónicos
            // no son un header canónico.
            if ($v['t'] !== 'o') {
                return false;
            }
            return self::serialize($v) === $raw;
        } catch (\Throwable $e) {
            return false;
        }
    }

    /** serialize devuelve la forma canónica JCS del valor leído. */
    public static function serialize(array $v): string
    {
        switch ($v['t']) {
            case 's':
                return self::escape($v['u']);
            case 'n':
                // Solo enteros seguros: es lo que el header usa (index). Canonicalizar
                // un número con fracción o exponente exige el algoritmo de números de
                // RFC 8785, que es la parte difícil y la que más se equivoca; se rechaza
                // en vez de adivinarse.
                if (preg_match('/\A-?(0|[1-9][0-9]*)\z/', $v['v']) !== 1) {
                    throw new \RuntimeException('número no canonicalizable aquí');
                }
                if (Bytes::decimalCanonical(ltrim($v['v'], '-')) === null) {
                    throw new \RuntimeException('número fuera del rango de enteros');
                }
                return $v['v'];
            case 'lit':
                return $v['v'];
            case 'a':
                return '[' . implode(',', array_map([self::class, 'serialize'], $v['v'])) . ']';
            case 'o':
                $m = $v['m'];
                usort($m, static fn(array $x, array $y): int => Utf8::compareUtf16($x['k'], $y['k']));
                $partes = [];
                foreach ($m as $miembro) {
                    $partes[] = self::escape($miembro['k']) . ':' . self::serialize($miembro['v']);
                }
                return '{' . implode(',', $partes) . '}';
        }
        throw new \RuntimeException('valor desconocido');
    }

    /** escape aplica los escapes mínimos de RFC 8785 §3.2.2.2. */
    public static function escape(array $units): string
    {
        $out = '"';
        $n = count($units);
        for ($i = 0; $i < $n; $i++) {
            $u = $units[$i];
            switch ($u) {
                case 0x22:
                    $out .= '\\"';
                    continue 2;
                case 0x5C:
                    $out .= '\\\\';
                    continue 2;
                case 0x08:
                    $out .= '\\b';
                    continue 2;
                case 0x0C:
                    $out .= '\\f';
                    continue 2;
                case 0x0A:
                    $out .= '\\n';
                    continue 2;
                case 0x0D:
                    $out .= '\\r';
                    continue 2;
                case 0x09:
                    $out .= '\\t';
                    continue 2;
            }
            if ($u < 0x20) {
                $out .= sprintf('\\u%04x', $u);
                continue;
            }
            if ($u >= 0xD800 && $u <= 0xDBFF && $i + 1 < $n && $units[$i + 1] >= 0xDC00 && $units[$i + 1] <= 0xDFFF) {
                $s = Utf8::fromUnits([$u, $units[$i + 1]]);
                if ($s === null) {
                    throw new \RuntimeException('par sustituto inválido');
                }
                $out .= $s;
                $i++;
                continue;
            }
            $s = Utf8::fromUnits([$u]);
            if ($s === null) {
                // Un sustituto suelto no tiene forma en UTF-8, así que el texto que lo
                // contenga no puede ser la forma canónica de nada.
                throw new \RuntimeException('sustituto suelto');
            }
            $out .= $s;
        }
        return $out . '"';
    }
}

/**
 * JcsReader es el lector estricto. Vive aquí, junto a Jcs, porque no tiene otro uso:
 * Policy tiene el suyo con las reglas de PROTOCOL §3.2.
 */
final class JcsReader
{
    private int $i = 0;

    public function __construct(private string $s)
    {
    }

    public function endOfText(): void
    {
        if ($this->i !== strlen($this->s)) {
            throw new \RuntimeException('sobra texto');
        }
    }

    public function value(int $depth, int $max): array
    {
        if ($depth > $max) {
            throw new \RuntimeException('demasiada anidación');
        }
        $c = $this->s[$this->i] ?? '';
        if ($c === '"') {
            return ['t' => 's', 'u' => $this->stringUnits()];
        }
        if ($c === '{') {
            return $this->object($depth, $max);
        }
        if ($c === '[') {
            return $this->array($depth, $max);
        }
        if ($c === '-' || ($c >= '0' && $c <= '9')) {
            return ['t' => 'n', 'v' => $this->number()];
        }
        foreach (['true', 'false', 'null'] as $lit) {
            if (substr($this->s, $this->i, strlen($lit)) === $lit) {
                $this->i += strlen($lit);
                return ['t' => 'lit', 'v' => $lit];
            }
        }
        throw new \RuntimeException('valor no reconocido');
    }

    private function object(int $depth, int $max): array
    {
        $this->i++;
        $m = [];
        $vistas = [];
        if (($this->s[$this->i] ?? '') === '}') {
            $this->i++;
            return ['t' => 'o', 'm' => $m];
        }
        for (;;) {
            if (($this->s[$this->i] ?? '') !== '"') {
                throw new \RuntimeException('nombre de miembro');
            }
            $k = $this->stringUnits();
            $huella = implode(',', $k);
            // Un miembro repetido no tiene forma canónica: json_decode se quedaría con
            // el último y perdería la pregunta.
            if (isset($vistas[$huella])) {
                throw new \RuntimeException('miembro repetido');
            }
            $vistas[$huella] = true;
            if (($this->s[$this->i] ?? '') !== ':') {
                throw new \RuntimeException("falta ':'");
            }
            $this->i++;
            $m[] = ['k' => $k, 'v' => $this->value($depth + 1, $max)];
            $c = $this->s[$this->i] ?? '';
            if ($c === ',') {
                $this->i++;
                continue;
            }
            if ($c === '}') {
                $this->i++;
                return ['t' => 'o', 'm' => $m];
            }
            throw new \RuntimeException("falta ',' o '}'");
        }
    }

    private function array(int $depth, int $max): array
    {
        $this->i++;
        $out = [];
        if (($this->s[$this->i] ?? '') === ']') {
            $this->i++;
            return ['t' => 'a', 'v' => $out];
        }
        for (;;) {
            $out[] = $this->value($depth + 1, $max);
            $c = $this->s[$this->i] ?? '';
            if ($c === ',') {
                $this->i++;
                continue;
            }
            if ($c === ']') {
                $this->i++;
                return ['t' => 'a', 'v' => $out];
            }
            throw new \RuntimeException("falta ',' o ']'");
        }
    }

    /** stringUnits lee una cadena JSON y devuelve sus unidades UTF-16. */
    private function stringUnits(): array
    {
        $this->i++;
        $out = [];
        for (;;) {
            if ($this->i >= strlen($this->s)) {
                throw new \RuntimeException('cadena sin cerrar');
            }
            $c = $this->s[$this->i];
            if ($c === '"') {
                $this->i++;
                return $out;
            }
            if (ord($c) < 0x20) {
                throw new \RuntimeException('control sin escapar');
            }
            if ($c !== '\\') {
                $d = Utf8::decodeAt($this->s, $this->i);
                if ($d === null) {
                    throw new \RuntimeException('UTF-8 inválido');
                }
                foreach (Utf8::utf16Units([$d[0]]) as $u) {
                    $out[] = $u;
                }
                $this->i += $d[1];
                continue;
            }
            $this->i++;
            $e = $this->s[$this->i] ?? '';
            $this->i++;
            $simples = ['"' => 0x22, '\\' => 0x5C, '/' => 0x2F, 'b' => 0x08, 'f' => 0x0C, 'n' => 0x0A, 'r' => 0x0D, 't' => 0x09];
            if (isset($simples[$e])) {
                $out[] = $simples[$e];
                continue;
            }
            if ($e !== 'u') {
                throw new \RuntimeException('escape desconocido');
            }
            $h = substr($this->s, $this->i, 4);
            if (preg_match('/\A[0-9a-fA-F]{4}\z/', $h) !== 1) {
                throw new \RuntimeException('escape \\u inválido');
            }
            $this->i += 4;
            $out[] = (int) hexdec($h);
        }
    }

    private function number(): string
    {
        $ini = $this->i;
        if (($this->s[$this->i] ?? '') === '-') {
            $this->i++;
        }
        while ($this->i < strlen($this->s) && $this->s[$this->i] >= '0' && $this->s[$this->i] <= '9') {
            $this->i++;
        }
        if ($this->i === $ini) {
            throw new \RuntimeException('número vacío');
        }
        // La fracción y el exponente se consumen para leer el texto entero; la
        // serialización los rechaza después.
        if (($this->s[$this->i] ?? '') === '.') {
            $this->i++;
            while ($this->i < strlen($this->s) && $this->s[$this->i] >= '0' && $this->s[$this->i] <= '9') {
                $this->i++;
            }
        }
        if (($this->s[$this->i] ?? '') === 'e' || ($this->s[$this->i] ?? '') === 'E') {
            $this->i++;
            if (($this->s[$this->i] ?? '') === '+' || ($this->s[$this->i] ?? '') === '-') {
                $this->i++;
            }
            while ($this->i < strlen($this->s) && $this->s[$this->i] >= '0' && $this->s[$this->i] <= '9') {
                $this->i++;
            }
        }
        return substr($this->s, $ini, $this->i - $ini);
    }
}
