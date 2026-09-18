<?php

declare(strict_types=1);

namespace Nucleo;

/**
 * Policy es la política de verificación como FORMATO DE CABLE (PROTOCOL.md §3.2,
 * ADR-018): todo lo que quien verifica trae de fuera del artefacto que verifica.
 *
 * Gemelo de internal/policy en Go y de policy.ts, con la misma gramática escrita a mano.
 * No se usa json_decode para leer el texto: cuando devuelve, un miembro duplicado ya se
 * ha perdido —se queda con el último, en silencio— y la tercera auditoría usó
 * exactamente eso: {"signerKey": A, "signerkey": B} daba una clave a la CLI y otra a la
 * página. Los tres lectores pasan por testdata/vectors/policy/ y por el diferencial.
 */
final class Policy
{
    /** MAX_BYTES es el tamaño máximo de un documento de política. */
    public const MAX_BYTES = 65536;

    private const MIEMBROS = ['origin', 'logKey', 'signerKey', 'witnesses', 'quorum'];
    private const HEX_CLAVE = '/\A[0-9a-f]{64}\z/';

    public string $origin;
    public string $logKey;
    public ?string $signerKey;
    /** @var array<int, array{name: string, key: string}> los testigos, en orden */
    public array $witnesses;
    public int $quorum;

    private function __construct(string $origin, string $logKey, ?string $signerKey, array $witnesses, int $quorum)
    {
        $this->origin = $origin;
        $this->logKey = $logKey;
        $this->signerKey = $signerKey;
        $this->witnesses = $witnesses;
        $this->quorum = $quorum;
    }

    /**
     * fromText lee y valida el TEXTO de una política. Lanza VerifyError con el motivo si
     * el documento no cumple §3.2.
     */
    public static function fromText(string $text): self
    {
        if (strlen($text) > self::MAX_BYTES) {
            throw new VerifyError(sprintf('la política mide más de %d bytes', self::MAX_BYTES));
        }
        if (str_starts_with($text, "\xEF\xBB\xBF")) {
            throw new VerifyError('la política empieza con BOM');
        }
        if (!Utf8::valid($text)) {
            // Un sustituto suelto no se puede escribir en UTF-8, así que aquí caen los
            // que TypeScript comprueba recorriendo unidades UTF-16.
            throw new VerifyError('la política no es Unicode válido');
        }
        $p = new PolicyReader($text);
        $p->spaces();
        if ($p->peek() !== '{') {
            throw new VerifyError('el documento tiene que ser un objeto JSON');
        }
        $obj = $p->object(1);
        $p->spaces();
        if (!$p->atEnd()) {
            throw new VerifyError(sprintf('hay contenido después del objeto (posición %d)', $p->pos()));
        }
        return self::build($obj);
    }

    /**
     * fromArray aplica las MISMAS reglas a una política que ya es un array —la que
     * construye un integrador en código—. No puede ver miembros duplicados, porque un
     * array de PHP no los tiene; todo lo demás, sí.
     *
     * Se reconstruye el texto y se pasa por el lector: una sola definición de las reglas.
     */
    public static function fromArray(array $p): self
    {
        $texto = json_encode($p, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        if ($texto === false) {
            throw new VerifyError('la política no se puede serializar: ' . json_last_error_msg());
        }
        return self::fromText($texto);
    }

    /** witnessKey devuelve la clave de un testigo por su nombre, o null. */
    public function witnessKey(string $name): ?string
    {
        foreach ($this->witnesses as $w) {
            if ($w['name'] === $name) {
                return $w['key'];
            }
        }
        return null;
    }

    private static function build(array $obj): self
    {
        $tiene = [];
        $origin = '';
        $logKey = '';
        $signerKey = null;
        // Los testigos van en una LISTA de pares, no en un array asociativo, y no es
        // estilo: las claves de array de PHP que parecen enteros se convierten en
        // enteros, así que un testigo llamado "123" dejaría de ser una cadena y su
        // nombre no volvería a salir igual. Es el mismo agujero que "__proto__" en
        // JavaScript (H5 de la cuarta auditoría), con otra forma.
        $witnesses = [];
        $quorum = '';
        foreach ($obj as $miembro) {
            $nombre = $miembro['nombre'];
            $valor = $miembro['valor'];
            if (!in_array($nombre, self::MIEMBROS, true)) {
                foreach (self::MIEMBROS as $k) {
                    if (strtolower($k) === self::asciiLower($nombre)) {
                        throw new VerifyError(sprintf(
                            'el miembro %s es una variante de mayúsculas de %s',
                            json_encode($nombre),
                            json_encode($k)
                        ));
                    }
                }
                throw new VerifyError(sprintf('miembro desconocido %s', json_encode($nombre)));
            }
            $tiene[$nombre] = true;
            switch ($nombre) {
                case 'origin':
                    if ($valor['tipo'] !== 's' || $valor['v'] === '') {
                        throw new VerifyError('origin tiene que ser una cadena no vacía');
                    }
                    $origin = $valor['v'];
                    break;
                case 'logKey':
                case 'signerKey':
                    if ($valor['tipo'] !== 's' || preg_match(self::HEX_CLAVE, $valor['v']) !== 1) {
                        throw new VerifyError(sprintf(
                            '%s tiene que ser una clave de 64 caracteres hexadecimales en minúsculas',
                            $nombre
                        ));
                    }
                    if ($nombre === 'logKey') {
                        $logKey = $valor['v'];
                    } else {
                        $signerKey = $valor['v'];
                    }
                    break;
                case 'witnesses':
                    if ($valor['tipo'] !== 'o') {
                        throw new VerifyError('witnesses tiene que ser un objeto');
                    }
                    if (count($valor['m']) === 0) {
                        throw new VerifyError('no trae ningún testigo; sin testigos no verifica nada');
                    }
                    $porClave = [];
                    foreach ($valor['m'] as $w) {
                        if ($w['nombre'] === '') {
                            throw new VerifyError('un testigo sin nombre');
                        }
                        if ($w['valor']['tipo'] !== 's' || preg_match(self::HEX_CLAVE, $w['valor']['v']) !== 1) {
                            throw new VerifyError(sprintf(
                                'la clave del testigo %s tiene que ser de 64 caracteres hexadecimales en minúsculas',
                                json_encode($w['nombre'])
                            ));
                        }
                        $clave = $w['valor']['v'];
                        if (isset($porClave[$clave])) {
                            throw new VerifyError(sprintf(
                                'la misma clave está bajo dos nombres (%s y %s)',
                                json_encode($porClave[$clave]),
                                json_encode($w['nombre'])
                            ));
                        }
                        $porClave[$clave] = $w['nombre'];
                        $witnesses[] = ['name' => $w['nombre'], 'key' => $clave];
                    }
                    break;
                case 'quorum':
                    if ($valor['tipo'] !== 'n') {
                        throw new VerifyError('quorum tiene que ser un número entero');
                    }
                    $quorum = $valor['v'];
                    break;
            }
        }
        foreach (['origin', 'logKey', 'witnesses', 'quorum'] as $req) {
            if (!isset($tiene[$req])) {
                throw new VerifyError(sprintf('falta el miembro %s', json_encode($req)));
            }
        }
        if (preg_match('/\A(0|[1-9][0-9]*)\z/', $quorum) !== 1) {
            throw new VerifyError(sprintf('quorum %s no es un entero sin fracción ni exponente', $quorum));
        }
        $q = Bytes::decimalCanonical($quorum);
        $n = count($witnesses);
        if ($q === null || $q < 1 || $q > $n) {
            throw new VerifyError(sprintf('quorum %s con %d testigos', $quorum, $n));
        }
        return new self($origin, $logKey, $signerKey, $witnesses, $q);
    }

    /** asciiLower pasa a minúsculas solo A-Z: solo decide el texto del error. */
    private static function asciiLower(string $s): string
    {
        $out = '';
        for ($i = 0; $i < strlen($s); $i++) {
            $c = $s[$i];
            $out .= ($c >= 'A' && $c <= 'Z') ? chr(ord($c) + 32) : $c;
        }
        return $out;
    }
}

/** PolicyReader es la gramática de §3.2, escrita a mano y sin tolerancias. */
final class PolicyReader
{
    private int $i = 0;

    public function __construct(private string $s)
    {
    }

    public function pos(): int
    {
        return $this->i;
    }

    public function atEnd(): bool
    {
        return $this->i >= strlen($this->s);
    }

    public function peek(): string
    {
        return $this->s[$this->i] ?? '';
    }

    private function err(string $msg): VerifyError
    {
        return new VerifyError(sprintf('%s (posición %d)', $msg, $this->i));
    }

    public function spaces(): void
    {
        while ($this->i < strlen($this->s)) {
            $c = $this->s[$this->i];
            if ($c === ' ' || $c === "\t" || $c === "\n" || $c === "\r") {
                $this->i++;
            } else {
                return;
            }
        }
    }

    /** @return array<int, array{nombre: string, valor: array}> */
    public function object(int $depth): array
    {
        if ($depth > 2) {
            throw $this->err('objeto anidado donde la política no admite ninguno');
        }
        $this->i++; // '{'
        $out = [];
        $vistos = [];
        $this->spaces();
        if ($this->peek() === '}') {
            $this->i++;
            return $out;
        }
        for (;;) {
            $this->spaces();
            if ($this->peek() !== '"') {
                throw $this->err('se esperaba el nombre de un miembro');
            }
            $nombre = $this->string();
            if (isset($vistos[$nombre])) {
                throw $this->err(sprintf('el miembro %s está repetido', json_encode($nombre)));
            }
            $vistos[$nombre] = true;
            $this->spaces();
            if ($this->peek() !== ':') {
                throw $this->err("se esperaba ':'");
            }
            $this->i++;
            $this->spaces();
            $out[] = ['nombre' => $nombre, 'valor' => $this->value($depth)];
            $this->spaces();
            $c = $this->peek();
            if ($c === ',') {
                $this->i++;
                continue;
            }
            if ($c === '}') {
                $this->i++;
                return $out;
            }
            if ($c === '') {
                throw $this->err('objeto sin cerrar');
            }
            throw $this->err("se esperaba ',' o '}'");
        }
    }

    public function value(int $depth): array
    {
        $c = $this->peek();
        if ($c === '') {
            throw $this->err('falta un valor');
        }
        if ($c === '"') {
            return ['tipo' => 's', 'v' => $this->string()];
        }
        if ($c === '{') {
            return ['tipo' => 'o', 'm' => $this->object($depth + 1)];
        }
        if ($c === '-' || ($c >= '0' && $c <= '9')) {
            return ['tipo' => 'n', 'v' => $this->number()];
        }
        throw $this->err('valor no admitido en una política (solo cadenas, números y el objeto de testigos)');
    }

    /** string lee una cadena JSON; rechaza sustitutos sueltos escritos con \u. */
    public function string(): string
    {
        $this->i++; // '"'
        $units = [];
        for (;;) {
            if ($this->i >= strlen($this->s)) {
                throw $this->err('cadena sin cerrar');
            }
            $c = $this->s[$this->i];
            if ($c === '"') {
                $this->i++;
                $out = Utf8::fromUnits($units);
                if ($out === null) {
                    throw $this->err('la cadena no es Unicode válido');
                }
                return $out;
            }
            if (ord($c) < 0x20) {
                throw $this->err('carácter de control sin escapar dentro de una cadena');
            }
            if ($c !== '\\') {
                $d = Utf8::decodeAt($this->s, $this->i);
                if ($d === null) {
                    throw $this->err('UTF-8 inválido dentro de una cadena');
                }
                foreach (Utf8::utf16Units([$d[0]]) as $u) {
                    $units[] = $u;
                }
                $this->i += $d[1];
                continue;
            }
            $this->i++;
            $e = $this->s[$this->i] ?? '';
            $this->i++;
            $simples = ['"' => 0x22, '\\' => 0x5C, '/' => 0x2F, 'b' => 0x08, 'f' => 0x0C, 'n' => 0x0A, 'r' => 0x0D, 't' => 0x09];
            if (isset($simples[$e])) {
                $units[] = $simples[$e];
                continue;
            }
            if ($e !== 'u') {
                throw $this->err(sprintf('escape desconocido \\%s', $e));
            }
            $u = $this->hex4();
            if ($u >= 0xD800 && $u <= 0xDBFF) {
                if (($this->s[$this->i] ?? '') !== '\\' || ($this->s[$this->i + 1] ?? '') !== 'u') {
                    throw $this->err('surrogate UTF-16 alto sin su pareja');
                }
                $this->i += 2;
                $bajo = $this->hex4();
                if ($bajo < 0xDC00 || $bajo > 0xDFFF) {
                    throw $this->err('surrogate UTF-16 alto sin su pareja');
                }
                $units[] = $u;
                $units[] = $bajo;
                continue;
            }
            if ($u >= 0xDC00 && $u <= 0xDFFF) {
                throw $this->err('surrogate UTF-16 bajo suelto');
            }
            $units[] = $u;
        }
    }

    private function hex4(): int
    {
        $h = substr($this->s, $this->i, 4);
        if (preg_match('/\A[0-9a-fA-F]{4}\z/', $h) !== 1) {
            throw $this->err('escape \\u con dígitos no hexadecimales');
        }
        $this->i += 4;
        return (int) hexdec($h);
    }

    /** number lee un número con la gramática de RFC 8259 y devuelve el literal. */
    public function number(): string
    {
        $ini = $this->i;
        $digitos = function (): int {
            $n = 0;
            while ($this->i < strlen($this->s) && $this->s[$this->i] >= '0' && $this->s[$this->i] <= '9') {
                $this->i++;
                $n++;
            }
            return $n;
        };
        if ($this->peek() === '-') {
            $this->i++;
        }
        if ($this->peek() === '0') {
            $this->i++;
        } elseif ($digitos() === 0) {
            throw $this->err('número mal formado');
        }
        if ($this->peek() === '.') {
            $this->i++;
            if ($digitos() === 0) {
                throw $this->err('número mal formado');
            }
        }
        if ($this->peek() === 'e' || $this->peek() === 'E') {
            $this->i++;
            if ($this->peek() === '+' || $this->peek() === '-') {
                $this->i++;
            }
            if ($digitos() === 0) {
                throw $this->err('número mal formado');
            }
        }
        return substr($this->s, $ini, $this->i - $ini);
    }
}
