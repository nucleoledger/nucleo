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

    /** MAX_CUTOFF es el mayor corte de una clave retirada: 2^53 − 1 (PROTOCOL §1). */
    public const MAX_CUTOFF = 9007199254740991;

    private const MIEMBROS = ['origin', 'logKey', 'signerKey', 'erasureKey', 'retiredErasureKeys', 'logMLDSAKey', 'witnesses', 'quorum'];
    private const HEX_CLAVE = '/\A[0-9a-f]{64}\z/';
    /** LARGO_MLDSA es la longitud en hexadecimal de una clave pública ML-DSA-44: 1312 bytes. */
    private const LARGO_MLDSA = 2624;

    public string $origin;
    public string $logKey;
    public ?string $signerKey;
    /**
     * erasureKey es la pública que autoriza las supresiones (ADR-032), o null. Este
     * verificador la lee y no la usa: un recibo no depende de ella.
     */
    public ?string $erasureKey;
    /**
     * retiredErasureKeys son las claves de supresión retiradas con su corte (ADR-033,
     * PROTOCOL 0.8-draft §3.2), como lista de pares en el orden del documento, o null si
     * no viene. Este verificador las lee con la gramática de Go y no las usa: no
     * implementa supresión, y un recibo no depende de ellas.
     *
     * @var array<int, array{key: string, cutoff: int}>|null
     */
    public ?array $retiredErasureKeys;
    /**
     * logMLDSAKey es la clave pública ML-DSA-44 del log en hexadecimal (ADR-034), o null.
     * Con ella, todo recibo tiene que traer al menos una línea de esa clave y todas tienen
     * que medir 2420 bytes; este verificador NO verifica la firma y lo dice.
     */
    public ?string $logMLDSAKey;
    /** @var array<int, array{name: string, key: string}> los testigos, en orden */
    public array $witnesses;
    public int $quorum;

    private function __construct(string $origin, string $logKey, ?string $signerKey, ?string $erasureKey, ?array $retiredErasureKeys, ?string $logMLDSAKey, array $witnesses, int $quorum)
    {
        $this->origin = $origin;
        $this->logKey = $logKey;
        $this->signerKey = $signerKey;
        $this->erasureKey = $erasureKey;
        $this->retiredErasureKeys = $retiredErasureKeys;
        $this->logMLDSAKey = $logMLDSAKey;
        $this->witnesses = $witnesses;
        $this->quorum = $quorum;
    }

    /**
     * fromText lee y valida el TEXTO de una política. Lanza VerifyError con el motivo si
     * el documento no cumple §3.2.
     */
    public static function fromText(string $text): self
    {
        // El orden de las tres primeras comprobaciones es el de internal/estricto: tamaño,
        // codificación, BOM. Decide el motivo de un documento que falla dos a la vez.
        if (strlen($text) > self::MAX_BYTES) {
            throw new VerifyError(sprintf('la política mide más de %d bytes', self::MAX_BYTES), 'size');
        }
        if (!Utf8::valid($text)) {
            // Un sustituto suelto no se puede escribir en UTF-8, así que aquí caen los
            // que TypeScript comprueba recorriendo unidades UTF-16.
            throw new VerifyError('la política no es Unicode válido', 'syntax');
        }
        if (str_starts_with($text, "\xEF\xBB\xBF")) {
            throw new VerifyError('la política empieza con BOM', 'bom');
        }
        $p = new PolicyReader($text);
        $p->spaces();
        if ($p->peek() !== '{') {
            // Otro valor JSON en vez del objeto es un tipo equivocado; lo que no empieza
            // como ningún valor —vacío, un comentario— no es JSON.
            $c = $p->peek();
            $motivo = ($c !== '' && str_contains('["-0123456789tfn', $c)) ? 'type' : 'syntax';
            throw new VerifyError('el documento tiene que ser un objeto JSON', $motivo);
        }
        $obj = $p->object(1);
        $p->spaces();
        if (!$p->atEnd()) {
            throw new VerifyError(sprintf('hay contenido después del objeto (posición %d)', $p->pos()), 'trailing');
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
        $erasureKey = null;
        $logMLDSAKey = null;
        $retiradas = null;
        // Los testigos van en una LISTA de pares, no en un array asociativo, y no es
        // estilo: las claves de array de PHP que parecen enteros se convierten en
        // enteros, así que un testigo llamado "123" dejaría de ser una cadena y su
        // nombre no volvería a salir igual. Es el mismo agujero que "__proto__" en
        // JavaScript (H5 de la cuarta auditoría), con otra forma. Las claves retiradas,
        // por lo mismo, también van en una lista.
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
                        ), 'case_variant');
                    }
                }
                throw new VerifyError(sprintf('miembro desconocido %s', json_encode($nombre)), 'unknown_member');
            }
            $tiene[$nombre] = true;
            switch ($nombre) {
                case 'origin':
                    if ($valor['tipo'] !== 's' || $valor['v'] === '') {
                        throw new VerifyError('origin tiene que ser una cadena no vacía', 'origin');
                    }
                    $origin = $valor['v'];
                    break;
                case 'logKey':
                case 'signerKey':
                case 'erasureKey':
                    if ($valor['tipo'] !== 's' || preg_match(self::HEX_CLAVE, $valor['v']) !== 1) {
                        throw new VerifyError(sprintf(
                            '%s tiene que ser una clave de 64 caracteres hexadecimales en minúsculas',
                            $nombre
                        ), self::motivoDeClave($valor));
                    }
                    if ($nombre === 'logKey') {
                        $logKey = $valor['v'];
                    } elseif ($nombre === 'signerKey') {
                        $signerKey = $valor['v'];
                    } else {
                        $erasureKey = $valor['v'];
                    }
                    break;
                case 'retiredErasureKeys':
                    $retiradas = self::clavesRetiradas($valor);
                    break;
                case 'logMLDSAKey':
                    if ($valor['tipo'] !== 's' || strlen($valor['v']) !== self::LARGO_MLDSA
                        || preg_match('/\A[0-9a-f]*\z/', $valor['v']) !== 1) {
                        throw new VerifyError(sprintf(
                            'logMLDSAKey tiene que ser la clave pública ML-DSA-44 del log: %d caracteres hexadecimales en minúsculas',
                            self::LARGO_MLDSA
                        ), self::motivoDeClave($valor));
                    }
                    $logMLDSAKey = $valor['v'];
                    break;
                case 'witnesses':
                    if ($valor['tipo'] !== 'o') {
                        throw new VerifyError('witnesses tiene que ser un objeto', 'type');
                    }
                    if (count($valor['m']) === 0) {
                        throw new VerifyError('no trae ningún testigo; sin testigos no verifica nada', 'no_witnesses');
                    }
                    $porClave = [];
                    foreach ($valor['m'] as $w) {
                        if ($w['nombre'] === '') {
                            throw new VerifyError('un testigo sin nombre', 'witness_name');
                        }
                        if ($w['valor']['tipo'] !== 's' || preg_match(self::HEX_CLAVE, $w['valor']['v']) !== 1) {
                            throw new VerifyError(sprintf(
                                'la clave del testigo %s tiene que ser de 64 caracteres hexadecimales en minúsculas',
                                json_encode($w['nombre'])
                            ), self::motivoDeClave($w['valor']));
                        }
                        $clave = $w['valor']['v'];
                        if (isset($porClave[$clave])) {
                            throw new VerifyError(sprintf(
                                'la misma clave está bajo dos nombres (%s y %s)',
                                json_encode($porClave[$clave]),
                                json_encode($w['nombre'])
                            ), 'duplicate_key');
                        }
                        $porClave[$clave] = $w['nombre'];
                        $witnesses[] = ['name' => $w['nombre'], 'key' => $clave];
                    }
                    break;
                case 'quorum':
                    if ($valor['tipo'] !== 'n') {
                        throw new VerifyError('quorum tiene que ser un número entero', 'quorum');
                    }
                    $quorum = $valor['v'];
                    break;
            }
        }
        foreach (['origin', 'logKey', 'witnesses', 'quorum'] as $req) {
            if (!isset($tiene[$req])) {
                throw new VerifyError(sprintf('falta el miembro %s', json_encode($req)), 'missing');
            }
        }
        if (preg_match('/\A(0|[1-9][0-9]*)\z/', $quorum) !== 1) {
            throw new VerifyError(sprintf('quorum %s no es un entero sin fracción ni exponente', $quorum), 'quorum');
        }
        $q = Bytes::decimalCanonical($quorum);
        $n = count($witnesses);
        if ($q === null || $q < 1 || $q > $n) {
            throw new VerifyError(sprintf('quorum %s con %d testigos', $quorum, $n), 'quorum');
        }
        // Los testigos ordenados por nombre, como los recorre Go: solo decide el texto del
        // error, no el motivo.
        $porNombre = $witnesses;
        usort($porNombre, static fn(array $a, array $b): int => strcmp($a['name'], $b['name']));
        if ($erasureKey !== null) {
            // La clave de supresión no puede ser ninguna de las otras (ADR-032 §B): la del
            // log y la del firmante están en el servidor, y una de testigo ya tiene su papel.
            if ($erasureKey === $logKey) {
                throw new VerifyError('erasureKey es la clave del log; la clave de supresión no puede estar en el servidor', 'erasure_key_reused');
            }
            if ($erasureKey === $signerKey) {
                throw new VerifyError('erasureKey es la clave del firmante; la clave de supresión no puede estar en el servidor', 'erasure_key_reused');
            }
            foreach ($porNombre as $w) {
                if ($w['key'] === $erasureKey) {
                    throw new VerifyError(sprintf('erasureKey es la clave del testigo %s', json_encode($w['name'])), 'erasure_key_reused');
                }
            }
        }
        if ($retiradas !== null) {
            // La regla de separación de las claves retiradas (ADR-033 §A): ninguna puede
            // ser la erasureKey, la del log, la del firmante ni la de un testigo. Vale
            // también sin erasureKey. En el orden de Go: las claves ordenadas, y para cada
            // una, esas cuatro.
            $ordenadas = array_column($retiradas, 'key');
            sort($ordenadas, SORT_STRING);
            foreach ($ordenadas as $k) {
                $ini = substr($k, 0, 16);
                if ($k === $erasureKey) {
                    throw new VerifyError(sprintf('la clave retirada %s… es la erasureKey: una clave no puede estar retirada y ser la actual', $ini), 'erasure_key_reused');
                }
                if ($k === $logKey) {
                    throw new VerifyError(sprintf('la clave retirada %s… es la clave del log; una clave de supresión no puede estar en el servidor', $ini), 'erasure_key_reused');
                }
                if ($k === $signerKey) {
                    throw new VerifyError(sprintf('la clave retirada %s… es la clave del firmante; una clave de supresión no puede estar en el servidor', $ini), 'erasure_key_reused');
                }
                foreach ($porNombre as $w) {
                    if ($w['key'] === $k) {
                        throw new VerifyError(sprintf('la clave retirada %s… es la clave del testigo %s', $ini, json_encode($w['name'])), 'erasure_key_reused');
                    }
                }
            }
        }
        return new self($origin, $logKey, $signerKey, $erasureKey, $retiradas, $logMLDSAKey, $witnesses, $q);
    }

    /**
     * motivoDeClave es el motivo de un valor que tenía que ser una clave en hexadecimal:
     * un objeto es otro tipo; un número o una cadena que no es la clave, una clave mal
     * escrita. (El null, el booleano y el array los rechaza antes el lector.)
     */
    private static function motivoDeClave(array $v): string
    {
        return $v['tipo'] === 'o' ? 'type' : 'hex';
    }

    /**
     * clavesRetiradas lee retiredErasureKeys (ADR-033 §A): un objeto con al menos un
     * miembro; cada nombre, una clave Ed25519 en hexadecimal en minúsculas; cada valor, su
     * corte. Una clave repetida ya la rechazó el lector: es un nombre repetido.
     *
     * @return array<int, array{key: string, cutoff: int}>
     */
    private static function clavesRetiradas(array $v): array
    {
        if ($v['tipo'] !== 'o') {
            throw new VerifyError('retiredErasureKeys tiene que ser un objeto {clave: corte}', 'type');
        }
        if (count($v['m']) === 0) {
            throw new VerifyError('retiredErasureKeys vacío: significaría lo mismo que no ponerlo; quítalo', 'no_retired_keys');
        }
        $out = [];
        foreach ($v['m'] as $m) {
            if (preg_match(self::HEX_CLAVE, $m['nombre']) !== 1) {
                throw new VerifyError(sprintf(
                    'la clave retirada %s tiene que ser de 64 caracteres hexadecimales en minúsculas',
                    json_encode(self::recorta($m['nombre']), JSON_UNESCAPED_UNICODE)
                ), 'hex');
            }
            if ($m['valor']['tipo'] !== 'n') {
                throw new VerifyError(sprintf('el corte de la clave retirada %s… tiene que ser un número entero', substr($m['nombre'], 0, 16)), 'cutoff');
            }
            $c = self::corte($m['valor']['v']);
            if ($c === null) {
                throw new VerifyError(sprintf(
                    'el corte %s de la clave retirada %s… no es un entero sin signo, sin fracción ni exponente, de como mucho 2^53 − 1',
                    self::recorta($m['valor']['v']),
                    substr($m['nombre'], 0, 16)
                ), 'cutoff');
            }
            $out[] = ['key' => $m['nombre'], 'cutoff' => $c];
        }
        return $out;
    }

    /**
     * corte lee el corte de una clave retirada: el literal 0|[1-9][0-9]*, sin signo, sin
     * fracción, sin exponente, como mucho 2^53 − 1. null si no lo es.
     */
    private static function corte(string $s): ?int
    {
        if (preg_match('/\A(0|[1-9][0-9]*)\z/', $s) !== 1 || strlen($s) > 16) {
            return null;
        }
        $c = (int) $s;
        return $c <= self::MAX_CUTOFF ? $c : null;
    }

    /** recorta acorta un valor del documento para un mensaje. */
    private static function recorta(string $s): string
    {
        return strlen($s) <= 24 ? $s : substr($s, 0, 24) . '…';
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
    /** @var string[] los nombres de los miembros que se están leyendo, desde el documento */
    private array $ruta = [];

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

    /**
     * err es un error del lector con su motivo. La clase es la de internal/estricto en Go
     * y el motivo sale de ella y de la ruta, con la regla de internal/policy.Motivo: lo
     * que está mal en origin, en quorum o en un corte es de ese miembro, sea del tipo que
     * sea; en lo demás, un null es un null y el resto es un tipo equivocado.
     */
    private function err(string $msg, string $clase = 'sintaxis'): VerifyError
    {
        return new VerifyError(sprintf('%s (posición %d)', $msg, $this->i), $this->motivo($clase));
    }

    private function motivo(string $clase): string
    {
        $primero = $this->ruta[0] ?? '';
        $deCorte = count($this->ruta) === 2 && $primero === 'retiredErasureKeys';
        switch ($clase) {
            case 'repetido':
                return 'duplicate_member';
            case 'surrogate':
                return 'surrogate';
            case 'número':
                if ($primero === 'quorum') {
                    return 'quorum';
                }
                return $deCorte ? 'cutoff' : 'syntax';
            case 'null':
            case 'booleano':
            case 'array':
            case 'anidado':
                if ($primero === 'origin') {
                    return 'origin';
                }
                if ($primero === 'quorum') {
                    return 'quorum';
                }
                if ($deCorte) {
                    return 'cutoff';
                }
                return $clase === 'null' ? 'null' : 'type';
        }
        return 'syntax';
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
            throw $this->err('objeto anidado donde la política no admite ninguno', 'anidado');
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
                throw $this->err(sprintf('el miembro %s está repetido', json_encode($nombre)), 'repetido');
            }
            $vistos[$nombre] = true;
            $this->spaces();
            if ($this->peek() !== ':') {
                throw $this->err("se esperaba ':'");
            }
            $this->i++;
            $this->spaces();
            $this->ruta[] = $nombre;
            $out[] = ['nombre' => $nombre, 'valor' => $this->value($depth)];
            array_pop($this->ruta);
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
        $resto = substr($this->s, $this->i, 5);
        $clase = 'sintaxis';
        if (str_starts_with($resto, 'null')) {
            $clase = 'null';
        } elseif (str_starts_with($resto, 'true') || str_starts_with($resto, 'false')) {
            $clase = 'booleano';
        } elseif ($c === '[') {
            $clase = 'array';
        }
        throw $this->err('valor no admitido en una política (solo cadenas, números y los objetos de testigos y de claves retiradas)', $clase);
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
                    throw $this->err('surrogate UTF-16 alto sin su pareja', 'surrogate');
                }
                $this->i += 2;
                $bajo = $this->hex4();
                if ($bajo < 0xDC00 || $bajo > 0xDFFF) {
                    throw $this->err('surrogate UTF-16 alto sin su pareja', 'surrogate');
                }
                $units[] = $u;
                $units[] = $bajo;
                continue;
            }
            if ($u >= 0xDC00 && $u <= 0xDFFF) {
                throw $this->err('surrogate UTF-16 bajo suelto', 'surrogate');
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
            // RFC 8259 no admite ceros a la izquierda; como en Go, el error es del número
            // —y del miembro que lo lleva—, no un separador que falta después.
            $d = $this->peek();
            if ($d !== '' && $d >= '0' && $d <= '9') {
                throw $this->err('número con un cero a la izquierda', 'número');
            }
        } elseif ($digitos() === 0) {
            throw $this->err('número mal formado', 'número');
        }
        if ($this->peek() === '.') {
            $this->i++;
            if ($digitos() === 0) {
                throw $this->err('número mal formado', 'número');
            }
        }
        if ($this->peek() === 'e' || $this->peek() === 'E') {
            $this->i++;
            if ($this->peek() === '+' || $this->peek() === '-') {
                $this->i++;
            }
            if ($digitos() === 0) {
                throw $this->err('número mal formado', 'número');
            }
        }
        return substr($this->s, $ini, $this->i - $ini);
    }
}
