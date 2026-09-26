<?php

declare(strict_types=1);

namespace Nucleo;

/**
 * Contract lee la salida `--json` de la CLI como lo que es: un FORMATO DE CABLE
 * (ADR-025), con la misma desconfianza con la que Policy lee una política.
 *
 * Antes esto eran casts: `(int) ($j['index'] ?? -1)`, `(bool) ($j['attested'] ?? false)`.
 * La auditoría del 2026-09-19 lo señaló: un binario antiguo, truncado, equivocado o
 * sustituido producía un objeto PHP aparentemente utilizable, con un índice -1 que se
 * podía confundir con un índice y un "no atestiguado" que nadie había afirmado. En un
 * producto de integridad, el envoltorio tiene que fallar CERRADO ante un contrato
 * inesperado.
 *
 * Las dos mitades de la regla de compatibilidad de CLI-JSON.md se aplican aquí:
 * lo obligatorio que falta es un error, y lo DESCONOCIDO se ignora —un binario más nuevo
 * puede añadir campos y este SDK tiene que seguir funcionando—.
 */
final class Contract
{
    /** maxError es cuánto se enseña de una salida que no es JSON. */
    private const MAX_ERROR = 200;

    /**
     * decode convierte el stdout de la CLI en un objeto, o lanza.
     *
     * A stdClass y NO a array asociativo, y esto lo encontró un vector inválido de este
     * mismo ADR: con `json_decode($raw, true)`, el objeto `{"0": 0}` y la lista `[0]` dan
     * el MISMO array de PHP, así que `array_is_list()` no puede distinguirlos y un objeto
     * colado donde va una lista pasaba la validación. Decodificando a objetos, un objeto
     * JSON es stdClass y una lista JSON es array: la diferencia se mantiene y se puede
     * exigir.
     *
     * JSON_THROW_ON_ERROR y no `json_decode() === null`: el segundo confunde el JSON
     * `null` —válido— con un error de sintaxis.
     */
    public static function decode(string $raw): \stdClass
    {
        try {
            $v = json_decode($raw, false, 32, JSON_THROW_ON_ERROR);
        } catch (\JsonException $e) {
            throw new SealContractError(sprintf(
                'la CLI no devolvió JSON (%s). Primeros bytes: %s',
                $e->getMessage(),
                json_encode(substr($raw, 0, self::MAX_ERROR))
            ));
        }
        if (!$v instanceof \stdClass) {
            throw new SealContractError(sprintf(
                'la CLI devolvió JSON que no es un objeto, sino %s',
                get_debug_type($v)
            ));
        }
        return $v;
    }

    /**
     * toArray devuelve el objeto como array asociativo, para CONSUMIRLO.
     *
     * Validar se hace sobre el stdClass —ver decode()—; leer es más cómodo con arrays, y
     * es lo que un integrador espera de `->raw` y de `status()`. La conversión va aquí,
     * en un solo sitio y después de haber comprobado el contrato.
     */
    public static function toArray(\stdClass $o): array
    {
        $a = json_decode(json_encode($o), true, 32, JSON_THROW_ON_ERROR);
        return is_array($a) ? $a : [];
    }

    /** intField exige un entero DE VERDAD: ni "0", ni 0.5, ni true. */
    public static function intField(\stdClass $o, string $k, int $min = 0): int
    {
        $v = self::present($o, $k);
        if (!is_int($v)) {
            throw self::wrong($k, 'un entero', $v);
        }
        if ($v < $min) {
            throw new SealContractError(sprintf('%s = %d, y el mínimo es %d', $k, $v, $min));
        }
        return $v;
    }

    /** boolField exige un booleano DE VERDAD: ni "true", ni 1. */
    public static function boolField(\stdClass $o, string $k): bool
    {
        $v = self::present($o, $k);
        if (!is_bool($v)) {
            throw self::wrong($k, 'un booleano', $v);
        }
        return $v;
    }

    /** strField exige una cadena; $vacia dice si se admite vacía. */
    public static function strField(\stdClass $o, string $k, bool $vacia = true): string
    {
        $v = self::present($o, $k);
        if (!is_string($v)) {
            throw self::wrong($k, 'una cadena', $v);
        }
        if (!$vacia && $v === '') {
            throw new SealContractError(sprintf('%s está vacío', $k));
        }
        return $v;
    }

    /**
     * hex64Field exige 64 caracteres [0-9a-f]: es lo que CLI-JSON.md fija para hashes y
     * claves. Las mayúsculas se rechazan aunque denoten el mismo valor, porque la forma
     * canónica del proyecto es la minúscula y dos grafías del mismo hash son una de más.
     */
    public static function hex64Field(\stdClass $o, string $k): string
    {
        $v = self::strField($o, $k);
        if (preg_match('/\A[0-9a-f]{64}\z/', $v) !== 1) {
            throw new SealContractError(sprintf(
                '%s no es un hash o clave en hex minúsculo de 64 caracteres: %s',
                $k,
                json_encode(substr($v, 0, 80))
            ));
        }
        return $v;
    }

    /** objField exige un objeto JSON (no una lista). */
    public static function objField(\stdClass $o, string $k): \stdClass
    {
        $v = self::present($o, $k);
        if (!$v instanceof \stdClass) {
            throw self::wrong($k, 'un objeto', $v);
        }
        return $v;
    }

    /** enumField exige una de las cadenas permitidas y ninguna más. */
    public static function enumField(\stdClass $o, string $k, array $permitidas): string
    {
        $v = self::strField($o, $k);
        if (!in_array($v, $permitidas, true)) {
            throw new SealContractError(sprintf(
                '%s = %s, y el contrato solo admite %s',
                $k,
                json_encode($v),
                implode(', ', $permitidas)
            ));
        }
        return $v;
    }

    /**
     * intListField exige una lista de enteros, o devuelve [] si el campo no está.
     *
     * Opcional a propósito: `duplicate_of` solo aparece cuando hay duplicados
     * (CLI-JSON.md). Lo que no se admite es que aparezca con cualquier cosa dentro.
     *
     * @return int[]
     */
    public static function intListField(\stdClass $o, string $k, int $min = 0): array
    {
        if (!property_exists($o, $k)) {
            return [];
        }
        $v = $o->$k;
        if (!is_array($v) || !array_is_list($v)) {
            throw self::wrong($k, 'una lista', $v);
        }
        $out = [];
        foreach ($v as $i => $x) {
            if (!is_int($x) || $x < $min) {
                throw new SealContractError(sprintf(
                    '%s[%d] no es un entero >= %d: %s',
                    $k,
                    $i,
                    $min,
                    json_encode($x)
                ));
            }
            $out[] = $x;
        }
        return $out;
    }

    /**
     * status comprueba los campos que docs/CLI-JSON.md fija para `status` y devuelve el
     * objeto entero.
     *
     * Devuelve el array completo y no un objeto de valor porque `status` es lo que un
     * cron mira, y lo que un cron mira cambia con lo que a cada integrador le importe.
     * Lo que este método garantiza es que lo obligatorio está y es del tipo que dice
     * ser; lo que haya de más, sigue ahí.
     */
    public static function status(\stdClass $j): array
    {
        self::boolField($j, 'ok');
        self::strField($j, 'dir', false);
        self::strField($j, 'origin', false);
        self::strField($j, 'leaf_rule', false);
        self::hex64Field($j, 'log_pubkey');
        self::intField($j, 'tree_size');
        self::hex64Field($j, 'root');
        self::enumField($j, 'attestation', ['none', 'unverified', 'verified']);
        self::boolField($j, 'attested');
        self::intField($j, 'attested_size');
        self::signer($j);
        self::freshness($j);
        return self::toArray($j);
    }

    /**
     * error comprueba el objeto de error de la CLI, que también es contrato
     * (CLI-JSON.md §Convenciones):
     * {"ok": false, "error": "...", "exit_code": N, "error_class": "..."}.
     */
    public static function error(\stdClass $j): array
    {
        if (self::boolField($j, 'ok') !== false) {
            throw new SealContractError('el objeto de error tiene que llevar ok: false');
        }
        self::strField($j, 'error', false);
        $code = self::intField($j, 'exit_code', 1);
        if (!in_array($code, [1, 2, 3], true)) {
            throw new SealContractError(sprintf('exit_code = %d, y los códigos son 1, 2 y 3', $code));
        }
        // Valida error_class si viene, y de paso deja la clase deducida al alcance de
        // quien llame: es el mismo cálculo y hacerlo dos veces invita a que divergan.
        $a = self::toArray($j);
        $a['error_class'] = self::errorClass($j, $code);
        return $a;
    }

    /**
     * errorClass devuelve la clase del error (ADR-027), validada.
     *
     * Se lee como OPCIONAL a propósito: un binario anterior a septiembre de 2026 no la
     * trae, y exigirla rompería contra un despliegue sin actualizar —la regla de
     * compatibilidad dice que los campos se pueden añadir, no que aparezcan hacia atrás—.
     * Cuando falta, se deduce del código de salida, que es el comportamiento de siempre.
     *
     * Lo que NO se tolera es un valor desconocido: un `retryable` que este SDK no conoce
     * no se puede interpretar a la baja sin inventar. Misma regla que `attestation`.
     */
    public static function errorClass(\stdClass $j, int $code): string
    {
        if (property_exists($j, 'error_class')) {
            return self::enumField($j, 'error_class', ['usage', 'transient', 'environment', 'integrity']);
        }
        return match ($code) {
            2 => 'integrity',
            3 => 'transient',
            default => 'usage',
        };
    }

    /**
     * alert lee el objeto `alert` de la alarma de frescura (ADR-028), o null si la
     * salida no lo trae.
     *
     * Opcional por lo mismo que error_class: un binario anterior a septiembre de 2026 no
     * lo manda, y exigirlo rompería contra un despliegue sin actualizar. Lo que no se
     * tolera es un objeto que no cumple: un estado desconocido no se interpreta a la
     * baja, porque "no sé si hay alarma" no puede acabar en "no hay alarma".
     *
     * @return array<string, mixed>|null
     */
    public static function alert(\stdClass $j): ?array
    {
        if (!property_exists($j, 'alert')) {
            return null;
        }
        $a = self::objField($j, 'alert');
        $estado = self::enumField($a, 'state', ['none', 'open', 'acked']);
        self::boolField($a, 'new');
        self::boolField($a, 'persisted');
        if ($estado !== 'none') {
            self::strField($a, 'stale_since', false);
            self::strField($a, 'alert_emitted_at', false);
            self::enumField($a, 'reason', ['age', 'never_attested', 'no_attestation_under_policy']);
            if (!is_int($a->threshold_hours ?? null) && !is_float($a->threshold_hours ?? null)) {
                throw self::wrong('alert.threshold_hours', 'un número', $a->threshold_hours ?? null);
            }
        }
        if ($estado === 'acked') {
            self::strField($a, 'alert_acked_at', false);
        }
        return self::toArray($a);
    }

    /** signer comprueba el objeto compartido `signer`. */
    public static function signer(\stdClass $j): \stdClass
    {
        $s = self::objField($j, 'signer');
        $estado = self::enumField($s, 'state', ['none', 'unverified', 'verified']);
        $verificado = self::boolField($s, 'verified');
        // verified == (state == verified), y lo dice CLI-JSON.md. Que la salida se
        // contradiga a sí misma no es algo que este SDK deba interpretar.
        if ($verificado !== ($estado === 'verified')) {
            throw new SealContractError(sprintf(
                'signer se contradice: state = %s con verified = %s',
                $estado,
                var_export($verificado, true)
            ));
        }
        // pubkey puede venir vacía —un ledger sin bloques y sin vault_meta— pero si trae
        // algo, tiene que ser una clave.
        $pub = self::strField($s, 'pubkey');
        if ($pub !== '') {
            self::hex64Field($s, 'pubkey');
        }
        return $s;
    }

    /** freshness comprueba el objeto compartido `freshness`. */
    public static function freshness(\stdClass $j): \stdClass
    {
        $f = self::objField($j, 'freshness');
        self::boolField($f, 'stale');
        self::boolField($f, 'verified');
        self::boolField($f, 'policy');
        self::enumField($f, 'source', ['attestation', 'local_record', 'none']);
        return $f;
    }

    /** present devuelve el valor o lanza si el campo no está. */
    private static function present(\stdClass $o, string $k)
    {
        if (!property_exists($o, $k)) {
            throw new SealContractError(sprintf(
                'falta el campo obligatorio %s en la salida de la CLI. Un binario más antiguo ' .
                'que este SDK, o una salida truncada, se ve exactamente así (ADR-025).',
                json_encode($k)
            ));
        }
        return $o->$k;
    }

    /** wrong compone el error de tipo, con lo que llegó. */
    private static function wrong(string $k, string $esperado, $v): SealContractError
    {
        return new SealContractError(sprintf(
            '%s tiene que ser %s y llegó %s: %s',
            $k,
            $esperado,
            get_debug_type($v),
            json_encode($v)
        ));
    }
}
