<?php

declare(strict_types=1);

namespace Nucleo;

/** SealResult es lo que devuelve un sellado, ya leído del --json de la CLI. */
final class SealResult
{
    public int $index;
    public string $hash;
    public string $payloadHash;
    public bool $encrypted;
    /** idempotent es true si NO se escribió nada porque la clave ya estaba (ADR-020). */
    public bool $idempotent;
    /** @var int[] duplicateOf son los bloques que ya sellaban este contenido */
    public array $duplicateOf;
    /** attested dice si la historia sobre la que se escribió tenía atestación verificada. */
    public bool $attested;
    /** stale dice si la última atestación pasa del umbral. Un cron debería mirarlo. */
    public bool $stale;
    /** @var array el objeto --json completo, para lo que este SDK no modele todavía */
    public array $raw;

    public static function fromJSON(array $j): self
    {
        $r = new self();
        $r->index = (int) ($j['index'] ?? -1);
        $r->hash = (string) ($j['hash'] ?? '');
        $r->payloadHash = (string) ($j['payload_hash'] ?? '');
        $r->encrypted = (bool) ($j['encrypted'] ?? false);
        $r->idempotent = (bool) ($j['idempotent'] ?? false);
        $r->duplicateOf = array_map('intval', $j['duplicate_of'] ?? []);
        $r->attested = (bool) ($j['attested'] ?? false);
        $r->stale = (bool) ($j['freshness']['stale'] ?? false);
        $r->raw = $j;
        return $r;
    }
}
