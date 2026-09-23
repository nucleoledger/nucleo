<?php

declare(strict_types=1);

namespace Nucleo;

/**
 * SealResult es lo que devuelve un sellado, leído del `--json` de la CLI con el contrato
 * de ADR-025.
 *
 * Todos sus campos son obligatorios en la salida y ninguno tiene valor por omisión. Eso
 * es la corrección del hallazgo medio de la auditoría del 2026-09-19: aquí había casts
 * —`(int) ($j['index'] ?? -1)`— y un binario antiguo, truncado o sustituido producía un
 * SealResult con un índice -1 y un "no atestiguado" que nadie había afirmado. Un ERP que
 * guarda eso en su base de datos cree tener un registro sellado.
 */
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
    /** attestation es el estado de la atestación: none, unverified o verified (ADR-016). */
    public string $attestation;
    /** attested dice si la historia sobre la que se escribió tenía atestación verificada. */
    public bool $attested;
    /** stale dice si la última atestación pasa del umbral. Un cron debería mirarlo. */
    public bool $stale;
    /** signerVerified dice si la identidad del firmante se comprobó contra la política. */
    public bool $signerVerified;
    /** @var array el objeto --json completo, para lo que este SDK no modele todavía */
    public array $raw;

    /**
     * fromCliJson lee el stdout literal de la CLI. Es el camino que usa el Sealer, y el
     * que los vectores de testdata/vectors/cli-json/ recorren.
     */
    public static function fromCliJson(string $raw): self
    {
        return self::fromObject(Contract::decode($raw));
    }

    /**
     * fromObject aplica el contrato campo por campo. Lanza SealContractError ante un
     * campo obligatorio ausente o un tipo que no es el suyo; ignora los campos que no
     * conoce, porque un binario más nuevo puede añadirlos y este SDK tiene que seguir
     * andando.
     *
     * Toma un stdClass y no un array por lo que explica Contract::decode: con arrays
     * asociativos, `{"0": 0}` y `[0]` son indistinguibles y un objeto colado donde va
     * una lista pasaba la validación.
     */
    public static function fromObject(\stdClass $j): self
    {
        // `ok: false` no llega hasta aquí —el Sealer lo convierte en SealError con el
        // mensaje de la CLI— pero si llegara, un resultado de sellado no es eso.
        if (Contract::boolField($j, 'ok') !== true) {
            throw new SealContractError('la CLI contestó ok: false y eso no es un sellado');
        }
        $r = new self();
        $r->index = Contract::intField($j, 'index');
        $r->hash = Contract::hex64Field($j, 'hash');
        $r->payloadHash = Contract::hex64Field($j, 'payload_hash');
        $r->encrypted = Contract::boolField($j, 'encrypted');
        $r->idempotent = Contract::boolField($j, 'idempotent');
        $r->duplicateOf = Contract::intListField($j, 'duplicate_of');
        $r->attestation = Contract::enumField($j, 'attestation', ['none', 'unverified', 'verified']);
        $r->attested = Contract::boolField($j, 'attested');
        Contract::intField($j, 'attested_size');
        $r->signerVerified = Contract::boolField(Contract::signer($j), 'verified');
        $r->stale = Contract::boolField(Contract::freshness($j), 'stale');
        $r->raw = Contract::toArray($j);

        // Dos afirmaciones que la CLI no puede contradecir sin que algo esté muy mal, y
        // que aquí cuestan una comparación: `attested` es exactamente
        // `attestation == verified` (ADR-016), y un sellado idempotente nunca trae un
        // índice que no exista.
        if ($r->attested !== ($r->attestation === 'verified')) {
            throw new SealContractError(sprintf(
                'la salida se contradice: attested = %s con attestation = %s',
                var_export($r->attested, true),
                $r->attestation
            ));
        }
        return $r;
    }
}
