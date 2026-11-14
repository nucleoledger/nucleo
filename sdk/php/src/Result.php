<?php

declare(strict_types=1);

namespace Nucleo;

/**
 * Result es lo que el verificador puede AFIRMAR sobre un recibo.
 *
 * Los nombres son los del SDK de TypeScript porque es el mismo dictamen: lo que el
 * diferencial compara entre las tres implementaciones son estos campos, no un booleano
 * (Sprint 7f, F.7). Dos verificadores que aceptan el mismo recibo y dan distinto tiempo
 * demostrable son dos verificadores distintos.
 */
final class Result
{
    /** valid solo es true si nada falló. */
    public bool $valid = false;
    /** declaredTime lo puso el emisor. NO prueba nada. */
    public ?string $declaredTime = null;
    /** provableTime es el menor timestamp de las cosignatures aceptadas. */
    public ?string $provableTime = null;
    /** blockIndex es la posición del registro en el log. */
    public ?int $blockIndex = null;
    /** recipient es a quién iba dirigido. */
    public ?string $recipient = null;
    /** @var string[] cosigners son los testigos cuya cosignature verificó */
    public array $cosigners = [];
    /** @var string[] ignoredSignatures son las firmas de claves desconocidas */
    public array $ignoredSignatures = [];
    /** signerPubKey es la clave que el header declara como firmante, en hexadecimal. */
    public ?string $signerPubKey = null;
    /**
     * logAdditionalSignatures cuenta las firmas ADICIONALES del propio log: líneas con
     * el nombre del origin que miden lo que mide una ML-DSA-44 (ADR-007). No se
     * verifican —no hay ML-DSA en PHP— y no afectan al veredicto, pero no son "claves
     * que no conoces".
     */
    public int $logAdditionalSignatures = 0;
    /**
     * logMLDSA dice qué se sabe de la firma ML-DSA-44 del log (ADR-034 §D), solo si el
     * recibo vale (null si no): "present-unverified" —con logMLDSAKey en la política, hay
     * al menos una línea de esa clave y todas miden 2420 bytes; sin ella, hay una línea a
     * nombre del log con la forma de una ML-DSA-44; en los dos casos SIN verificarla— o
     * "absent". Nunca "verified": no hay ML-DSA en PHP. Para verificarla, `nucleo
     * verify-receipt`.
     */
    public ?string $logMLDSA = null;
    /** logMLDSANote es el motivo de "present-unverified", para enseñarlo con el estado. */
    public ?string $logMLDSANote = null;
    /** @var string[] reasons explica, en español, por qué falla */
    public array $reasons = [];
    /** @var array{origin: string, size: string, rootHash: string}|null */
    public ?array $checkpoint = null;
    /** blockSignatureVerified dice si la firma del bloque verifica con signer_pubkey. */
    public ?bool $blockSignatureVerified = null;
    /** receiptSignatureVerified dice si la firma del emisor sobre el recibo verifica. */
    public ?bool $receiptSignatureVerified = null;

    /** toArray es la forma que consume el diferencial. */
    public function toArray(): array
    {
        return [
            'valid' => $this->valid,
            'declared_time' => $this->declaredTime ?? '',
            'provable_time' => $this->provableTime ?? '',
            'block_index' => $this->blockIndex === null ? '' : (string) $this->blockIndex,
            'recipient' => $this->recipient ?? '',
            'signer_pubkey' => $this->signerPubKey ?? '',
            'cosigners' => $this->cosigners,
            'ignored' => $this->ignoredSignatures,
            'checkpoint' => $this->checkpoint === null
                ? ''
                : $this->checkpoint['origin'] . '/' . $this->checkpoint['size'] . '/' . $this->checkpoint['rootHash'],
            'reasons' => $this->reasons,
            'log_mldsa' => $this->logMLDSA ?? '',
        ];
    }
}
