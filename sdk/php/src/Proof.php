<?php

declare(strict_types=1);

namespace Nucleo;

/** Proof es la parte verificable del recibo: c2sp.org/tlog-proof@v1. */
final class Proof
{
    public const MAGIC = 'c2sp.org/tlog-proof@v1';

    public int $index;
    /** @var string[] nodos de 32 bytes, de la hoja a la raíz */
    public array $inclusionProof;
    public string $checkpointNote;

    private function __construct(int $index, array $inclusionProof, string $note)
    {
        $this->index = $index;
        $this->inclusionProof = $inclusionProof;
        $this->checkpointNote = $note;
    }

    public static function parse(string $data): self
    {
        $lines = explode("\n", $data);
        if (($lines[0] ?? '') !== self::MAGIC) {
            throw new VerifyError(sprintf('se esperaba %s en la primera línea', self::MAGIC));
        }
        $index = Bytes::decimalCanonical($lines[1] ?? '');
        if ($index === null) {
            throw new VerifyError(sprintf('índice no canónico o fuera de rango: %s', json_encode($lines[1] ?? null)));
        }

        $nodes = [];
        $i = 2;
        for (; $i < count($lines); $i++) {
            if ($lines[$i] === '') {
                break;
            }
            $node = Bytes::base64Canonical($lines[$i]);
            if ($node === null) {
                throw new VerifyError(sprintf('nodo de la prueba en base64 no canónico: %s', json_encode($lines[$i])));
            }
            if (strlen($node) !== 32) {
                throw new VerifyError(sprintf('nodo de %d bytes, se esperaban 32', strlen($node)));
            }
            $nodes[] = $node;
        }
        if ($i >= count($lines)) {
            throw new VerifyError('falta la línea vacía antes del checkpoint');
        }
        $note = implode("\n", array_slice($lines, $i + 1));
        if ($note === '') {
            throw new VerifyError('falta la nota del checkpoint');
        }
        return new self($index, $nodes, $note);
    }
}
