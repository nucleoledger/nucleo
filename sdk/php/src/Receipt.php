<?php

declare(strict_types=1);

namespace Nucleo;

/**
 * Receipt es el recibo de Núcleo: una prueba de c2sp.org/tlog-proof envuelta en un
 * encabezado legible.
 *
 * La regla que hace fiable ese encabezado es que el texto se DERIVA de la prueba, y
 * verificar consiste, entre otras cosas, en volver a derivarlo y comprobar que coincide
 * byte a byte. Un recibo con prueba impecable y texto retocado —otra fecha, otro emisor,
 * otro importe— se rechaza.
 *
 * Esta es la TERCERA implementación (Go, TypeScript, PHP) y está escrita desde
 * PROTOCOL.md §3.1 (ADR-021 §B). La plantilla del texto legible no está en el protocolo
 * —solo en el código de las otras dos—, así que sale de los vectores compartidos, que es
 * la fuente que tendría un tercero.
 */
final class Receipt
{
    /** MAGIC fija a la vez el formato y la REGLA DE HOJA (PROTOCOL.md §3.1). */
    public const MAGIC = 'nucleo.org/receipt@v2';

    /** MAGIC_V1 es el magic histórico, para reconocerlo y dar un error que lo explique. */
    public const MAGIC_V1 = 'nucleo.org/receipt@v1';

    public const SEPARATOR = '--- prueba verificable ---';
    public const NO_PROVABLE_TIME = 'SIN TIEMPO DEMOSTRABLE';
    public const RECIPIENT_NOTE = '  (firmado por el emisor)';
    public const RECEIPT_SIG_PREFIX = "\u{2014} ";
    public const BLOCK_SIG_SIZE = 64;

    /** MLDSA44_SIGNATURE_SIZE es lo que mide una firma ML-DSA-44 (FIPS 204). */
    public const MLDSA44_SIGNATURE_SIZE = 2420;

    /**
     * LEGAL_NOTICE es la advertencia legal que viaja DENTRO del texto legible.
     *
     * Byte a byte la misma que en Go y en TypeScript: renderHeader la vuelve a componer
     * para compararla con lo que llegó, así que un recibo al que le hayan quitado la
     * advertencia —o le hayan cambiado una palabra— no verifica. Una advertencia que se
     * puede borrar con un editor de texto no protege a nadie; esta no.
     */
    public const LEGAL_NOTICE = [
        'ADVERTENCIA LEGAL',
        'Este recibo es evidencia técnica de integridad y tiempo. No constituye por sí',
        'mismo un acto público, una certificación notarial ni un pronunciamiento de',
        'autoridad. Su valor probatorio lo determina un perito o un juez.',
    ];

    public string $recipient;
    public string $headerJSON;
    public array $header;
    public int $headerIndex;
    public string $blockSig;
    public ?string $receiptSig;
    /** signedBytes es el recibo SIN su línea de firma: lo que el emisor firmó. */
    public string $signedBytes;
    public Proof $proof;
    public Note $note;
    public Checkpoint $checkpoint;
    public string $text;

    private function __construct()
    {
    }

    /** parse separa el recibo en sus partes. Lanza VerifyError con el motivo. */
    public static function parse(string $receipt): self
    {
        $r = new self();
        $at = strpos($receipt, self::SEPARATOR . "\n");
        if ($at === false) {
            throw new VerifyError(sprintf('falta el separador %s', json_encode(self::SEPARATOR)));
        }
        $r->text = substr($receipt, 0, $at);
        $machine = substr($receipt, $at + strlen(self::SEPARATOR) + 1);

        if (str_starts_with($r->text, self::MAGIC_V1 . "\n")) {
            // Se reconoce el recibo viejo para poder decir QUÉ pasa. Sin esto el error
            // hablaría de una firma que falta, y quien lo leyera buscaría el problema
            // donde no está.
            throw new VerifyError(sprintf(
                'este recibo es %s, con la regla de hoja leaf/v1; este verificador implementa %s (leaf/v2). Ver PROTOCOL.md §2.1 y ADR-014',
                self::MAGIC_V1,
                self::MAGIC
            ));
        }
        if (!str_starts_with($r->text, self::MAGIC . "\n")) {
            throw new VerifyError(sprintf('se esperaba %s en la primera línea', self::MAGIC));
        }

        // Se quita la etiqueta para devolver el nombre limpio. Si no viniera, el nombre
        // queda tal cual, renderHeader la volverá a añadir y la comparación del texto
        // rechaza el recibo: un recibo que enseña el nombre sin decir qué es no pasa.
        $dest = self::field($r->text, 'destinatario      : ');
        if (str_ends_with($dest, self::RECIPIENT_NOTE)) {
            $dest = substr($dest, 0, -strlen(self::RECIPIENT_NOTE));
        }
        $r->recipient = $dest;

        $nl = strpos($machine, "\n");
        if ($nl === false) {
            throw new VerifyError('falta el header canónico');
        }
        $r->headerJSON = substr($machine, 0, $nl);
        $header = json_decode($r->headerJSON, true);
        if (!is_array($header)) {
            throw new VerifyError('el header del bloque no es un objeto JSON');
        }
        $r->header = $header;
        $r->headerIndex = self::headerIndexOf($r->headerJSON);

        // Tras el header, la firma del bloque en base64 (PROTOCOL.md §3.1). Va aquí y no
        // al final porque la cola del recibo es la nota del checkpoint: cualquier línea
        // pegada después acabaría dentro de la nota, leída como una línea de firma más.
        $rest = substr($machine, $nl + 1);
        $nl2 = strpos($rest, "\n");
        if ($nl2 === false) {
            throw new VerifyError('falta la firma del bloque');
        }
        $blockSigLine = substr($rest, 0, $nl2);
        $blockSig = Bytes::base64Canonical($blockSigLine);
        if ($blockSig === null) {
            throw new VerifyError('la firma del bloque no está en base64 canónico');
        }
        if (strlen($blockSig) !== self::BLOCK_SIG_SIZE) {
            throw new VerifyError(sprintf(
                'la firma del bloque mide %d bytes y una Ed25519 mide %d',
                strlen($blockSig),
                self::BLOCK_SIG_SIZE
            ));
        }
        $r->blockSig = $blockSig;

        // Y tras ella, la firma del emisor sobre el recibo entero (ADR-015). El formato
        // la exige; se lee como opcional para poder decir "no lleva firma del emisor" en
        // vez de que el parser de la prueba se queje de un magic que no entiende.
        $afterSig = substr($rest, $nl2 + 1);
        $r->receiptSig = null;
        $r->signedBytes = $receipt;
        if (str_starts_with($afterSig, self::RECEIPT_SIG_PREFIX)) {
            $nl3 = strpos($afterSig, "\n");
            if ($nl3 === false) {
                throw new VerifyError('la línea de la firma del emisor no termina');
            }
            $line = substr($afterSig, 0, $nl3);
            $sp = strrpos($line, ' ');
            if ($sp === false) {
                throw new VerifyError('la línea de la firma del emisor no trae nombre y firma');
            }
            $name = substr($line, strlen(self::RECEIPT_SIG_PREFIX), $sp - strlen(self::RECEIPT_SIG_PREFIX));
            $tenant = is_string($r->header['tenant'] ?? null) ? $r->header['tenant'] : '';
            if ($name !== $tenant) {
                throw new VerifyError(sprintf(
                    'la firma del emisor dice ser de %s y el header declara %s',
                    json_encode($name),
                    json_encode($tenant)
                ));
            }
            $b64 = substr($line, $sp + 1);
            $sig = Bytes::base64Canonical($b64);
            if ($sig === null) {
                throw new VerifyError('la firma del emisor no está en base64 canónico');
            }
            if (strlen($sig) !== self::BLOCK_SIG_SIZE) {
                throw new VerifyError(sprintf(
                    'la firma del emisor mide %d bytes y una Ed25519 mide %d',
                    strlen($sig),
                    self::BLOCK_SIG_SIZE
                ));
            }
            $r->receiptSig = $sig;
            // Lo firmado es el recibo SIN esta línea. Se quita de la cadena en vez de
            // volver a renderizar el documento: son los mismos bytes y no hay dos
            // caminos que puedan divergir.
            $entera = $line . "\n";
            $pos = strrpos($receipt, $entera);
            if ($pos === false) {
                throw new VerifyError('no se pudo aislar la línea de la firma del emisor');
            }
            $r->signedBytes = substr($receipt, 0, $pos) . substr($receipt, $pos + strlen($entera));
            $afterSig = substr($afterSig, $nl3 + 1);
        }

        $r->proof = Proof::parse($afterSig);
        $r->note = Note::parse($r->proof->checkpointNote);
        $r->checkpoint = Checkpoint::parse($r->note->text);
        return $r;
    }

    /**
     * headerIndexOf lee el índice del header canónico DEL TEXTO.
     *
     * No se usa el valor de json_decode porque un entero por encima de PHP_INT_MAX se
     * convierte en float y la comparación con el índice de la prueba compararía dos
     * valores ya redondeados —que además coincidirían, dando por bueno un recibo que no
     * lo es—. Aquí se rechaza (ADR-021 §E).
     */
    private static function headerIndexOf(string $headerJSON): int
    {
        if (preg_match('/"index"\s*:\s*(\d+)/', $headerJSON, $m) !== 1) {
            throw new VerifyError('el header no lleva un índice entero');
        }
        $n = Bytes::decimalCanonical($m[1]);
        if ($n === null) {
            throw new VerifyError(sprintf('índice del header no canónico o fuera del rango de enteros: %s', $m[1]));
        }
        return $n;
    }

    /** field extrae el valor de una línea del encabezado. */
    private static function field(string $text, string $prefix): string
    {
        foreach (explode("\n", $text) as $line) {
            if (str_starts_with($line, $prefix)) {
                return substr($line, strlen($prefix));
            }
        }
        throw new VerifyError(sprintf('falta la línea %s', json_encode(trim($prefix))));
    }

    /**
     * renderHeader reconstruye el encabezado a partir de la prueba.
     *
     * Tiene que producir EXACTAMENTE los mismos bytes que el emisor en Go. Es el punto
     * donde las implementaciones se tienen que encontrar, y por eso los vectores golden
     * existen: si alguien cambia un espacio en un lado, los otros lo notan.
     *
     * Los campos que vienen del header se copian VERBATIM, timestamp incluido (ADR-019):
     * reformatear un campo firmado inventa una segunda representación de él, y dos
     * representaciones acaban en dos verificadores que no coinciden. Pasó: Go imprimía el
     * tiempo declarado sin su fracción de segundo y TypeScript imprimía el literal.
     */
    public function renderHeader(?string $provable): string
    {
        $lines = [
            self::MAGIC,
            'destinatario      : ' . $this->recipient . self::RECIPIENT_NOTE,
            'emisor (tenant)   : ' . ($this->header['tenant'] ?? ''),
            'tipo de registro  : ' . ($this->header['type'] ?? ''),
            'hash del contenido: ' . ($this->header['payload_hash'] ?? ''),
            'bloque            : ' . $this->headerIndex,
            '',
            'TIEMPO DECLARADO  : ' . ($this->header['timestamp'] ?? '') . '  (declarado por el sistema emisor)',
            $provable === null
                ? 'TIEMPO DEMOSTRABLE: ' . self::NO_PROVABLE_TIME
                : 'TIEMPO DEMOSTRABLE: ' . $provable . '  (atestiguado por testigos)',
            '',
        ];
        foreach (self::LEGAL_NOTICE as $l) {
            $lines[] = $l;
        }
        $lines[] = '';
        $lines[] = '';
        return implode("\n", $lines);
    }

    /** text devuelve solo el encabezado legible de un recibo, para mostrarlo. */
    public static function readableText(string $receipt): string
    {
        $at = strpos($receipt, self::SEPARATOR);
        return $at === false ? '' : rtrim(substr($receipt, 0, $at), "\n");
    }
}
