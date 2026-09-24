<?php

declare(strict_types=1);

namespace Nucleo;

/**
 * SealError y sus tres hijas traducen los códigos de salida de la CLI a excepciones
 * tipadas (ADR-021 §A).
 *
 * Tipadas y no un código en un campo porque lo que un ERP hace con cada una es
 * distinto: un error de uso es un bug del integrador que hay que arreglar, un fallo de
 * integridad es un incidente que hay que escalar, y un fallo de sincronización es algo
 * que se reintenta luego. Un `catch (SealError)` genérico sigue funcionando.
 */
class SealError extends \RuntimeException
{
    /** @var string lo que la CLI escribió por stderr, para el log del integrador */
    public string $stderr = '';
    /** @var int el código de salida de la CLI, o -1 si no llegó a ejecutarse */
    public int $exitCode = -1;
    /**
     * @var string la clase del error (ADR-027): usage, transient, environment o
     * integrity. Dice lo que el código de salida no puede: si esto se reintenta, si hay
     * que llamar a una persona o si es un incidente. Un binario antiguo no la manda y
     * entonces se deduce del código.
     */
    public string $errorClass = '';

    /** esReintentable es la pregunta que un ERP hace de verdad. */
    public function esReintentable(): bool
    {
        return $this->errorClass === 'transient';
    }

    public static function make(string $mensaje, int $code, string $stderr, string $errorClass = ''): self
    {
        $clase = self::class;
        if ($code === 1) {
            $clase = SealUsageError::class;
        } elseif ($code === 2) {
            $clase = SealIntegrityError::class;
        } elseif ($code === 3) {
            $clase = SealSyncError::class;
        }
        /** @var self $e */
        $e = new $clase($mensaje);
        $e->exitCode = $code;
        $e->stderr = $stderr;
        $e->errorClass = $errorClass !== '' ? $errorClass : match ($code) {
            2 => 'integrity',
            3 => 'transient',
            default => 'usage',
        };
        return $e;
    }
}
