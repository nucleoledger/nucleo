<?php

declare(strict_types=1);

namespace Nucleo;

/**
 * SealEnvironmentError es cuando el binario NO LLEGA A EJECUTARSE: proc_open
 * deshabilitado, el fichero no está, no tiene permiso de ejecución, o el fichero de
 * passphrase es legible por otros.
 *
 * Es su propia clase porque su arreglo no está en el código: está en el hosting, y el
 * mensaje dice qué pedirle al proveedor (ADR-021 §C).
 */
final class SealEnvironmentError extends SealError
{
}
