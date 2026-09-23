<?php

declare(strict_types=1);

namespace Nucleo;

/**
 * SealContractError es lo que se lanza cuando la salida de la CLI no cumple el contrato
 * de docs/CLI-JSON.md: un campo obligatorio que falta, un tipo que no es el suyo, o algo
 * que no es JSON.
 *
 * Es su propia clase porque su causa no está en el ledger ni en el documento: está en el
 * BINARIO. Un binario antiguo, truncado, equivocado o sustituido cae aquí, y lo que hay
 * que hacer con eso —revisar el despliegue— no se parece a lo que se hace con un error de
 * uso ni con un incidente de integridad (ADR-025 §B).
 */
final class SealContractError extends SealError
{
}
