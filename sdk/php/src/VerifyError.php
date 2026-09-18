<?php

declare(strict_types=1);

namespace Nucleo;

/**
 * VerifyError es lo que se lanza cuando algo no se puede LEER.
 *
 * Es distinto de un veredicto negativo: Verifier::verify no lanza nunca y devuelve un
 * Result con razones. Estas excepciones son internas de los lectores y Verifier las
 * convierte en razones. Que exista el tipo es lo que permite no capturar \Throwable a
 * ciegas en sitios donde eso taparía un error de programación.
 */
final class VerifyError extends \RuntimeException
{
}
