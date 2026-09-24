<?php

declare(strict_types=1);

// El contrato `--json` con los vectores compartidos (ADR-025).
//
// Los válidos los emite la CLI de verdad (cmd/nucleo/clijson_vectors_test.go); los
// inválidos están escritos a mano, porque son justo lo que la CLI nunca produce: un
// binario anterior al formato, uno sustituido que miente en un tipo, una salida cortada
// a la mitad. Los primeros tienen que parsear y los segundos tienen que LANZAR.
//
// Es la otra mitad del hallazgo medio del 2026-09-19: no basta con que el lector sea
// estricto, hay que poder demostrar contra qué es estricto.

use Nucleo\Contract;
use Nucleo\SealContractError;
use Nucleo\SealError;
use Nucleo\SealResult;

function pruebasDeContrato(string $vectores): void
{
    grupo('contrato --json (testdata/vectors/cli-json)');

    $n = 0;
    $validos = 0;
    $invalidos = 0;
    foreach (glob($vectores . '/cli-json/*.json') as $f) {
        $v = leerJSON($f);
        $n++;
        $nombre = $v['name'];
        $stdout = $v['stdout'];

        if ($v['valid'] === false) {
            $invalidos++;
            // Los inválidos que son OBJETOS DE ERROR van por el camino del error, no por
            // el del sellado. Si fueran por el del sellado se rechazarían por llevar
            // `ok: false`, que es cierto y no prueba nada: el vector existe para fijar
            // que la clase del error se valida (ADR-027), y un test que pasa por el
            // motivo equivocado es un test que no vigila nada.
            if (str_starts_with($nombre, 'invalido-error-class')) {
                try {
                    Contract::error(Contract::decode($stdout));
                    comprueba('rechaza ' . $nombre, false, 'debería haber lanzado; motivo del vector: ' . $v['reason']);
                } catch (SealContractError $e) {
                    comprueba('rechaza ' . $nombre, true);
                } catch (\Throwable $e) {
                    comprueba('rechaza ' . $nombre, false, 'lanzó ' . get_class($e) . ': ' . $e->getMessage());
                }
                continue;
            }
            // Regla para el resto: el camino del sellado los rechaza. Todos son
            // mutaciones de una salida de `seal` o cosas que no son JSON.
            try {
                SealResult::fromCliJson($stdout);
                comprueba('rechaza ' . $nombre, false, 'debería haber lanzado; motivo del vector: ' . $v['reason']);
            } catch (SealContractError $e) {
                comprueba('rechaza ' . $nombre, true);
            } catch (\Throwable $e) {
                // Lanzar está bien; lanzar OTRA cosa no: el integrador captura
                // SealContractError, y una excepción de otro tipo se le escapa.
                comprueba('rechaza ' . $nombre, false, 'lanzó ' . get_class($e) . ': ' . $e->getMessage());
            }
            continue;
        }

        $validos++;
        // Por familia, porque cada subcomando tiene su contrato.
        if (str_starts_with($nombre, 'valido-seal')) {
            $r = null;
            try {
                $r = SealResult::fromCliJson($stdout);
                comprueba('acepta ' . $nombre, true);
            } catch (\Throwable $e) {
                comprueba('acepta ' . $nombre, false, get_class($e) . ': ' . $e->getMessage());
            }
            if ($r === null) {
                continue;
            }
            // Y no solo "parsea": lo que el vector dice es lo que el objeto afirma.
            $j = Contract::toArray(Contract::decode($stdout));
            igual($nombre . ': index', $j['index'], $r->index);
            igual($nombre . ': hash', $j['hash'], $r->hash);
            igual($nombre . ': payload_hash', $j['payload_hash'], $r->payloadHash);
            igual($nombre . ': idempotent', $j['idempotent'], $r->idempotent);
            igual($nombre . ': attestation', $j['attestation'], $r->attestation);
            igual($nombre . ': duplicate_of', $j['duplicate_of'] ?? [], $r->duplicateOf);
            igual($nombre . ': freshness.stale', $j['freshness']['stale'], $r->stale);
            igual($nombre . ': signer.verified', $j['signer']['verified'], $r->signerVerified);
            continue;
        }
        if (str_starts_with($nombre, 'valido-status')) {
            try {
                Contract::status(Contract::decode($stdout));
                comprueba('acepta ' . $nombre, true);
            } catch (\Throwable $e) {
                comprueba('acepta ' . $nombre, false, get_class($e) . ': ' . $e->getMessage());
            }
            continue;
        }
        if (str_starts_with($nombre, 'valido-error')) {
            try {
                $e = Contract::error(Contract::decode($stdout));
                comprueba('acepta ' . $nombre, true);
                // La clase se lee, y es una de las cuatro (ADR-027).
                igual($nombre . ': error_class', 'usage', $e['error_class']);
            } catch (\Throwable $e) {
                comprueba('acepta ' . $nombre, false, get_class($e) . ': ' . $e->getMessage());
            }
            // Y el camino del sellado lo rechaza, que es lo que tiene que pasar cuando un
            // integrador confunde un error con un resultado.
            try {
                SealResult::fromCliJson($stdout);
                comprueba($nombre . ': no pasa por sellado', false, 'un error no es un sellado');
            } catch (SealContractError $e) {
                comprueba($nombre . ': no pasa por sellado', true);
            }
            continue;
        }
        comprueba('familia conocida: ' . $nombre, false, 'el vector no encaja en ninguna familia del contrato');
    }

    comprueba('hay vectores de contrato', $n >= 30, sprintf('solo %d', $n));
    comprueba('hay válidos e inválidos', $validos >= 8 && $invalidos >= 20,
        sprintf('%d válidos, %d inválidos', $validos, $invalidos));

    // La clase del error se deduce del código cuando el binario no la manda, que es lo
    // que pasa con un despliegue anterior a septiembre de 2026 (ADR-027 §C).
    foreach ([[1, 'usage'], [2, 'integrity'], [3, 'transient']] as [$code, $esperada]) {
        $viejo = Contract::decode(sprintf('{"ok":false,"error":"algo","exit_code":%d}', $code));
        $a = Contract::error($viejo);
        igual(sprintf('binario sin error_class: código %d', $code), $esperada, $a['error_class']);
    }
    // Y una clase desconocida en esa misma salida no se interpreta a la baja.
    try {
        Contract::error(Contract::decode('{"ok":false,"error":"algo","exit_code":1,"error_class":"retryable"}'));
        comprueba('una clase desconocida no pasa', false, 'debería haber lanzado');
    } catch (SealContractError $e) {
        comprueba('una clase desconocida no pasa', true);
    }
    // La excepción tipada lleva la clase, y contesta la pregunta que un ERP hace.
    $e = SealError::make('el testigo no contesta', 3, '', 'transient');
    comprueba('SealError transitorio es reintentable', $e->esReintentable());
    $e2 = SealError::make('la clave no es la de la política', 3, '', 'environment');
    comprueba('SealError de entorno NO es reintentable', !$e2->esReintentable());
    igual('SealError sin clase la deduce del código', 'integrity', SealError::make('x', 2, '')->errorClass);

    // Lo que el contrato SÍ tolera, y es la otra mitad de la regla: un campo que este SDK
    // no conoce. Un binario más nuevo puede añadirlos y el envoltorio tiene que seguir
    // andando (CLI-JSON.md §Estabilidad, ADR-025 §B).
    $j = Contract::decode(leerJSON($vectores . '/cli-json/valido-seal.json')['stdout']);
    $j->campo_del_futuro = ['lo que sea', 42];
    $j->otro_mas = null;
    try {
        $r = SealResult::fromObject($j);
        comprueba('un campo desconocido NO rompe el contrato', $r->index === $j->index);
    } catch (\Throwable $e) {
        comprueba('un campo desconocido NO rompe el contrato', false, $e->getMessage());
    }
}
