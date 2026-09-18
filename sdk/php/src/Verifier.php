<?php

declare(strict_types=1);

namespace Nucleo;

/**
 * Verifier comprueba un recibo completo contra una política.
 *
 * NUNCA lanza: devuelve un Result con las razones. Un verificador que lanza obliga a
 * envolver cada llamada en un try, y basta un olvido para que un recibo malo parezca
 * bueno.
 *
 * Los seis pasos son los de PROTOCOL.md §3.1, en ese orden.
 */
final class Verifier
{
    /**
     * verify acepta la política como objeto Policy, como array (la que un integrador
     * escribe en código) o como texto (la que llega en un fichero).
     *
     * @param Policy|array|string $policy
     */
    public static function verify(string $receipt, $policy): Result
    {
        try {
            return self::run($receipt, $policy);
        } catch (\Throwable $e) {
            // Red de seguridad. Si algo dentro lanza pese a todo, quien llama recibe un
            // veredicto negativo con la razón, no una excepción. La promesa de esta
            // función es que nunca lanza, y una promesa con excepciones no es una
            // promesa.
            $r = new Result();
            $r->reasons = [sprintf('error inesperado al verificar: %s', $e->getMessage())];
            return $r;
        }
    }

    /** @param Policy|array|string $policy */
    private static function run(string $receipt, $policy): Result
    {
        $r = new Result();

        try {
            $p = Receipt::parse($receipt);
        } catch (VerifyError $e) {
            $r->reasons[] = sprintf('el recibo no se pudo leer: %s', $e->getMessage());
            return $r;
        }

        // La POLÍTICA también es entrada, y viene de fuera igual que el recibo: de un
        // fichero de configuración, de un formulario, de un JSON pegado a mano. Una
        // función que promete no lanzar tiene que cumplirlo con TODAS sus entradas.
        try {
            $pol = self::asPolicy($policy);
            if ($pol->signerKey === null) {
                throw new VerifyError('falta signerKey: la clave del firmante de bloques tiene que venir en la política (ADR-017)');
            }
            $logKey = self::keyBytes($pol->logKey, 'logKey');
            $signerKey = self::keyBytes($pol->signerKey, 'signerKey');
            $witnesses = [];
            foreach ($pol->witnesses as $w) {
                $witnesses[] = ['name' => $w['name'], 'key' => self::keyBytes($w['key'], 'la clave del testigo ' . $w['name'])];
            }
        } catch (VerifyError $e) {
            $r->reasons[] = sprintf('la política no se pudo leer: %s', $e->getMessage());
            return $r;
        }

        // 1. El origin del checkpoint tiene que ser el de la política.
        if ($p->checkpoint->origin !== $pol->origin) {
            $r->reasons[] = sprintf(
                'el recibo es del log %s y la política espera %s',
                json_encode($p->checkpoint->origin),
                json_encode($pol->origin)
            );
        }

        // 2. El header tiene que estar en forma canónica JCS: es lo que se firmó.
        if (!Jcs::isCanonical($p->headerJSON)) {
            $r->reasons[] = 'el header del bloque no está en forma canónica JCS';
        }

        // 3. La hoja sale del header Y de la firma (leaf/v2, PROTOCOL.md §2.1).
        $blockHash = hash('sha256', $p->headerJSON, true);
        $leafData = $blockHash . $p->blockSig;

        // 3b. IDENTIDAD del firmante, contra la política y no contra el recibo
        // (ADR-017): la pregunta que la contraparte hace en realidad es "¿es de quien
        // creo que es?", y una firma válida de OTRA clave no la responde.
        $signerHex = is_string($p->header['signer_pubkey'] ?? null) ? $p->header['signer_pubkey'] : '';
        if (strtolower($signerHex) !== Bytes::binToHex($signerKey)) {
            $r->reasons[] = 'el bloque no está firmado por la clave del emisor que fija la política (signerKey)';
        }
        $signerPub = Bytes::hexToBin($signerHex);
        if ($signerPub === null || strlen($signerPub) !== 32) {
            $r->reasons[] = 'signer_pubkey del header no es una clave Ed25519';
        } else {
            $r->blockSignatureVerified = self::ed25519($signerPub, $p->blockSig, $blockHash);
            if (!$r->blockSignatureVerified) {
                $r->reasons[] = 'la firma del bloque no verifica con la clave signer_pubkey del header';
            }

            // 3c. Y la firma del emisor sobre el recibo ENTERO, destinatario incluido
            // (ADR-015). Es la que hace que el nombre del destinatario deje de ser una
            // línea que cualquiera con el fichero puede reescribir.
            if ($p->receiptSig === null) {
                $r->reasons[] = 'el recibo no lleva firma del emisor';
            } else {
                $digest = hash('sha256', $p->signedBytes, true);
                $r->receiptSignatureVerified = self::ed25519($signerPub, $p->receiptSig, $digest);
                if (!$r->receiptSignatureVerified) {
                    $r->reasons[] = 'la firma del emisor sobre el recibo no verifica: el recibo fue alterado';
                }
            }
        }

        // 4. Firmas de la nota del checkpoint (PROTOCOL.md §3.3).
        $logId = Note::keyId($pol->origin, Note::ALG_ED25519, $logKey);
        $logSigned = false;
        // Indexado por (nombre, key ID), que es lo que identifica una clave en
        // signed-note. Por key ID solo, dos testigos cuyos IDs de 4 bytes colisionaran
        // se pisarían en el mapa.
        $porId = [];
        foreach ($witnesses as $w) {
            $porId[$w['name'] . "\n" . Note::keyId($w['name'], Note::ALG_COSIGNATURE_V1, $w['key'])] = $w;
        }
        $contados = [];
        $earliest = null;
        foreach ($p->note->sigs as $sig) {
            $id = $sig['name'] . "\n" . $sig['keyId'];
            if ($sig['name'] === $pol->origin && $sig['keyId'] === $logId) {
                // Una firma de una clave CONOCIDA que no verifica invalida la nota
                // entera. No es lo mismo que una firma desconocida.
                if (!self::ed25519($logKey, $sig['signature'], $p->note->text)) {
                    $r->reasons[] = 'la firma del log no verifica';
                    continue;
                }
                $logSigned = true;
                continue;
            }
            if (!isset($porId[$id])) {
                if ($sig['name'] === $pol->origin && strlen($sig['signature']) === Receipt::MLDSA44_SIGNATURE_SIZE) {
                    // La ML-DSA-44 del propio log: no hay ML-DSA en PHP, así que no se
                    // verifica, pero tampoco es "una clave que no conoces".
                    $r->logAdditionalSignatures++;
                    continue;
                }
                // Firmas de claves desconocidas: cosignatures de otros testigos. Se
                // IGNORAN, como manda c2sp.org/signed-note. Es lo que permite que un
                // mismo recibo circule entre partes que confían en testigos distintos.
                $r->ignoredSignatures[] = $sig['name'];
                continue;
            }
            $w = $porId[$id];
            $cs = Cosignature::parse($sig['signature']);
            if ($cs === null) {
                $r->reasons[] = sprintf(
                    'la cosignature de %s mide %d bytes y una tlog-cosignature@v1 mide %d',
                    $sig['name'],
                    strlen($sig['signature']),
                    Cosignature::SIZE
                );
                continue;
            }
            if (!self::ed25519($w['key'], $cs->signature, Cosignature::message($cs->timestamp, $p->note->text))) {
                $r->reasons[] = sprintf('la cosignature de %s no verifica', $sig['name']);
                continue;
            }
            // Un testigo cuenta UNA vez para el quórum, tenga las líneas que tenga
            // (PROTOCOL.md §3.3): la tercera auditoría duplicó la cosignature de un
            // único testigo, re-firmó el recibo y cumplió un quórum 2-de-2 en la página.
            if (!isset($contados[$id])) {
                $contados[$id] = true;
                $r->cosigners[] = $sig['name'];
            }
            // El tiempo de un testigo es el MÁS ANTIGUO de sus líneas que verifican, y
            // el demostrable el mínimo entre los contados: el orden de las líneas, que
            // lo elige el emisor, no puede cambiar el resultado.
            if ($earliest === null || $cs->timestamp < $earliest) {
                $earliest = $cs->timestamp;
            }
        }

        if (!$logSigned) {
            $r->reasons[] = 'el checkpoint no está firmado por la clave del log';
        }
        if (count($r->cosigners) < $pol->quorum) {
            $r->reasons[] = sprintf('quórum de testigos no alcanzado: %d de %d', count($r->cosigners), $pol->quorum);
        }

        // 5. El camino de inclusión.
        if (!Merkle::verifyInclusion($leafData, $p->proof->index, $p->checkpoint->size, $p->proof->inclusionProof, $p->checkpoint->rootHash)) {
            $r->reasons[] = 'la prueba de inclusión no verifica contra la raíz del checkpoint';
        }
        if ($p->proof->index !== $p->headerIndex) {
            $r->reasons[] = sprintf(
                'el índice de la prueba (%d) no es el del header (%d)',
                $p->proof->index,
                $p->headerIndex
            );
        }

        // 6. El encabezado legible tiene que derivarse de todo lo anterior.
        $provable = $earliest === null ? null : gmdate('Y-m-d\TH:i:s\Z', $earliest);
        if ($p->renderHeader($provable) !== $p->text) {
            $r->reasons[] = 'el texto del recibo no coincide con lo que dice la prueba: el encabezado fue alterado o el tiempo demostrable no lo respalda ningún testigo aceptado';
        }

        $r->valid = count($r->reasons) === 0;
        $r->declaredTime = is_string($p->header['timestamp'] ?? null) ? $p->header['timestamp'] : null;
        $r->provableTime = $r->valid ? $provable : null;
        $r->blockIndex = $p->headerIndex;
        $r->recipient = $p->recipient;
        $r->signerPubKey = $signerHex !== '' ? $signerHex : null;
        $r->checkpoint = [
            'origin' => $p->checkpoint->origin,
            'size' => (string) $p->checkpoint->size,
            'rootHash' => Bytes::binToHex($p->checkpoint->rootHash),
        ];
        return $r;
    }

    /** @param Policy|array|string $policy */
    private static function asPolicy($policy): Policy
    {
        if ($policy instanceof Policy) {
            return $policy;
        }
        if (is_array($policy)) {
            return Policy::fromArray($policy);
        }
        if (is_string($policy)) {
            return Policy::fromText($policy);
        }
        throw new VerifyError('la política no es un objeto, un array ni un texto');
    }

    private static function keyBytes(string $hex, string $cual): string
    {
        $raw = Bytes::hexToBin($hex);
        if ($raw === null) {
            throw new VerifyError(sprintf('%s no es hexadecimal en minúsculas', $cual));
        }
        if (strlen($raw) !== 32) {
            throw new VerifyError(sprintf('%s mide %d bytes y una clave Ed25519 mide 32', $cual, strlen($raw)));
        }
        return $raw;
    }

    /**
     * ed25519 verifica una firma. Devuelve false ante cualquier error en vez de lanzar:
     * sodium lanza SodiumException con una firma del tamaño equivocado, y eso aquí es un
     * veredicto negativo, no una excepción.
     */
    private static function ed25519(string $pub, string $sig, string $msg): bool
    {
        if (strlen($sig) !== 64 || strlen($pub) !== 32) {
            return false;
        }
        try {
            return sodium_crypto_sign_verify_detached($sig, $msg, $pub);
        } catch (\Throwable $e) {
            return false;
        }
    }
}
