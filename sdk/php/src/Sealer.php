<?php

declare(strict_types=1);

namespace Nucleo;

/**
 * Sealer sella ejecutando el binario `nucleo`. NO reimplementa nada (ADR-021 §A).
 *
 * Por qué un envoltorio y no una implementación nativa: el escritor del ledger sostiene
 * invariantes que no están en el formato —el encadenamiento contra el último bloque
 * persistido, la transacción única de ADR-020, el cerrojo anti-retroceso, la atestación
 * en la apertura—, así que una segunda implementación no necesita equivocarse en
 * criptografía para romper un ledger de un cliente, y lo que escriba es append-only.
 *
 * Lo que este envoltorio SÍ aporta: la idempotencia donde el ERP la necesita, los
 * códigos de salida como excepciones tipadas, y un error EXPLÍCITO cuando el entorno no
 * puede ejecutar el binario. Nunca un degradado silencioso: un sellador que "sigue
 * adelante" sin sellar es lo peor que este producto puede hacer.
 */
final class Sealer
{
    private string $binary;
    private string $dir;
    private string $passphraseFile;
    private ?string $policyFile;
    private int $timeout;

    /**
     * @param string $binary         ruta del ejecutable `nucleo`
     * @param string $dir            directorio del despliegue (el que lleva nucleo.db)
     * @param string $passphraseFile fichero con la passphrase, en modo 0600
     * @param string|null $policyFile fichero de política; se pasa a la CLI como
     *                                --policy-file en TODA ejecución (ADR-017)
     * @param int $timeout           segundos antes de declarar colgado el sellado
     */
    public function __construct(
        string $binary,
        string $dir,
        string $passphraseFile,
        ?string $policyFile = null,
        int $timeout = 60
    ) {
        $this->binary = $binary;
        $this->dir = $dir;
        $this->passphraseFile = $passphraseFile;
        $this->policyFile = $policyFile;
        $this->timeout = $timeout;
    }

    /**
     * seal sella un fichero ya escrito en disco.
     *
     * $idempotencyKey es lo que hace que un reintento tras un timeout no duplique el
     * registro (ADR-020 §D): con la misma clave y el mismo documento, la CLI no escribe
     * nada y contesta lo del sellado original, y el resultado lo dice en ->idempotent.
     * Un ERP que reintenta debería pasarla SIEMPRE.
     */
    public function seal(
        string $payloadFile,
        string $type,
        string $tenant,
        ?string $idempotencyKey = null,
        bool $encrypt = true
    ): SealResult {
        $args = ['seal', '--tenant', $tenant, '--type', $type, '--payload', $payloadFile,
            '--passphrase-file', $this->passphraseFile];
        if ($idempotencyKey !== null) {
            $args[] = '--idempotency-key';
            $args[] = $idempotencyKey;
        }
        if (!$encrypt) {
            $args[] = '--no-encrypt';
        }
        return SealResult::fromObject($this->run($args));
    }

    /**
     * sealBytes escribe el contenido en un fichero temporal en modo 0600 y lo sella.
     *
     * El fichero se borra siempre, también si el sellado falla: es el documento del
     * cliente y no tiene por qué quedarse en /tmp.
     */
    public function sealBytes(
        string $payload,
        string $type,
        string $tenant,
        ?string $idempotencyKey = null,
        bool $encrypt = true
    ): SealResult {
        $tmp = tempnam(sys_get_temp_dir(), 'nucleo-');
        if ($tmp === false) {
            throw new SealEnvironmentError('no se pudo crear el fichero temporal del documento');
        }
        try {
            if (!self::esWindows()) {
                @chmod($tmp, 0600);
            }
            if (file_put_contents($tmp, $payload) === false) {
                throw new SealEnvironmentError('no se pudo escribir el documento en ' . $tmp);
            }
            return $this->seal($tmp, $type, $tenant, $idempotencyKey, $encrypt);
        } finally {
            @unlink($tmp);
        }
    }

    /**
     * status devuelve el --json de `nucleo status`, útil para un cron de vigilancia.
     *
     * Pasa por el contrato igual que el sellado (ADR-025): devuelve el objeto entero
     * —lo que un cron mira cambia con lo que a cada integrador le importe— pero solo
     * después de comprobar que lo obligatorio está y es del tipo que dice ser.
     */
    public function status(): array
    {
        return Contract::status($this->run(['status']));
    }

    /**
     * politica devuelve --policy-file si el integrador dio una política, o nada.
     *
     * Va en el camino COMÚN de run() y no en cada subcomando, y eso es la corrección del
     * hallazgo alto de la auditoría del 2026-09-19: el constructor aceptaba la política,
     * la guardaba… y ni seal() ni status() la pasaban al binario. Un ERP podía creer que
     * había configurado la raíz de confianza de ADR-017 mientras la CLI se abría sin
     * ella: la atestación, la frescura y la identidad del firmante salían sin verificar y
     * nadie se enteraba. Un parámetro que APARENTA configurar algo y no lo configura es
     * peor que no ofrecerlo.
     *
     * Por qué aquí y no repitiéndolo en cada método: porque repetirlo es exactamente el
     * error que se acaba de arreglar. Todo subcomando que este envoltorio ejecute la
     * recibe; si algún día se envuelve uno que no la admita —`init`, por ejemplo—, la CLI
     * contesta con un error de uso en la primera ejecución, que es un fallo ruidoso y no
     * un silencio.
     *
     * @return string[]
     */
    private function politica(): array
    {
        return $this->policyFile === null ? [] : ['--policy-file', $this->policyFile];
    }

    /**
     * run ejecuta la CLI y devuelve su JSON ya decodificado (stdClass: ver
     * Contract::decode sobre por qué no un array).
     *
     * proc_open con el comando en ARRAY: así no hay shell, y por tanto no hay citado que
     * se pueda equivocar con un nombre de fichero raro. La passphrase va por fichero y
     * nunca por argumento —la lista de procesos la ve toda la máquina— ni por entorno,
     * que en muchos paneles es legible.
     */
    private function run(array $args): \stdClass
    {
        if ($args === []) {
            throw new SealEnvironmentError('run sin subcomando: es un error de programación del SDK');
        }
        $this->checkEntorno();
        // El orden importa y no es adorno: --dir y --json son banderas GLOBALES y van
        // antes del subcomando, mientras --policy-file lo registra cada subcomando y va
        // DESPUÉS. Con el orden al revés, la CLI contesta "subcomando desconocido".
        $subcomando = array_shift($args);
        $cmd = array_merge(
            [$this->binary, '--dir', $this->dir, '--json', $subcomando],
            $this->politica(),
            $args
        );
        $descr = [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']];
        $proc = @proc_open($cmd, $descr, $pipes);
        if (!is_resource($proc)) {
            throw new SealEnvironmentError(sprintf(
                'no se pudo ejecutar %s. Comprueba que el fichero existe y que el usuario de PHP puede ejecutarlo.',
                $this->binary
            ));
        }
        // La entrada estándar se cierra en el acto: la CLI pide la passphrase por
        // terminal si no encuentra el fichero, y un proceso web no tiene terminal. Sin
        // esto, un olvido del fichero de passphrase se quedaría esperando para siempre.
        fclose($pipes[0]);
        stream_set_blocking($pipes[1], false);
        stream_set_blocking($pipes[2], false);

        $out = '';
        $err = '';
        $limite = microtime(true) + $this->timeout;
        while (true) {
            $out .= (string) stream_get_contents($pipes[1]);
            $err .= (string) stream_get_contents($pipes[2]);
            $estado = proc_get_status($proc);
            if (!$estado['running']) {
                break;
            }
            if (microtime(true) > $limite) {
                proc_terminate($proc);
                fclose($pipes[1]);
                fclose($pipes[2]);
                proc_close($proc);
                throw new SealEnvironmentError(sprintf(
                    'el sellado no terminó en %d s. El registro PUEDE haberse escrito: reintenta con la misma ' .
                    'clave de idempotencia, que es exactamente para esto (ADR-020 §D).',
                    $this->timeout
                ));
            }
            usleep(2000);
        }
        $out .= (string) stream_get_contents($pipes[1]);
        $err .= (string) stream_get_contents($pipes[2]);
        fclose($pipes[1]);
        fclose($pipes[2]);
        $code = proc_close($proc);

        // El decodificador es el del contrato (ADR-025), el mismo que recorren los
        // vectores de testdata/vectors/cli-json/: una salida que no es JSON, o que es
        // JSON y no un objeto, sale por aquí con sus primeros bytes a la vista.
        try {
            $j = Contract::decode($out);
        } catch (SealContractError $e) {
            $e2 = SealError::make($e->getMessage(), $code, $err);
            throw $code === 0 ? $e : $e2;
        }
        if ($code !== 0 || ($j->ok ?? null) === false) {
            throw SealError::make(
                is_string($j->error ?? null) ? $j->error : 'el sellado falló sin decir por qué',
                $code,
                $err
            );
        }
        return $j;
    }

    /**
     * checkEntorno comprueba lo que un hosting compartido puede impedir, y lo dice con
     * lo que hay que pedirle al proveedor (ADR-021 §C).
     */
    private function checkEntorno(): void
    {
        if (!function_exists('proc_open') || self::deshabilitada('proc_open')) {
            throw new SealEnvironmentError(
                'proc_open está deshabilitada en este PHP (disable_functions), así que no se puede ' .
                'ejecutar el binario de Núcleo. Es decisión del proveedor: pídele que la habilite ' .
                'para esta cuenta, o sella desde una máquina donde sí se pueda.'
            );
        }
        if (!is_file($this->binary)) {
            throw new SealEnvironmentError(sprintf('no hay ningún fichero en %s', $this->binary));
        }
        // is_executable solo se cree en Unix, por lo mismo que los permisos del fichero
        // de passphrase: en Windows no consulta ninguna ACL, decide por la extensión del
        // nombre, y se equivoca en las dos direcciones. Una comprobación que dice "no se
        // puede ejecutar" sobre algo que sí se ejecuta es peor que no comprobar: ahí el
        // error real lo da proc_open, y ese camino ya está cubierto abajo con su mensaje.
        if (!self::esWindows() && !is_executable($this->binary)) {
            throw new SealEnvironmentError(sprintf(
                '%s existe pero no se puede ejecutar. Dale permiso (chmod 0700); si tampoco así, ' .
                'el sistema de ficheros puede estar montado noexec y hay que preguntarle al proveedor.',
                $this->binary
            ));
        }
        if (!is_dir($this->dir)) {
            throw new SealEnvironmentError(sprintf('%s no es un directorio de despliegue', $this->dir));
        }
        if (!is_file($this->passphraseFile)) {
            throw new SealEnvironmentError(sprintf(
                'no hay fichero de passphrase en %s. Sin él la CLI la pediría por terminal, y un ' .
                'proceso web no tiene terminal.',
                $this->passphraseFile
            ));
        }
        // La política es la raíz de confianza (ADR-017): si se pidió una y el fichero no
        // está, el sellado NO sigue sin ella. Seguir sería volver al hallazgo de arriba
        // por otro camino.
        if ($this->policyFile !== null) {
            if (!is_file($this->policyFile)) {
                throw new SealEnvironmentError(sprintf(
                    'no hay fichero de política en %s. Se configuró una política y sin ella el ' .
                    'sellado no verificaría ni la atestación ni el firmante (ADR-017).',
                    $this->policyFile
                ));
            }
            if (!is_readable($this->policyFile)) {
                throw new SealEnvironmentError(sprintf(
                    'el fichero de política %s no se puede leer con el usuario de PHP',
                    $this->policyFile
                ));
            }
        }
        if (!self::esWindows()) {
            $modo = @fileperms($this->passphraseFile);
            if ($modo !== false && ($modo & 0077) !== 0) {
                throw new SealEnvironmentError(sprintf(
                    'el fichero de passphrase %s tiene permisos %04o: lo puede leer alguien más. ' .
                    'Ponlo en 0600.',
                    $this->passphraseFile,
                    $modo & 0777
                ));
            }
        }
    }

    /** deshabilitada mira disable_functions, que es donde los paneles apagan proc_open. */
    private static function deshabilitada(string $fn): bool
    {
        $lista = (string) ini_get('disable_functions');
        foreach (explode(',', $lista) as $x) {
            if (strtolower(trim($x)) === strtolower($fn)) {
                return true;
            }
        }
        return false;
    }

    /**
     * esWindows decide si se comprueban los permisos POSIX.
     *
     * En Windows NO se comprueban, y por la misma razón que en la CLI: el acceso lo
     * gobierna la ACL del fichero, que no se ve desde los permisos que expone PHP, y una
     * comprobación que puede decir "está bien" cuando no lo está da una confianza que no
     * se ha ganado.
     */
    private static function esWindows(): bool
    {
        return DIRECTORY_SEPARATOR === '\\';
    }
}
