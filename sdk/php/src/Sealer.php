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
    /** @var callable|null */
    private $onStale;

    /**
     * @param string $binary         ruta del ejecutable `nucleo`
     * @param string $dir            directorio del despliegue (el que lleva nucleo.db)
     * @param string $passphraseFile fichero con la passphrase, en modo 0600
     * @param string|null $policyFile fichero de política; se pasa a la CLI como
     *                                --policy-file en TODA ejecución (ADR-017)
     * @param int $timeout           segundos antes de declarar colgado el sellado
     * @param callable|null $onStale  function (array $alert): void — se llama en CADA
     *                                operación mientras haya una alarma de frescura
     *                                abierta y sin reconocer (ADR-028 §E). Es un
     *                                requisito de integración: ver docs/OPERACION.md.
     */
    public function __construct(
        string $binary,
        string $dir,
        string $passphraseFile,
        ?string $policyFile = null,
        int $timeout = 60,
        ?callable $onStale = null
    ) {
        $this->binary = $binary;
        $this->dir = $dir;
        $this->passphraseFile = $passphraseFile;
        $this->policyFile = $policyFile;
        $this->timeout = $timeout;
        $this->onStale = $onStale;
    }

    /**
     * seal sella un fichero ya escrito en disco.
     *
     * $idempotencyKey es lo que hace que un reintento tras un timeout no duplique el
     * registro (ADR-020 §D): con la misma clave y el mismo documento, la CLI no escribe
     * nada y contesta lo del sellado original, y el resultado lo dice en ->idempotent.
     * Un ERP que reintenta debería pasarla SIEMPRE.
     *
     * $failOnStale: con la atestación vieja, NO sella y lanza SealSyncError (código 3,
     * errorClass "transient") en vez de sellar igualmente. Está desactivado por omisión a
     * propósito (ADR-028 §A): un registro que no se sella se pierde. Es para quien tiene
     * una cola y reintenta, con la misma clave, después de un sync.
     */
    public function seal(
        string $payloadFile,
        string $type,
        string $tenant,
        ?string $idempotencyKey = null,
        bool $encrypt = true,
        bool $failOnStale = false
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
        if ($failOnStale) {
            $args[] = '--fail-on-stale';
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
        bool $encrypt = true,
        bool $failOnStale = false
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
            return $this->seal($tmp, $type, $tenant, $idempotencyKey, $encrypt, $failOnStale);
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
     * sync pide atestación al testigo. Es lo que el cron del ERP ejecuta cada hora.
     *
     * Si el testigo no contesta, lanza SealSyncError —y antes llama a onStale si la
     * alarma de frescura está abierta: es justo el momento en que se produce—.
     *
     * @return array<string, mixed> el --json de `nucleo sync`
     */
    public function sync(string $witnessUrl): array
    {
        $j = $this->run(['sync', '--witness', $witnessUrl, '--passphrase-file', $this->passphraseFile]);
        Contract::boolField($j, 'attested');
        Contract::alert($j);
        return Contract::toArray($j);
    }

    /**
     * alertStatus devuelve la alarma de frescura (ADR-028): el objeto `alert` con su
     * `state` —"none", "open" o "acked"—, y la frescura con la que se juzgó.
     *
     * @return array<string, mixed>
     */
    public function alertStatus(): array
    {
        $j = $this->run(['alert', 'status']);
        $a = Contract::alert($j);
        if ($a === null) {
            throw new SealContractError('alert status no trajo el objeto alert: el binario es anterior a ADR-028');
        }
        return Contract::toArray($j);
    }

    /**
     * alertAck deja constancia de que alguien se ha enterado. No cierra la alarma —la
     * cierra un sync que sale bien—, pero onStale deja de llamarse hasta el siguiente
     * episodio. Llámalo cuando tu canal haya ENTREGADO el aviso, no antes: si lo llamas
     * dentro del propio hook y el correo falla, la alarma queda reconocida y nadie lo sabe.
     *
     * @return array<string, mixed>
     */
    public function alertAck(?string $by = null): array
    {
        $args = ['alert', 'ack'];
        if ($by !== null) {
            $args[] = '--by';
            $args[] = $by;
        }
        $j = $this->run($args);
        Contract::boolField($j, 'acked');
        return Contract::toArray($j);
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
        // `alert status` y `alert ack` son subcomandos de DOS palabras: la política va
        // detrás de las dos, no entre ellas.
        $subcomando = [array_shift($args)];
        if ($subcomando[0] === 'alert' && $args !== []) {
            $subcomando[] = array_shift($args);
        }
        $cmd = array_merge(
            [$this->binary, '--dir', $this->dir, '--json'],
            $subcomando,
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
            if ($code === 0) {
                throw $e;
            }
            // Un código distinto de 0 SIN el JSON de la CLI no es un veredicto: el proceso
            // murió antes de poder darlo. Y el caso real deja una trampa: el runtime de Go
            // sale con 2 en un error fatal —con memoria virtual limitada por debajo de
            // ~800 MiB muere con "fatal error: out of memory allocating heap arena map"—,
            // y 2 es «la verificación falló» en el contrato. Leerlo por el código haría
            // escalar como incidente de integridad un límite de memoria del hosting.
            throw new SealEnvironmentError(self::murioSinContestar($code, $err));
        }
        // La alarma, antes que nada: también cuando la CLI devuelve un error. Un `sync`
        // que no llega al testigo y un `seal --fail-on-stale` que se niega traen `alert`
        // en el objeto de error, y son justo los dos momentos en que más importa.
        $this->avisaSiHayAlarma($j);
        if ($code !== 0 || ($j->ok ?? null) === false) {
            // La clase viaja en la excepción (ADR-027). Se lee con el mismo lector que
            // los vectores, así que una clase desconocida es un error de contrato y no
            // un valor que se cuela hasta el ERP.
            throw SealError::make(
                is_string($j->error ?? null) ? $j->error : 'el sellado falló sin decir por qué',
                $code,
                $err,
                Contract::errorClass($j, in_array($code, [1, 2, 3], true) ? $code : 1)
            );
        }
        return $j;
    }

    /**
     * murioSinContestar redacta el error de un binario que terminó sin escribir su JSON.
     */
    private static function murioSinContestar(int $code, string $stderr): string
    {
        $primera = trim(strtok($stderr, "\n") ?: '');
        $msg = sprintf(
            'el binario de Núcleo terminó con código %d sin escribir su respuesta, así que ese ' .
            'código no es un veredicto: el proceso no llegó a contestar.',
            $code
        );
        if (str_contains($stderr, 'out of memory') || str_contains($stderr, 'failed to reserve')) {
            $msg .= ' Se quedó sin memoria: el hosting limita la memoria virtual del proceso por ' .
                'debajo de lo que necesita el binario (~800 MiB de memoria virtual, aunque use ' .
                'mucha menos memoria real). Pídele al proveedor que suba ese límite; ver ' .
                'docs/OPERACION.md.';
        }
        if ($primera !== '') {
            $msg .= ' Detalle: ' . $primera;
        }
        return $msg;
    }

    /**
     * avisaSiHayAlarma llama a onStale si la salida trae una alarma abierta sin reconocer.
     *
     * Al menos una vez (ADR-028 §E): se repite en cada operación hasta que alguien
     * ejecuta alertAck(), porque un hook que avisara solo la primera vez perdería el
     * aviso el día que el correo estuviera caído.
     *
     * Si el hook lanza, la excepción NO sale de aquí: se escribe en el log de errores de
     * PHP con error_log() y la operación sigue. El sellado ya está hecho cuando se llama
     * al hook, y una excepción de un correo que no sale convertiría un sellado bueno en
     * uno que el ERP daría por fallido.
     */
    private function avisaSiHayAlarma(\stdClass $j): void
    {
        if ($this->onStale === null || !property_exists($j, 'alert')) {
            return;
        }
        try {
            $a = Contract::alert($j);
        } catch (SealContractError $e) {
            // Un alert que no cumple el contrato lo rechaza el camino normal; aquí no se
            // llama al hook con algo que no se entiende.
            return;
        }
        if ($a === null || ($a['state'] ?? null) !== 'open') {
            return;
        }
        try {
            ($this->onStale)($a);
        } catch (\Throwable $e) {
            error_log(sprintf(
                '[nucleo] el hook onStale lanzó %s: %s. La alarma de frescura sigue abierta desde %s.',
                get_class($e),
                $e->getMessage(),
                (string) ($a['stale_since'] ?? '?')
            ));
        }
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
