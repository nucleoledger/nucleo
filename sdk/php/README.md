# SDK de PHP de Núcleo

Dos cosas, y la distinción es el ADR entero ([ADR-021](../../docs/adr/ADR-021-sdk-php.md)):

| | qué es | por qué así |
|---|---|---|
| `Nucleo\Verifier` | verificador **nativo** de recibos `receipt@v2` | quien verifica es la contraparte: no puede tener que ejecutar el binario del emisor para comprobar el recibo del emisor |
| `Nucleo\Sealer` | **envoltorio** del binario `nucleo` | el que escribe el ledger tiene que ser uno solo: una segunda implementación no necesita equivocarse en criptografía para romper un ledger, y lo que escriba es append-only |

Sin composer, sin dependencias. Necesita PHP 8.0+ con **ext-sodium** (Ed25519) y
**ext-json**, que vienen con PHP desde 7.2. Si tu proveedor las ha desactivado, el
paquete lo dice al cargarse con el nombre de la extensión.

## Verificar un recibo

```php
require '/ruta/a/sdk/php/autoload.php';

$politica = [
    'origin'    => 'nucleoledger.com/mi-empresa',
    'logKey'    => '5e42…',   // 64 hex, minúsculas
    'signerKey' => '79b5…',   // obligatoria para verificar un recibo (ADR-017)
    'witnesses' => ['witness.example/w1' => '1e98…'],
    'quorum'    => 1,
];

$r = Nucleo\Verifier::verify(file_get_contents('recibo.txt'), $politica);
if (!$r->valid) {
    foreach ($r->reasons as $motivo) {
        echo "✘ $motivo\n";
    }
    return;
}
printf("bloque %d · declarado %s · demostrable %s · testigos: %s\n",
    $r->blockIndex, $r->declaredTime, $r->provableTime, implode(', ', $r->cosigners));
```

`Verifier::verify` **no lanza nunca**: devuelve un `Result` con `reasons`. Un verificador
que lanza obliga a envolver cada llamada en un `try`, y basta un olvido para que un
recibo malo parezca bueno. La política se acepta como array, como texto JSON o como
objeto `Nucleo\Policy`; en los tres casos pasa por el parser estricto de
[PROTOCOL.md §3.2](../../docs/PROTOCOL.md).

Lo que el veredicto afirma, y lo que no, está en el propio recibo: prueba que el registro
estaba en el log y quién lo firmó; no prueba la entrega ni que el emisor no haya emitido
otro recibo del mismo registro para otra persona.

## Sellar desde un ERP

```php
$sealer = new Nucleo\Sealer(
    '/home/usuario/bin/nucleo',        // el binario, chmod 0700
    '/home/usuario/nucleo',            // el despliegue (el que lleva nucleo.db)
    '/home/usuario/.nucleo-pass',      // fichero de passphrase, chmod 0600
);

try {
    $r = $sealer->sealBytes($xml, 'ecuador.sri.factura.v1', '1790012345001', "factura-$numero");
    if ($r->idempotent) {
        // Ya estaba sellado: este es el bloque del sellado original y no se escribió nada.
    }
    guardarEnMiERP($r->index, $r->hash, $r->payloadHash);
} catch (Nucleo\SealUsageError $e) {      // código 1: bug del integrador
    throw $e;
} catch (Nucleo\SealIntegrityError $e) {  // código 2: incidente, escalar
    avisarAlAdministrador($e->getMessage());
} catch (Nucleo\SealSyncError $e) {       // código 3: reintentar luego
    encolarParaReintento();
} catch (Nucleo\SealEnvironmentError $e) { // el binario no llegó a ejecutarse
    // El arreglo no está en el código: está en el hosting. El mensaje dice qué pedir.
    throw $e;
}
```

**Pasa siempre `--idempotency-key`** (el cuarto argumento). Es lo que hace que un
reintento tras un timeout no duplique el registro, y un ERP que reintenta es exactamente
el caso que lo hace falta ([ADR-020](../../docs/adr/ADR-020-idempotencia-y-atomicidad-del-sellado.md)).
La clave está acotada por tenant, así que `factura-001` es de cualquiera.

### En hosting compartido

- El binario de Go es estático: se sube por FTP o por el gestor de ficheros, `chmod 0700`.
  No hay que compilar nada en el servidor.
- La passphrase va en un fichero en **modo 0600**. El sellador se niega a seguir si lo
  puede leer alguien más, y nunca la pasa por argumento —la lista de procesos la ve toda
  la máquina— ni por entorno, que en muchos paneles es legible.
- Si el proveedor tiene `proc_open` en `disable_functions`, o `/home` montado `noexec`,
  **no se puede sellar desde ahí** y el sellador lo dice con lo que hay que pedirle. No
  hay degradado silencioso: un sellador que sigue adelante sin sellar es lo peor que
  este producto puede hacer.

## La suite

```bash
php sdk/php/test/run.php
```

Corre contra los **mismos vectores compartidos** que Go y TypeScript
(`testdata/vectors/`): la hoja `leaf/v2`, Merkle de RFC 6962, canonicidad JCS, los 64
documentos de política y los 17 recibos. Sin PHPUnit, porque un paquete cuyo argumento es
"no necesitas instalar nada" no puede pedir composer para probarse.

El sellado de punta a punta se activa con `NUCLEO_BIN` apuntando al ejecutable:

```bash
NUCLEO_BIN=$(go build -o /tmp/nucleo ./cmd/nucleo && echo /tmp/nucleo) php sdk/php/test/run.php
```

Sin esa variable, la suite **avisa** de que esa parte no se comprobó en vez de callarse.

## El diferencial

PHP es el tercer verificador del diferencial desde el día uno (ADR-021 §F):

```bash
NUCLEO_DIFERENCIAL_OUT=/tmp/catalogo.json go test ./internal/receipt -run TestDiferencialGeneraCatalogo
cd sdk/ts && node scripts/diferencial.mjs /tmp/catalogo.json
```

Se busca `php` en el PATH, o en `$NUCLEO_PHP`, que puede llevar argumentos:

```bash
# WSL con el PHP de Windows, con sodium activado en la invocación
NUCLEO_PHP="/mnt/c/xampp/php/php.exe -d extension=php_sodium.dll" node scripts/diferencial.mjs /tmp/catalogo.json
```

Si no hay PHP, el diferencial lo dice y sigue con dos de tres. Lo que no hace es
callarse: una compuerta que no distingue "coinciden" de "no se comprobó" no es una
compuerta. Y con `NUCLEO_DIFERENCIAL_EXIGE_PHP=1` la ausencia deja de ser un aviso y
pasa a ser un fallo — es lo que pone el CI, donde el tercer verificador no es opcional.

## Lo que este SDK NO hace

Abrir un ledger, el vault, SLIP-0039, `sync`, el testigo: son del emisor, y el emisor
tiene la CLI. Y la firma ML-DSA-44 adicional del log (ADR-007) no se verifica —no hay
ML-DSA en PHP—, pero tampoco se cuenta como "clave desconocida": aparece en
`logAdditionalSignatures`, igual que en TypeScript.
