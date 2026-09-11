// Regenera web/verify/ejemplo.js desde el vector golden.
//
// Este fichero existe porque el ejemplo embebido en la página se quedó viejo dos
// veces: es una copia de un vector, y una copia que alguien tiene que acordarse
// de actualizar se queda vieja. Ahora se genera, y se genera dentro de
// `npm run bundle`, junto al otro artefacto derivado que sirve la página.
import { readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const raiz = join(here, "..", "..", "..");
const vector = JSON.parse(
  readFileSync(join(raiz, "testdata", "vectors", "receipt", "valido-1-cosignature.json"), "utf8"),
);

const salida =
  `// Recibo de ejemplo, COPIADO de testdata/vectors/receipt/valido-1-cosignature.json.
// Está aquí para que la página se pueda probar sin un despliegue delante.
// No es un recibo real de nadie: sus claves son de prueba.
//
// GENERADO por sdk/ts/scripts/ejemplo.mjs dentro de \`npm run bundle\`. No se
// edita a mano: si el formato del recibo cambia, el vector cambia y este fichero
// se regenera. Que estuviera viejo lo detecta sdk/ts/test/bundle.test.ts.
window.NUCLEO_EJEMPLO = ` +
  JSON.stringify(
    {
      receipt: vector.receipt,
      policy: {
        origin: vector.policy.origin,
        logKey: vector.policy.log_key,
        witnesses: vector.policy.witnesses,
        quorum: vector.policy.quorum,
      },
    },
    null,
    2,
  ) +
  ";\n";

const destino = join(raiz, "web", "verify", "ejemplo.js");
writeFileSync(destino, salida);
console.log(`ejemplo.js regenerado desde el vector (${salida.length} bytes)`);
