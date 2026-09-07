# @nucleoledger/verify

Verificador **offline** de recibos de Núcleo. Comprueba que un registro estaba en
el log en un momento dado, sin pedirle nada a quien lo emitió.

**Cero dependencias de runtime.** Ed25519 y SHA-256 salen de WebCrypto
(`SubtleCrypto`), que es parte de la plataforma. Lo único que hace falta es un
entorno que soporte Ed25519 en WebCrypto: Node ≥ 18.4, Chrome ≥ 137, Safari ≥ 17,
Firefox ≥ 130.

```ts
import { verifyReceipt } from "@nucleoledger/verify";

const result = await verifyReceipt(textoDelRecibo, {
  origin: "nucleoledger.com/mi-empresa",
  logKey: "5e42…",                       // hex
  witnesses: { "witness.example/w1": "1e98…" },
  quorum: 1,
});

result.valid;         // true | false
result.declaredTime;  // lo que dijo el emisor. Puede mentir.
result.provableTime;  // lo que atestiguó un testigo. Es lo que prueba algo.
result.blockIndex;
result.reasons;       // por qué falla, si falla
```

## Los dos relojes

`declaredTime` sale del reloj del emisor y **no prueba nada**: quien selló el
registro controla ese reloj. `provableTime` es el menor de los timestamps de las
cosignatures que verifican **con las claves de tu política**. Si no hay ninguna,
es `null`, y eso significa exactamente lo que parece: el recibo demuestra que el
registro está en el log, no cuándo existía.

## Firmas que no se entienden

Una nota firmada puede llevar firmas de claves que este verificador no conoce
—ML-DSA-44 del log, cosignatures de otros testigos—. **Se ignoran**, como manda
`c2sp.org/signed-note`. Ignorarlas es lo que permite que un mismo recibo circule
entre partes que confían en testigos distintos; rechazarlo por traer una firma
ajena rompería esa propiedad.

Lo que NO se ignora es una firma cuya clave sí se conoce y no verifica: eso
invalida el recibo entero.
