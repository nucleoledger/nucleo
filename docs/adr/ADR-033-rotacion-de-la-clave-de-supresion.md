# ADR-033-rotacion-de-la-clave-de-supresion

**Estado:** ACEPTADA el 2026-10-18 por el dev (Sprint 27), sin código; propuesta el 2026-10-17 (Sprint 26); las preguntas abiertas, respondidas en «Decisiones del dev (2026-10-18)» · **Fecha:** 2026-10-17 · **Fuentes:** ADR-032 (la autoridad de supresión) y su «Lo que NO resuelve», `docs/GARANTIAS.md` L21, ADR-017 (la política, raíz de confianza), ADR-018 (su formato de cable), ADR-030 (logs retirados en el testigo: retirar sin olvidar), ADR-028 (la alarma durable), PROTOCOL 0.7-draft §3.2 y §5.1, `internal/policy/policy.go`, `internal/estricto`, `sdk/ts/src/policy.ts`, `sdk/php/src/Policy.php`

## El problema

ADR-032 hizo que una supresión cuente solo si la autoriza la clave de supresión cuya parte
pública es `erasureKey` en la política. Una política tiene **una** `erasureKey`. Y la clave se
cambia por razones normales: se pierde el umbral de tarjetas, cambia el delegado de protección
de datos, o se sospecha que alguien vio dos tarjetas. ADR-032 §A lo dice: al cambiarla, las
supresiones ya hechas siguen contando para quien tenga la política vieja, y **dejan de contar
para quien solo tenga la nueva**. Es el límite L21.

Lo que eso significa en la práctica: el día que la custodia rota su clave, cada registro
suprimido legítimamente con la vieja pasa, en la siguiente reconciliación con la política
nueva, a «supresión no autorizada» y a `faltante`. La reconciliación sale con 2 por todo el
historial. Rotar la clave sería romper la reconciliación, y una clave que no se puede rotar
sin romper nada es una clave que no se rota.

Y hay que hacerlo sin deshacer lo que ADR-032 consiguió: si la clave vieja siguiera
autorizando para siempre, retirarla no serviría de nada, y precisamente se retira, a veces,
porque alguien pudo tenerla.

## Decisión

### A. En la política: `retiredErasureKeys`, un objeto clave → corte

Miembro nuevo y **opcional** (PROTOCOL 0.8-draft §3.2):

```json
{
  "origin": "nucleoledger.com/mi-empresa",
  "logKey": "…",
  "signerKey": "…",
  "erasureKey": "<clave B, la de ahora>",
  "retiredErasureKeys": {
    "<clave A, 64 hexadecimales en minúsculas>": 41
  },
  "witnesses": { "witness.ejemplo.ec/w1": "…" },
  "quorum": 1
}
```

| miembro | tipo | regla |
|---|---|---|
| `retiredErasureKeys` | objeto | OPCIONAL; **al menos un miembro**; cada nombre, exactamente 64 caracteres `[0-9a-f]` (una clave pública Ed25519); cada valor, un entero JSON `0\|[1-9][0-9]*` —sin signo, sin fracción, sin exponente— como mucho 2^53 − 1, el **corte** |

Y, como `erasureKey`, una regla de separación que no tiene ningún otro miembro:

- cada clave retirada **no puede ser igual** a `erasureKey`, a `logKey`, a `signerKey` ni a la
  clave de ningún testigo;
- al abrir un ledger con política, ninguna puede ser la clave que firma los bloques, que el
  parser no ve cuando la política no trae `signerKey` (es la regla de ADR-032 §B, aplicada a
  cada clave retirada).

Las reglas generales de §3.2 no cambian y cubren el resto: un nombre repetido —también tras
deshacer los escapes— es un error; `null` es un error; `retiredErasureKeys` con otra grafía
(`retirederasurekeys`, `RetiredErasureKeys`) es un error.

**Por qué un objeto y no el array `[{key, until}]` de la idea de partida.** El lector
estricto (`internal/estricto`, y sus gemelos de TypeScript y PHP) solo conoce cadenas,
enteros y objetos: rechaza arrays, booleanos y `null` en la política y en la configuración del
testigo (ADR-030 §A). Un array obligaría a ampliar tres lectores de un formato de cable para
un solo miembro, y con él vendrían preguntas que hoy no existen: ¿un array vacío?, ¿un
elemento con miembros de más?, ¿el orden importa? Con un objeto, **una clave que aparece dos
veces ya es un error de la gramática**, sin una regla nueva; es la forma de `witnesses`
(nombre → clave) y de `retired` en el testigo (origin → clave).

**Por qué no vacío.** `"retiredErasureKeys": {}` significaría lo mismo que no ponerlo. Dos
grafías del mismo documento es lo que ADR-018 prohíbe.

**`retiredErasureKeys` sin `erasureKey` vale** (pregunta abierta 2): es la política de quien
ya no suprime —o todavía no tiene clave nueva— y no quiere que lo suprimido deje de contar.
Ningún evento posterior a los cortes cuenta, que es justo lo que significa no tener clave.

### B. El corte es el índice del evento de supresión, incluido

Una clave retirada con corte `c` autoriza los eventos `nucleo.erasure.v1` cuyo **índice es
≤ c**, y ninguno más.

Se evaluaron cuatro cortes:

- **El índice del evento (elegido).** Los índices son de la cadena, que es append-only y la
  vigilan los testigos. Un evento con índice ≤ `c` o ya estaba sellado cuando se retiró la
  clave, o solo se puede añadir **reescribiendo la cadena por debajo de `c`**, y eso lo
  detecta la tercera capa de ADR-017 (el testigo responde 422 a otra raíz con la misma
  altura, y los recibos viejos dejan de casar). La condición es que el corte esté por debajo
  de lo ya atestiguado; §D dice cómo se elige.
- **El `through` de la autorización** (la autorización cuenta si `through ≤ c`). Descartado:
  `through` es lo que la autorización **cubre**, no cuándo se usó. Quien tenga la clave vieja
  podría autorizar hoy la supresión de un registro viejo —`through` pequeño—, sellar el
  evento al final de la cadena y que contara. Los registros viejos son justo los que hay;
  retirar la clave no protegería ninguno.
- **La hora.** La del bloque es tiempo declarado (ADR-002): la pone el servidor, y el servidor
  es el adversario de ADR-032. La demostrable sale de las cosignatures, que fechan
  checkpoints y no eventos, y no llega a la reconciliación bloque a bloque. Descartado.
- **Un checkpoint cosignado fijado en la política** («cuenta lo que esté bajo esta raíz»). Es
  el corte más fuerte: no depende de que nadie vuelva a mirar al testigo. Descartado por
  pesado —la política llevaría una nota firmada entera y la reconciliación tendría que
  probar la inclusión de cada evento en ella— cuando el índice, elegido por debajo de lo
  atestiguado, ya queda protegido por la misma memoria externa.

**Incluido**, como `through` en ADR-032: «hasta el índice 41» incluye el 41. El corte natural
es el índice del último evento que se reconoce como legítimo, y con un corte exclusivo habría
que escribir ese número más uno.

**Sin «desde».** Una clave retirada no lleva índice de inicio, y no lo necesita: una clave solo
puede haber autorizado eventos sellados después de existir, porque la autorización va dentro
del `payload_cid` del evento (ADR-032 §C) y nadie la mete en un bloque ya sellado. Un «desde»
no protegería nada que la cadena no proteja ya, y sería otro número que copiar mal.

### C. Qué clave vale para qué evento (la regla exacta de reconcile)

Con la política que se le pasa (`origin`, `erasureKey` opcional, `retiredErasureKeys`
opcional), un evento `E` de tipo `nucleo.erasure.v1` **está autorizado** si y solo si:

1. su `payload_cid` tiene la forma de ADR-032 §C, con `through < E.index`;
2. hay un bloque anterior a `E` cuyo `payload_hash` `h` cumple
   `E.payload_hash = SHA-256({"erased_payload_hash":"<h>"})`;
3. la firma verifica, sobre el texto de ADR-032 §C con el `origin` de la política, `h` y
   `through`, con **alguna** de estas claves:
   - `erasureKey`, sea cual sea `E.index`;
   - una clave `K` de `retiredErasureKeys` con `E.index ≤ retiredErasureKeys[K]`.

Los puntos 1 y 2 son los de ADR-032 §D sin cambios, y la regla de cuándo un bloque cuenta como
suprimido (`B.index ≤ through`) tampoco cambia.

Las consecuencias, una por una:

- **Una clave retirada no autoriza nada después de su corte.** Un evento con índice > `c`
  firmado con ella es un hallazgo de integridad —`"supresión no autorizada"`—, el bloque que
  decía suprimir sigue `faltante` y la reconciliación sale con 2. El `reason` lo dice con
  números: *«autorizada por la clave retirada …, cuyo corte es el índice 41; el evento es el
  57»*. Es lo que hace que retirar una clave sirva para algo, y lo que distingue este hallazgo
  del de una clave ajena.
- **La clave actual no tiene límite inferior**, por el argumento de «sin desde» (§B).
- **Varios cortes se solapan siempre, y está bien.** Todas las ventanas empiezan en el
  principio de la cadena; A hasta 41 y B hasta 120 quiere decir que un evento con índice 30
  puede ir firmado con A o con B. No hace falta que los cortes vayan en orden, ni que la
  clave retirada más tarde tenga el corte mayor: cada clave responde de su ventana.
- **La misma clave dos veces** no se puede escribir: es un nombre repetido (§A).
- **Una clave retirada igual a la actual** es un error de la política. ¿Está retirada o no?
  Las dos lecturas son posibles, y una política que se lee de dos maneras es lo que ADR-018
  prohíbe.
- **Sin `erasureKey` y sin `retiredErasureKeys`**, ningún evento está autorizado, como hoy.
- **Una política sin `retiredErasureKeys` significa exactamente lo que significa en
  0.7-draft.** Ningún veredicto cambia para quien no use el miembro.
- **Un corte por encima de lo atestiguado** no es un error de la política —la reconciliación
  no tiene por qué saber qué atestiguó el testigo—, pero deja una ventana: la clave retirada
  aún puede autorizar eventos que se sellen hasta ese índice. La reconciliación lo **avisa**
  por stderr, sin cambiar la salida, cuando el corte es mayor o igual que el último índice de
  la cadena: *«la clave retirada … todavía autoriza eventos hasta el índice …, y la cadena va
  por el …»*.

`reconcile --json` gana, en cada entrada de `erased`, qué clave la autorizó: la actual o una
retirada, con su corte (`docs/CLI-JSON.md`).

### D. Cómo se rota

En `docs/OPERACION.md` §3, con este orden:

1. La custodia genera la clave nueva B con `nucleo erasure-key init`, como la primera vez.
2. Se elige el **corte** de A: el índice del último evento autorizado con A que se reconoce
   como legítimo —está en `erased` de la última reconciliación— y que **ya está atestiguado**
   (`sync` antes, si hace falta). No el final de la cadena «por si acaso»: cada índice de más
   es ventana para quien pudiera tener A.
3. Política nueva: `erasureKey` B, `retiredErasureKeys` `{A: corte}`. Se distribuye como
   cualquier cambio de política: entera, por un medio autenticado (ADR-017).
4. Una autorización hecha con A y sin usar, después del corte, ya no vale: se repite con B.

`nucleo erasure-key authorize` rechaza unas tarjetas que reconstruyen una clave de
`retiredErasureKeys`, diciéndolo —*«esa clave está retirada desde el índice 41»*—, en vez del
error genérico de unas tarjetas que no son las de la política. Si la orden `rotate` de la
pregunta abierta 3 llega, hace los pasos 2 y 3.

**Si se sospecha que A se usó mal**, el corte se pone por debajo del primer evento sospechoso.
Esos eventos pasan a ser hallazgos —que es lo que se quiere—, y también los legítimos de
después, que habría que volver a autorizar con B (pregunta abierta 4).

### E. Un tercero, sin Núcleo

La receta de ADR-032 §E gana un paso antes de verificar la firma: con el índice del evento, se
elige la clave —`erasureKey`, o una clave retirada cuyo corte sea ≥ ese índice— y se verifica
con ella. Si hay varias candidatas, basta con que una verifique. Sigue siendo `sha256sum` y
`openssl`; `scripts/tercero-supresion.sh` gana el caso.

Los SDK leen el miembro y no lo usan para nada más, como `erasureKey`: verifican recibos, y un
recibo no depende de esto. Pero lo **parsean con la misma gramática**, porque una política que
el SDK acepta y la CLI rechaza —o al revés— es un formato de cable que se lee de dos maneras.

## Lo que NO resuelve

- **Una clave robada antes del corte.** Lo que el ladrón autorizó con A y se selló con índice
  ≤ `c` cuenta, y no se distingue de lo legítimo: las dos cosas son una firma válida de A. Lo
  que lo hace visible es lo de ADR-032: cada evento abre su alarma (ADR-028), sale en
  `erased` de cada reconciliación y se atestigua en el siguiente `sync`. Si se detecta a
  tiempo, el corte se pone por debajo (§D), a costa de las supresiones legítimas de después.
- **La política tiene que llegar por un medio autenticado** (ADR-017), y esto lo empeora un
  poco: quien pueda cambiar la política de quien reconcilia puede, además de poner su propia
  `erasureKey`, subir el corte de una clave retirada. Es el mismo límite de L21, con un miembro
  más que vigilar en el diff.
- **Las políticas viejas.** Quien siga con una política donde A es `erasureKey` sigue contando
  lo que A autorice después del corte. Retirar es una decisión de quien escribe la política, y
  solo protege a quien recibe la nueva.
- **La custodia de B sigue siendo de personas.** Si las tarjetas de B acaban en las mismas
  manos que el servidor, rotar no separó nada (ADR-032, «Lo que NO resuelve»).

## Alternativas descartadas

- **Varias claves sin corte**, todas válidas para siempre. Retirar no impediría nada a quien
  tenga la vieja.
- **El array `[{key, until}]`.** §A.
- **Cortar por `through`, por la hora o por un checkpoint fijado.** §B.
- **Un bloque de rotación en la cadena**, firmado por la clave vieja, que nombre la nueva. La
  cadena la escribe el servidor y la raíz de confianza es la política (ADR-017); con A robada,
  el ladrón firma la rotación a su clave. Y exigiría que la custodia firmara algo que depende
  del estado de la cadena en el momento de sellar, que es lo que ADR-032 §C evitó.
- **Volver a autorizar con la clave nueva todo el historial.** La autorización va en el
  `payload_cid` de eventos ya sellados, que no se tocan; habría que sellar un evento nuevo por
  cada supresión vieja, con B firmando lo que decidió A. Es la pregunta abierta 4 como
  excepción, no como regla de rotación.
- **No hacer nada y documentar L21.** Es lo que hay. La consecuencia es que nadie rota.

## Consecuencias

- PROTOCOL 0.8-draft: §3.2 gana `retiredErasureKeys` y su regla de separación; §5.1, la
  condición 3 de §C y el paso de la receta del tercero (§E).
- `internal/policy` y sus gemelos de TS y PHP leen el miembro; `internal/estricto` no cambia.
- `internal/erasure` y `internal/reconcile`: la regla de §C, el `reason` de una clave retirada
  usada después de su corte, el aviso de un corte por encima de la cadena.
- `erasure-key authorize` rechaza una clave retirada; `reconcile --json` dice la clave en
  `erased`.
- GARANTIAS: L21 se reescribe —rotar ya no tira el historial si la política lista la clave
  vieja— y se añade el límite nuevo: lo autorizado con una clave robada antes del corte.

## Los tests y los vectores que la fijarían

Calculados fuera del código, como en ADR-032: la gramática, a mano desde la tabla de §A; las
firmas, con la biblioteca `cryptography` de Python (la 3.4.8 de esta máquina tiene Ed25519) y
comprobadas con OpenSSL 3.

- **`testdata/vectors/policy/`**, desde `generar.py`:
  - válidas: con una clave retirada; con dos; sin `erasureKey`; corte `0`; corte
    `9007199254740991` (2^53 − 1);
  - inválidas: `{}`; nombre de 63 y de 65 caracteres; nombre en mayúsculas; nombre no
    hexadecimal; corte negativo, con fracción, con exponente, con cero a la izquierda, como
    cadena, `null`, `9007199254740992`; clave retirada igual a `erasureKey`, a `logKey`, a
    `signerKey`, a un testigo; la misma clave dos veces, también por un escape; el miembro con
    otra grafía; **el array `[{key, until}]`**, para que la forma descartada quede rechazada
    por escrito.
- **`testdata/vectors/erasure/`**, con `cryptography`: una segunda clave —semilla
  `202122…3f`, los 32 bytes 0x20 a 0x3f— y su autorización sobre el mismo texto del vector de
  PROTOCOL §5.1; y `rotacion.json`, un escenario con la política `{erasureKey: B,
  retiredErasureKeys: {A: 41}}` y el veredicto de cada evento escrito a mano desde §C:

  | evento | firmado con | veredicto |
  |---|---|---|
  | índice 40 | A | autorizado |
  | índice 41 | A | autorizado (el borde) |
  | índice 42 | A | no autorizado: después del corte |
  | índice 20 | B | autorizado (sin «desde») |
  | índice 42 | B | autorizado |
  | índice 42 | C, ni actual ni retirada | no autorizado: otra clave |

- **Go** (`internal/reconcile`): el escenario de `rotacion.json` construido como cadena;
  `TestClaveRetiradaDespuesDelCorteNoCuenta`, que sella el evento con las piezas internas sin
  pasar por `erase` —es la prueba de que retirar sirve— y que tiene que fallar si se quita la
  comprobación del corte; la regresión de ADR-032 sin el miembro; la clave retirada igual a la
  del firmante, al abrir.
- **TS y PHP**: los mismos vectores de política, aceptados y rechazados igual.
- **El diferencial de políticas** muta el miembro nuevo como a los demás.
- **`scripts/tercero-supresion.sh`**: la supresión autorizada con la clave retirada.

## Decisiones del dev (2026-10-18)

El dev acepta el ADR y cierra las preguntas abiertas 1 a 4 y la 10 (las 5 a 9 son de
ADR-034 y se responden allí). Donde una decisión precisa o cambia el texto de arriba, manda
esta sección.

**1. La forma: un objeto clave → corte.** `retiredErasureKeys` es `{ "<clave>": corte }`, como
en §A. El array `[{key, until}]` queda descartado y fijado como inválido en los vectores de
política.

**2. Sin `erasureKey`, vale.** Una política con `retiredErasureKeys` y sin `erasureKey` es
válida, con el significado de §A: lo suprimido hasta cada corte sigue contando y ningún
evento posterior cuenta.

**3. Sin `erasure-key rotate` en la 0.5; el fragmento lo imprime `nucleo sync`.** La política
nueva se escribe a mano con la receta de §D, pero nadie calcula el corte a ojo:
**`nucleo sync --policy-file F`**, cuando `F` trae `erasureKey` y la atestación del testigo
verificó, imprime después de la política (ADR-017 §c) el fragmento exacto que la política
nueva tiene que llevar si se rota la clave de supresión:

```
Si rotas la clave de supresión, la política nueva lleva, además de la erasureKey nueva:
  "retiredErasureKeys": {"<erasureKey de F>": 41}
```

- **El corte** es el mayor índice de un evento `nucleo.erasure.v1` autorizado (§C) con la
  `erasureKey` de `F` **dentro del checkpoint que ese mismo `sync` acaba de atestiguar**
  (índice < tamaño atestiguado). Por construcción, nunca queda por encima de lo atestiguado,
  que es la condición de §B y §D.
- **Las claves que `F` ya retiraba** van en el fragmento con sus cortes de siempre: la
  política nueva las tiene que seguir listando, y un fragmento que las olvidara haría que
  sus supresiones dejaran de contar al pegarlo.
- **Sin ningún evento autorizado con esa clave** dentro de lo atestiguado, no hay fragmento
  que pegar, y lo dice: *«ninguna supresión autorizada con la clave actual está atestiguada:
  al rotarla no hace falta retiredErasureKeys para ella»*. Si `F` ya retiraba otras, imprime
  esas.
- **Con `--json`**, el mismo dato en el miembro `erasure_rotation` (`docs/CLI-JSON.md`):
  `{"retiredErasureKeys": {…}, "attested_size": N}`, o `null` cuando la política no trae
  `erasureKey` o la atestación no verificó.
- **Por qué `sync` y no `erasure-key init`.** `init` es la orden de la custodia: no abre el
  ledger y no puede saber qué se suprimió ni qué está atestiguado. `sync` es la orden que ya
  imprime la política, y la única que sabe, en ese momento, hasta dónde llega lo atestiguado.
  Sin `--policy-file` (con banderas sueltas), `sync` no conoce ninguna `erasureKey` y no
  imprime nada de esto. El fragmento se puede pegar tal cual en el JSON de la política, que
  es lo que exige la regla de los mensajes.

§D, paso 2, queda así: *el corte se copia del fragmento que imprime `sync`*. Si se sospecha
que la clave se usó mal, se sigue bajando a mano por debajo del primer evento sospechoso.

**4. Se puede regularizar con la clave nueva, y el original no desaparece.** Nota sobre la
pregunta: `erase` **ya** sella ese segundo evento —cuando el contenido ya no está y solo hay
eventos sin autorización válida (`cmd/nucleo/erase.go#hayEventoSinAutorizar`)—; lo que no
existía es la manera de contarlo en `reconcile`, que hoy sigue informando el original como
hallazgo y sale con 2 para siempre. La regla exacta:

> Sea `E` un evento `nucleo.erasure.v1` **no autorizado** (§C) que cumple el punto 2 de §C
> —suprime un contenido `h` sellado antes que él—. `E` queda **regularizado por** el evento
> `R` si y solo si:
>
> 1. `R` está autorizado (§C), con cualquiera de las claves que valen para **su** índice;
> 2. `R.index > E.index`;
> 3. `R` suprime el mismo contenido: `R.payload_hash = E.payload_hash`;
> 4. el `through` de `R` cubre todo bloque con contenido `h` anterior a `E`:
>    `through(R) ≥ max{ B.index : B.payload_hash = h, B.index < E.index }`.
>
> Si hay varios `R`, se nombra el de menor índice.

- El punto 4 no usa el `through` de `E`: viene de una autorización que no vale y no se le
  cree. `R` tiene que cubrir todo lo que `E` pudo pretender suprimir.
- **Un `R` anterior a `E` no lo regulariza.** Un evento sin autorización sellado después de
  una supresión legítima sigue siendo el servidor sellando lo que nadie autorizó.
- **Un `E` que no cumple el punto 2** —no suprime ningún contenido anterior— no se regulariza:
  no hay supresión que regularizar, y sigue siendo hallazgo.
- **El original no desaparece.** `E` sale de `findings` y entra en una lista nueva,
  `regularized`, que va **siempre** en `reconcile --json` (`[]` si no hay ninguna, como
  `findings` y `erased`; ADR-025): `{index, sealed_hash, sealed_at, regularized_by, reason}`,
  donde `reason` es por qué `E` no estaba autorizado. En texto, una línea por evento, en cada
  reconciliación y para siempre: *«⚠ supresión no autorizada en el evento 42, regularizada en
  el evento 57 (autorizada por la clave retirada …, cuyo corte es el índice 41; el evento es
  el 42)»*. Los bloques que `R` cubre van en `erased` con `erased_by` = el primer evento
  autorizado que los cubre, como hoy.
- **El código de salida.** Un evento regularizado **no** cuenta como hallazgo: si no hay
  otro, `reconcile` sale con **0**, con el aviso. La razón: regularizar exige una firma de
  quien custodia la clave de supresión, que es justo la parte que el servidor no tiene
  (ADR-032); quien suprimió sin autorización no puede regularizarse solo. El aviso es
  permanente porque el hecho lo es: `E` está en la cadena, atestiguado, y quien audite tiene
  que verlo aunque la salida sea 0.
- La alarma durable del evento (ADR-028) no cambia: se abre con cada evento de supresión,
  autorizado o no, y se cierra como hoy.

**Su test**, en el mismo sprint que la regla (Go, `internal/reconcile`):

- `TestSupresionNoAutorizadaRegularizada`: cadena con el contenido `X` en el bloque 0, el
  evento `E` en el 2 —firmado con una clave que la política no lista, sellado con las piezas
  internas, sin pasar por `erase`— y `R` en el 3, autorizado con la `erasureKey` y `through`
  0. Esperado: `findings` vacío, `erased` = `[{index 0, erased_by 3}]`, `regularized` =
  `[{index 2, regularized_by 3}]`.
- Y los cuatro casos que **no** regularizan, cada uno con `E` en `findings`: `R` anterior a
  `E`; `R` con un `through` que no cubre una segunda copia de `X` sellada entre `R.through` y
  `E`; `R` tampoco autorizado; `E` que no suprime ningún contenido anterior.
- Tiene que fallar si se quita la condición 2 o la 4 (se demuestra al escribirlo, como el
  test del corte).
- En la CLI (`cmd/nucleo`): la misma cadena sale con 0, el texto dice «regularizada en el
  evento 3» y el JSON trae la entrada en `regularized`; sin `R`, sale con 2.
- En `testdata/vectors/erasure/rotacion.json`, dos filas más, escritas a mano desde esta
  regla: el evento 42 firmado con A (después del corte) y un evento 50 autorizado con B para
  el mismo contenido → *«no autorizado, regularizado en el evento 50»*; y el mismo con el
  evento autorizado en el 30 → *«no autorizado»* (anterior, no regulariza).

**10. La 0.5 sale con los dos ADR implementados.** Ni el SDK ni el binario 0.5 se publican
con un miembro aceptado en la gramática que nadie use.

## Plan conjunto con ADR-033 y ADR-034 (el mismo texto en los dos)

Los dos ADR tocan lo mismo —la gramática de la política, PROTOCOL §3.2— y se proponen a la vez
para que **la política suba una sola vez**. Una contraparte que actualiza su verificador lo
hace una vez para los dos miembros, no dos veces en dos meses.

### Una sola subida

- **PROTOCOL 0.8-draft**, con los dos miembros nuevos y opcionales de la política:
  `retiredErasureKeys` (ADR-033) y `logMLDSAKey` (ADR-034). §3.2 gana sus filas y sus reglas;
  §3.3, la regla de la línea ML-DSA cuando la política fija la clave; §5.1, las claves
  retiradas en «When an event is authorized» y en la receta del tercero. Ningún artefacto
  cambia de bytes: ni el bloque, ni la hoja, ni el checkpoint, ni el recibo.
- **Una sola versión del SDK, `0.5.0-alpha.0`**: `@nucleoledger/verify` y el SDK de PHP, los
  dos con los dos miembros. No hay una 0.5 con uno solo.

### La compatibilidad

| política | SDK 0.4 / binario v0.4.0-alpha | SDK 0.5 / binario v0.5 |
|---|---|---|
| sin los miembros nuevos (toda política de hoy) | vale, como hoy | vale, y significa lo mismo |
| con `retiredErasureKeys` o `logMLDSAKey` | **se rechaza**: miembro desconocido (§3.2) | vale |

Es exactamente lo que pasó con `erasureKey` en la 0.4 (PROTOCOL 0.7-draft): un verificador
viejo rechaza un miembro que no sabría usar, y eso es lo correcto. Rechazar es lo seguro: un
verificador 0.4 que aceptara `logMLDSAKey` sin saber qué es daría a entender que la comprobó.

Los recibos no cambian, así que todo recibo emitido por v0.4.0-alpha verifica bajo 0.8-draft
con una política vieja; con una política que fija `logMLDSAKey`, verifica si su checkpoint
trae la línea ML-DSA de esa clave, que es lo que firma `checkpoint.Log` en todo checkpoint
desde el addendum de ADR-007 (lo comprueba el ensayo, abajo).

### El orden de implementación

1. El dev acepta, enmienda o rechaza ADR-033 y ADR-034, y cierra las preguntas de abajo.
2. PROTOCOL 0.8-draft, con la nota de cabecera de cada subida (qué acepta de más, qué no
   cambia), por instrucción del dev.
3. **Los vectores, antes que el código** (regla criptográfica): `testdata/vectors/policy/`
   desde `generar.py`, escrito a mano a partir de las tablas; `testdata/vectors/erasure/`, la
   segunda clave y el escenario de rotación, con la biblioteca `cryptography` de Python;
   `testdata/vectors/mldsa/` y los recibos ML-DSA, con la implementación independiente que
   apruebe el dev (ADR-034, «Los vectores»). Cambiar `testdata/vectors/` exige este ADR.
4. **Go**: `internal/policy` (los dos miembros; `internal/estricto` no cambia, porque ninguno
   trae un tipo JSON nuevo), `internal/erasure` y `internal/reconcile` (las claves retiradas),
   `internal/proof` (la ML-DSA con `crypto/mldsa` y el campo de tres estados) y la CLI
   (`sync` imprime `logMLDSAKey` en la política y el fragmento de `retiredErasureKeys`; la
   apertura la coteja; `erasure-key authorize` rechaza una clave retirada; `reconcile
   --json` dice qué clave autorizó cada supresión y lista las regularizadas; y la orden
   nueva `nucleo verify-receipt`, que verifica un recibo ajeno con una política —ADR-034,
   decisión 8—).
5. **TypeScript y PHP**: el parser contra los mismos vectores, el campo de tres estados en el
   resultado y su texto; la página de `web/verify/` con él.
6. **El diferencial**: el catálogo de políticas muta los dos miembros nuevos; el de notas
   re-firmadas muta la línea ML-DSA, con la divergencia declarada si se elige la opción B de
   ADR-034.
7. **La documentación**: GARANTIAS (L14, L21, L23 y las garantías nuevas, con su test),
   `docs/OPERACION.md` §3 (cómo se rota la clave de supresión), `docs/CLI-JSON.md`, README.
8. `./scripts/compuerta.sh` en verde, un commit por paso.

### El orden de publicación

Como manda RELEASING: **primero el SDK** —tag `vsdk-0.5.0-alpha.0`, npm—, **después el
binario** `v0.5.0-alpha`. La razón es la de siempre y aquí pesa más: el `sync` del binario
nuevo imprime políticas con `logMLDSAKey`, y la contraparte que la reciba tiene que poder
leerla el día que el binario se publica, no después.

### El ensayo de actualización desde v0.4.0-alpha

`./scripts/ensayo-actualizacion.sh v0.4.0-alpha` con `NUCLEO_ENSAYO_SDK=0.4.0-alpha.0`, que
gana estos pasos:

1. Con el binario **publicado** de v0.4.0-alpha: ledger, testigo, una política con
   `erasureKey` A, un recibo, y una supresión autorizada con A. Todo esto ya lo hace hoy.
2. Con el HEAD, la misma política vieja: abre, sella, sincroniza y reconcilia igual.
3. Con el HEAD, la política nueva: `erasureKey` B, `retiredErasureKeys` `{A: índice del
   evento del paso 1}` y `logMLDSAKey` copiada de lo que imprime `sync`. La supresión del
   paso 1 **sigue contando** (es el cambio de L21); una supresión nueva con B cuenta;
   `erasure-key authorize` con las tarjetas de A y la política nueva se rechaza.
4. El recibo emitido por v0.4.0-alpha, con la política nueva: el verificador de Go
   —`nucleo verify-receipt` del HEAD— dice «ML-DSA verificada»; el SDK 0.5 del HEAD y el de npm lo aceptan y dicen lo que su opción
   de ADR-034 obliga a decir; el SDK 0.4 de npm **rechaza** la política nueva (miembro
   desconocido) y sigue aceptando la vieja.
5. `scripts/tercero-supresion.sh` con la clave retirada: el tercero elige la clave por el
   índice del evento y la comprueba con `openssl`.

Que una clave retirada no autorice nada después de su corte no entra en el ensayo: para
probarlo hay que sellar un evento sin pasar por `erase`, y eso es un test de Go
(ADR-033, «Los tests y los vectores»).

### Preguntas abiertas para el dev (respondidas el 2026-10-18)

Cada pregunta lleva debajo la respuesta del dev; el detalle está en la sección «Decisiones
del dev (2026-10-18)» del ADR al que pertenece.

1. **ADR-033, la forma.** ¿`retiredErasureKeys` como objeto `{clave: corte}` —recomendado: no
   añade arrays al lector estricto y una clave repetida ya es un error de la gramática— o
   como el array `[{key, until}]` de la idea de partida?
   **Respuesta:** objeto clave → corte.
2. **ADR-033, sin clave actual.** ¿Vale una política con `retiredErasureKeys` y sin
   `erasureKey` —«ya no suprimo, pero lo suprimido sigue contando»—? Se recomienda que sí.
   **Respuesta:** sí, vale.
3. **ADR-033, la herramienta.** ¿Un `nucleo erasure-key rotate --policy-file` que escriba la
   política nueva con el corte calculado desde el último checkpoint atestiguado, o se edita
   a mano con la receta de OPERACION? Se recomienda editarla a mano en la 0.5 y la orden
   cuando alguien rote de verdad.
   **Respuesta:** a mano en la 0.5, sin `rotate`; pero `nucleo sync --policy-file` imprime el
   fragmento exacto de `retiredErasureKeys`, con el corte calculado dentro de lo que ese
   `sync` acaba de atestiguar (ADR-033, decisión 3).
4. **ADR-033, volver a autorizar.** Si se pone el corte por debajo de un evento sospechoso,
   las supresiones legítimas de después dejan de contar. ¿Se permite sellar un segundo
   evento, autorizado con la clave nueva, para un bloque ya suprimido? El protocolo ya lo
   admite (§5.1 no prohíbe dos eventos para el mismo contenido); `erase` hoy no lo hace.
   **Respuesta:** sí. El original no desaparece: `reconcile` lo informa como «no autorizada,
   regularizada en el evento N» y sale con 0, con un aviso permanente en el texto y en el
   JSON (`regularized`). Corrección: `erase` ya sella ese segundo evento; lo nuevo es cómo lo
   cuenta `reconcile` (ADR-033, decisión 4, con la regla exacta y su test).
5. **ADR-034, TypeScript y PHP.** Opción A (verificar de verdad, implementación propia),
   B (aceptar la clave y decir «presente sin verificar»; recomendada para la 0.5) o C (solo
   Go).
   **Respuesta:** B. TS y PHP dan `"present-unverified"`; la divergencia con Go se declara
   en el diferencial; README y GARANTIAS dicen que la comprobación post-cuántica solo la
   hace el verificador de Go (ADR-034, decisión 5).
6. **ADR-034, el nombre y la codificación.** `logMLDSAKey` en hexadecimal en minúsculas, 2624
   caracteres, como el resto de las claves de la política. ¿O otro nombre?
   **Respuesta:** `logMLDSAKey`, hexadecimal en minúsculas, 2624 caracteres.
7. **ADR-034, la implementación independiente para los vectores.** ¿Se aprueba OpenSSL ≥ 3.5
   como herramienta de desarrollo —no como dependencia del producto—, instalada con su
   checksum como las del ritual, junto con los vectores sigVer del ACVP del NIST? Con eso
   ADR-024 se revisa y `material/mldsa.json` desaparece.
   **Respuesta:** aprobado, versión fijada con su checksum, solo para generar vectores, junto
   con los sigVer del ACVP (ADR-034, decisión 7).
8. **ADR-034, quién verifica fuera.** La única verificación de recibos en Go es la que la CLI
   hace de los suyos (TODO, «Verificar recibos ajenos desde la CLI»). Con la opción B, una
   contraparte no tiene dónde comprobar la ML-DSA. ¿Entra en la 0.5 una orden para verificar
   un recibo ajeno, o la 0.5 cierra L23 solo para el emisor?
   **Respuesta:** entra `nucleo verify-receipt` (ADR-034, decisión 8).
9. **ADR-034, el `sync`.** ¿La política que imprime `sync` lleva `logMLDSAKey` siempre? Se
   recomienda que sí desde v0.5: es la política completa del log, y una contraparte con el
   SDK 0.4 tiene que actualizar de todos modos para leer una política 0.8-draft.
   **Respuesta:** sí, siempre.
10. **Los dos.** ¿Se publica la 0.5 cuando estén los dos ADR implementados, o vale publicar el
    SDK 0.5 con los dos miembros aceptados en la gramática aunque la CLI implemente uno
    después? Se recomienda lo primero: una gramática que acepta un miembro que nadie usa es
    la promesa vacía que la enmienda de ADR-030 quitó.
    **Respuesta:** la 0.5 se publica solo con los dos ADR implementados.
