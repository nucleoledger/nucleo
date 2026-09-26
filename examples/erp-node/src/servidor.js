// El servidor del ERP de ejemplo. node:http y nada más.
//
// Cada ruta hace UNA cosa de las cinco que este ejemplo tiene que demostrar, y las
// cinco terminan enseñando el comando que ejecutaron:
//
//   POST /facturas              sella la factura al emitirla, con clave de idempotencia
//   POST /factura/:n/recibo     emite el recibo del cliente y lo muestra
//   POST /verificar             verifica un recibo pegado, con @nucleoledger/verify
//   POST /reconciliar           coteja el sistema vivo contra lo sellado
//   POST /estado/sync           pide atestación al testigo
//
// El manejo de errores no está al final: está en `responde`, y es la mitad del ejemplo.
// Un ERP que sella y no sabe qué hacer cuando el sellado falla no es una integración,
// es una demo.

import { createServer } from "node:http";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { verifyReceipt, parsePolicyText } from "@nucleoledger/verify";
import * as cfg from "./config.js";
import { ERP, TENANT, TIPO } from "./erp.js";
import {
  ErrorDeContrato,
  ErrorDeEntorno,
  ErrorDeIntegridad,
  ErrorDeNucleo,
  ErrorDeSincronizacion,
  ErrorDeUso,
} from "./nucleo.js";
import { comando, esc, marca, pagina, paginaDeError, pares } from "./paginas.js";

const DIR_RECIBOS = join(cfg.DATOS, "recibos");

const nucleo = cfg.nucleo();
const erp = new ERP({
  fichero: cfg.FICHERO_FACTURAS,
  nucleo,
  dirDocumentos: cfg.DIR_DOCUMENTOS,
});

// ————— las páginas —————

/**
 * bloqueDeAlarma pinta la alarma de frescura (ADR-028), o nada si no hay.
 *
 * Sale del objeto `alert` que trae `status`: la alarma vive en el ledger, así que la ve
 * cualquiera que abra la pantalla, sin haber leído nunca stderr.
 */
function bloqueDeAlarma(alerta, { conBoton = false } = {}) {
  if (!alerta || alerta.state === "none") return "";
  const abierta = alerta.state === "open";
  return `<div class="tarjeta ${abierta ? "grave" : "aviso"}">
  <h2 style="margin-top:0">${abierta ? "✘ Alarma de frescura: nadie la ha reconocido" : "◐ Alarma de frescura reconocida"}</h2>
  <p>La atestación está vieja desde <code>${esc(alerta.stale_since)}</code>: desde entonces,
  lo que se sella aquí no lo ha visto ningún testigo. <strong>Se sigue sellando</strong>
  —un registro que no se sella se pierde—, y la alarma se cierra sola con el próximo
  <code>sync</code> que salga bien.</p>
  ${abierta ? "" : `<p class="nota">Reconocida${alerta.acked_by ? " por " + esc(alerta.acked_by) : ""} el ${esc(alerta.alert_acked_at)}.</p>`}
  ${abierta && conBoton ? `<form method="post" action="/estado/ack">
    <button type="submit" class="suave">Me he enterado (alert ack)</button>
  </form>` : ""}
  ${comando(nucleo.comando(["alert", abierta ? "ack" : "status"]))}
</div>`;
}

async function panel() {
  const est = await nucleo.estado();
  const facturas = erp.facturas();
  const filas = facturas
    .slice()
    .reverse()
    .map(
      (f) => `<tr>
  <td><a href="/factura/${esc(f.numero)}">${esc(f.numero)}</a></td>
  <td>${esc(f.cliente)}</td>
  <td class="num">${esc(f.total)}</td>
  <td>${f.nucleo ? `bloque ${f.nucleo.bloque}` : '<span class="mal">sin sellar</span>'}</td>
  <td>${f.alterada ? '<span class="mal">alterada en el ERP</span>' : '<span class="ok">intacta</span>'}</td>
</tr>`,
    )
    .join("");

  const cuerpo = `
${bloqueDeAlarma(est.alerta)}
<div class="tarjeta">
  ${pares([
    ["Ledger", `<code>${esc(est.origin)}</code>`],
    ["Bloques sellados", String(est.treeSize)],
    ["Atestación", marca(est.attested, "verificada por un testigo", "sin atestación verificada")],
    ["Cabeza atestiguada", marca(est.attestedHead, "el último bloque está cubierto", `cubiertos ${est.attestedSize} de ${est.treeSize}`)],
    ["Firmante", marca(est.signer.verified, "verificado contra la política", "NO verificado contra ninguna política")],
    ["Frescura", est.freshness.stale ? '<span class="medio">◐ la última atestación es vieja</span>' : '<span class="ok">✔ reciente</span>'],
  ])}
  <p class="nota">Esto sale de <code>nucleo status --json</code>, leído campo por campo. Los
  tres estados de la atestación son los de ADR-016: nadie afirma más de lo que puede.</p>
  ${comando(nucleo.comando(["status"]))}
</div>

<h2>Facturas emitidas</h2>
<div class="tarjeta">
${facturas.length === 0 ? "<p class=\"nota\">Todavía no hay ninguna. Emite la primera abajo.</p>" : `<table>
<tr><th>Número</th><th>Cliente</th><th class="num">Total</th><th>En el ledger</th><th>En el ERP</th></tr>
${filas}</table>`}
</div>

<h2>Emitir una factura</h2>
<div class="tarjeta">
  <form method="post" action="/facturas">
    <div class="fila">
      <div><label for="cliente">Cliente</label><input id="cliente" name="cliente" required value="Constructora del Litoral S.A."></div>
      <div><label for="ruc">RUC del cliente</label><input id="ruc" name="ruc" required value="0992345678001"></div>
    </div>
    <div class="fila">
      <div><label for="concepto">Concepto</label><input id="concepto" name="concepto" required value="Hormigón premezclado f'c=210"></div>
      <div><label for="cantidad">Cantidad</label><input id="cantidad" name="cantidad" type="number" min="1" step="1" required value="12"></div>
      <div><label for="precio">Precio unitario (USD)</label><input id="precio" name="precio" type="number" min="0" step="0.01" required value="86.50"></div>
    </div>
    <button type="submit">Emitir y sellar</button>
  </form>
  <p class="nota">Al emitir, el ERP escribe el documento canónico de la factura y ejecuta
  <code>nucleo seal</code> con <code>--idempotency-key factura-NNNNNN</code>. La clave es
  el número de factura, no un UUID nuevo: si el reintento no repite la clave, duplica el
  registro (ADR-020 §D).</p>
</div>`;
  return pagina({ titulo: "Facturas", ruta: "/", cuerpo });
}

function detalleDeFactura(numero, { recibo = null, aviso = "" } = {}) {
  const f = erp.factura(numero);
  if (!f) return null;
  const n = f.nucleo;
  const cuerpo = `
${aviso}
<h2>Factura ${esc(f.numero)}</h2>
<div class="tarjeta">
  ${pares([
    ["Cliente", esc(f.cliente)],
    ["RUC", `<code>${esc(f.ruc)}</code>`],
    ["Fecha", esc(f.fecha)],
    ["Total", `USD ${esc(f.total)}`],
    ["Estado en el ERP", f.estado === "emitida" ? '<span class="ok">emitida</span>' : '<span class="medio">pendiente de sellar</span>'],
    f.alterada ? ["Ojo", '<span class="mal">este registro se modificó DESPUÉS de sellarse</span>'] : null,
  ])}
  <h2>El documento que se sella</h2>
  <pre>${esc(erp.documento(f))}</pre>
  <p class="nota">El campo <code>nonce</code> son dieciséis bytes aleatorios y no es
  decoración: el <code>payload_hash</code> viaja en el recibo, y una factura sin entropía
  dentro es adivinable por enumeración (ADR-023 §C).</p>
</div>

<h2>El sellado</h2>
<div class="tarjeta">
${
  n
    ? pares([
        ["Bloque", String(n.bloque)],
        ["Hash del bloque", `<code>${esc(n.hashBloque)}</code>`],
        ["Hash del contenido", `<code>${esc(n.hashContenido)}</code>`],
        ["Clave de idempotencia", `<code>${esc(n.idempotencyKey)}</code>`],
        ["Respuesta idempotente", n.idempotente ? "sí — este seal no escribió nada nuevo" : "no — se escribió un bloque"],
        n.duplicadoDe?.length ? ["Duplicado de", `bloques ${n.duplicadoDe.join(", ")}`] : null,
      ])
    : `<p class="mal">Esta factura no está sellada.</p>
       <form method="post" action="/factura/${esc(f.numero)}/reintentar">
         <button type="submit">Reintentar el sellado (misma clave)</button>
       </form>`
}
  ${comando(f.comandoDeSellado ?? nucleo.comando(["seal", "--tenant", TENANT, "--type", TIPO, "--payload", "<documento>", "--passphrase-file", "<fichero>", "--idempotency-key", `factura-${f.numero}`]))}
</div>

<h2>El recibo del cliente</h2>
<div class="tarjeta">
${
  recibo
    ? `${pares([
        ["Destinatario", esc(recibo.destinatario)],
        ["Tiempo demostrable", recibo.tiempoDemostrable ? `<code>${esc(recibo.tiempoDemostrable)}</code>` : '<span class="medio">◐ ninguno: no hay cosignature de testigo todavía</span>'],
        ["Testigos que cosignaron", recibo.cosignatarios.length ? esc(recibo.cosignatarios.join(", ")) : '<span class="medio">ninguno</span>'],
      ])}
       <pre class="recibo">${esc(recibo.texto)}</pre>
       <form method="post" action="/verificar">
         <input type="hidden" name="recibo" value="${esc(recibo.texto)}">
         <button type="submit">Verificar este recibo</button>
         <p class="nota">El botón manda el recibo a la pantalla de verificación, que usa
         <code>@nucleoledger/verify</code> y no consulta nada: ni el ledger, ni el
         testigo, ni la red.</p>
       </form>`
    : `<form method="post" action="/factura/${esc(f.numero)}/recibo">
         <label for="para">Para (nombre o RUC del destinatario)</label>
         <input id="para" name="para" required value="${esc(f.cliente)}">
         <button type="submit"${n ? "" : " disabled"}>Emitir el recibo</button>
       </form>
       <p class="nota">El recibo se FIRMA, así que este comando pide la passphrase. Lleva
       el header del bloque, la prueba de inclusión y el checkpoint cosignado: con eso se
       verifica sin llamar a nadie.</p>`
}
  ${n ? comando(nucleo.comando(["receipt", "--block", String(n.bloque), "--recipient", f.cliente, "--passphrase-file", "<fichero>"])) : ""}
</div>

<h2>Alterar el registro (la demo del criterio de éxito)</h2>
<div class="tarjeta aviso">
  <p>Esto cambia el importe <strong>en la base del ERP</strong> y no toca el ledger. Es lo
  que haría quien quiere rebajar una factura ya emitida. Núcleo no puede impedirlo —la
  base no es suya—; lo que hace es recordar qué decía el registro cuando se selló, y
  <a href="/reconciliar">la reconciliación</a> lo enseña.</p>
  <form method="post" action="/factura/${esc(f.numero)}/alterar">
    <label for="total">Total nuevo (USD)</label>
    <input id="total" name="total" required value="1.00">
    <button type="submit" class="suave">Alterar el importe</button>
  </form>
</div>

<a class="boton suave" href="/">Volver</a>`;
  return pagina({ titulo: `Factura ${f.numero}`, ruta: "/", cuerpo });
}

async function paginaDeVerificacion({ texto = "", resultado = null } = {}) {
  const veredicto = resultado
    ? `<div class="tarjeta">
  <h2 style="margin-top:0">${resultado.valid ? '<span class="ok">✔ RECIBO VÁLIDO</span>' : '<span class="mal">✘ RECIBO NO VÁLIDO</span>'}</h2>
  ${pares([
    ["Bloque", resultado.blockIndex === null ? "—" : String(resultado.blockIndex)],
    ["Destinatario", esc(resultado.recipient ?? "—")],
    ["Tiempo demostrable", resultado.provableTime ? `<code>${esc(resultado.provableTime)}</code>` : '<span class="medio">◐ ninguno: sin cosignature aceptada no hay tiempo que demostrar</span>'],
    ["Tiempo declarado", esc(resultado.declaredTime ?? "—")],
    ["Firma del bloque", marca(resultado.blockSignatureVerified, "verificada contra la clave del emisor", "no verificada")],
    ["Firma del recibo", marca(resultado.receiptSignatureVerified, "verificada: cubre a este destinatario", "no verificada")],
    ["Testigos que cosignaron", resultado.cosigners.length ? esc(resultado.cosigners.join(", ")) : '<span class="medio">ninguno</span>'],
    ["Clave del firmante", `<code>${esc(resultado.signerPubKey ?? "—")}</code>`],
    resultado.reasons.length ? ["Por qué falla", `<ul>${resultado.reasons.map((r) => `<li class="mal">${esc(r)}</li>`).join("")}</ul>`] : null,
  ])}
  <p class="nota">Verificado con <code>@nucleoledger/verify</code> contra
  <code>datos/politica.json</code>. Sin red, sin ledger y sin el binario: lo mismo que
  haría el cliente que recibe el recibo por correo.</p>
</div>`
    : "";
  const cuerpo = `
${veredicto}
<h2>Verificar un recibo</h2>
<div class="tarjeta">
  <form method="post" action="/verificar">
    <label for="recibo">Pega aquí el recibo completo, desde <code>nucleo.org/receipt@v2</code></label>
    <textarea id="recibo" name="recibo" required>${esc(texto)}</textarea>
    <button type="submit">Verificar</button>
  </form>
  <p class="nota">La política es lo único en lo que el verificador confía: el origin del
  log, la clave del emisor y los testigos aceptados. Todo lo demás se comprueba contra
  ella. Cambia un byte del recibo y mira lo que dice.</p>
</div>`;
  return pagina({ titulo: "Verificar un recibo", ruta: "/verificar", cuerpo });
}

async function paginaDeReconciliacion(informe) {
  const filas = (informe?.hallazgos ?? [])
    .map(
      (h) => `<tr>
  <td>${esc(h.estado)}</td>
  <td class="num">${h.bloque}</td>
  <td><code>${esc((h.hashSellado ?? "—").slice(0, 16))}…</code></td>
  <td><code>${esc((h.hashActual ?? "—").slice(0, 16))}…</code></td>
  <td>${esc(h.selladoEn ?? "—")}</td>
</tr>`,
    )
    .join("");
  const resultado = informe
    ? `<div class="tarjeta">
  <h2 style="margin-top:0">${informe.cuadra ? '<span class="ok">✔ TODO CUADRA</span>' : '<span class="mal">✘ HAY REGISTROS QUE NO CUADRAN</span>'}</h2>
  ${pares([
    ["Bloques en el ledger", String(informe.treeSize)],
    ["Registros comparados", String(informe.comparados)],
    ["Coincidentes", String(informe.coincidentes)],
    ["Hallazgos", String(informe.hallazgos.length)],
    ["Verificación exhaustiva", informe.verificacionCompleta ? marca(informe.verificacionCompleta.ok, "la cadena entera verifica", "la cadena NO verifica") : "no se ejecutó"],
  ])}
  ${informe.hallazgos.length ? `<table>
<tr><th>Estado</th><th class="num">Bloque</th><th>Sellado</th><th>Hoy</th><th>Sellado el</th></tr>
${filas}</table>
<p class="nota">Código de salida <code>2</code>. Y eso NO es un fallo del programa: un
cotejo que encuentra una discrepancia ha hecho su trabajo. Por eso el ERP lee el informe
en las dos ramas en vez de tratar el 2 como una excepción.</p>` : ""}
</div>`
    : "";
  const cuerpo = `
${resultado}
<h2>Reconciliar</h2>
<div class="tarjeta">
  <p>El ERP exporta lo que dice <strong>hoy</strong> —una línea por factura, con el
  índice del bloque y el contenido actual en base64— y Núcleo lo compara con lo que se
  selló.</p>
  <form method="post" action="/reconciliar">
    <button type="submit">Cotejar el ERP contra el ledger</button>
  </form>
  ${comando(nucleo.comando(["reconcile", "--source", cfg.FICHERO_VIVO]))}
  <p class="nota">Para ver un hallazgo: entra en una factura, altera el importe y vuelve
  aquí. Ese es el paso 8 del criterio de éxito, dentro de una aplicación.</p>
</div>`;
  return pagina({ titulo: "Reconciliar", ruta: "/reconciliar", cuerpo });
}

async function paginaDeEstado({ sync = null } = {}) {
  const est = await nucleo.estado();
  const ver = await nucleo.verifica();
  const avisos = cfg.DIARIO.length
    ? `<table><tr><th>Cuándo</th><th>Nivel</th><th>Aviso</th></tr>${cfg.DIARIO.slice(0, 12)
        .map(
          (a) => `<tr><td>${esc(a.cuando)}</td><td>${a.nivel === "alarma" ? '<span class="mal">alarma</span>' : '<span class="medio">aviso</span>'}</td><td><code>${esc(a.mensaje)}</code></td></tr>`,
        )
        .join("")}</table>`
    : '<p class="nota">Ninguno todavía.</p>';

  const resultadoSync = sync
    ? `<div class="tarjeta">
  <h2 style="margin-top:0">${sync.error ? '<span class="mal">✘ el testigo no atestiguó</span>' : '<span class="ok">✔ atestación conseguida</span>'}</h2>
  ${
    sync.error
      ? `<pre>${esc(sync.error)}</pre>
         <p>El ERP <strong>no ha perdido nada</strong>: las facturas siguen selladas y la
         cadena sigue siendo verificable. Lo que falta es el tercero que dé fe de la
         fecha, y eso se reintenta —lo hace el cron—. Código de salida <code>3</code>:
         incidente operativo, no incidente de integridad.</p>`
      : pares([
          ["Testigo", `<code>${esc(cfg.TESTIGO)}</code>`],
          ["Bloques aquí", String(sync.localSize)],
          ["Bloques que el testigo cosignó", String(sync.witnessSize)],
          ["Cosignature verificada", marca(sync.attested, "sí", "no")],
          ["Cosignature vieja al nacer", sync.replaySuspect ? '<span class="medio">◐ sí: el testigo devolvió algo que ya nacía viejo</span>' : "no"],
        ])
  }
</div>`
    : "";

  const cuerpo = `
${resultadoSync}
${bloqueDeAlarma(est.alerta, { conBoton: true })}
<h2>El ledger</h2>
<div class="tarjeta">
  ${pares([
    ["Origin", `<code>${esc(est.origin)}</code>`],
    ["Clave pública del log", `<code>${esc(est.logPubkey)}</code>`],
    ["Bloques", String(est.treeSize)],
    ["Integridad local", `<span class="ok">✔ ${esc(ver.modo)}</span> sobre ${ver.treeSize} bloques`],
    ["Atestación", marca(est.attested, "verificada", "sin verificar")],
    ["Rollback registrado", est.rollback ? '<span class="mal">✘ sí — un testigo recuerda más historia que este disco</span>' : "no"],
  ])}
  ${comando(nucleo.comando(["verify"]))}
</div>

<h2>Pedir atestación a un testigo</h2>
<div class="tarjeta">
  <form method="post" action="/estado/sync">
    <button type="submit">Sincronizar ahora</button>
  </form>
  ${comando(nucleo.comando(["sync", "--witness", cfg.TESTIGO, "--passphrase-file", "<fichero>"]))}
</div>

<h2>La receta de cron</h2>
<div class="tarjeta">
  <p>Es la que dejó funcionando el ensayo de operación: <code>sync</code> cada hora y
  <code>verify --full</code> los domingos. <code>sync</code> firma un checkpoint, así que
  necesita la passphrase por fichero; <code>status</code> no la necesita.</p>
  <pre>0 * * * * cd ${esc(cfg.RAIZ)} &amp;&amp; node bin/cron.js sync  &gt;&gt; datos/cron.log 2&gt;&amp;1
0 3 * * 0 cd ${esc(cfg.RAIZ)} &amp;&amp; node bin/cron.js semanal &gt;&gt; datos/cron.log 2&gt;&amp;1</pre>
  <p class="nota">stderr va al correo del cron a propósito: los avisos de frescura y de
  rollback salen por ahí <em>también</em> con <code>--json</code>, y son la única alarma
  que hay.</p>
</div>

<h2>Avisos que Núcleo ha mandado por stderr</h2>
<div class="tarjeta">${avisos}</div>`;
  return pagina({ titulo: "Estado del ledger", ruta: "/estado", cuerpo });
}

// ————— el manejo de errores, que es media integración —————

/**
 * respuestaDeError traduce un fallo de Núcleo en una página que sirve.
 *
 * Cada rama contesta las dos preguntas que tiene el que mira la pantalla: ¿se emitió mi
 * factura? y ¿qué hago ahora? El mensaje de Núcleo se enseña TAL CUAL: es el que el
 * operador va a buscar, y traducirlo solo consigue que no lo encuentre.
 */
function respuestaDeError(e, ruta) {
  // La CLASE primero (ADR-027), porque dice lo que el código no puede. Un código 1 que
  // es `transient` no es un fallo de la llamada: es "todavía no", y la respuesta correcta
  // es esperar o sincronizar, no revisar el código del ERP. Este ejemplo fue el que
  // encontró el caso, y ya no tiene que adivinarlo leyendo el mensaje.
  if (e instanceof ErrorDeNucleo && e.clase === "transient" && e.exitCode === 1) {
    return {
      codigo: 409,
      html: paginaDeError({
        ruta,
        titulo: "Todavía no",
        clase: `error_class: transient (código ${e.exitCode})`,
        mensaje: e.message,
        queHizoElERP:
          "Nada que haya que deshacer. Lo que se pidió está bien pedido; falta que se " +
          "cumpla una condición que no depende de este ERP.",
        queHacer: `<ul>
          <li>Si el mensaje habla de <code>sync</code>: sincroniza y vuelve a intentarlo</li>
          <li>Si habla de otro proceso con el ledger tomado: reintenta en unos segundos,
          con la misma clave de idempotencia</li>
          <li>Lo que <strong>no</strong> hay que hacer es cambiar la llamada: no está mal</li>
        </ul>`,
        detalle: e.stderr,
      }),
    };
  }
  if (e instanceof ErrorDeEntorno) {
    return {
      codigo: 503,
      html: paginaDeError({
        ruta,
        titulo: "Núcleo no se pudo ejecutar",
        clase: `ErrorDeEntorno${e.clase ? ` · error_class: ${e.clase}` : ""}`,
        mensaje: e.message,
        queHizoElERP:
          "<strong>No se emitió nada.</strong> El ERP se detuvo antes de escribir la factura " +
          "como emitida: preferimos una factura que falta a una factura sin sello.",
        queHacer: `<ul>
          <li>Comprueba que el binario existe y se puede ejecutar: <code>${esc(cfg.BINARIO)}</code></li>
          <li>Comprueba el fichero de passphrase y sus permisos (<code>0600</code>)</li>
          <li>Después, entra en la factura pendiente y pulsa <em>Reintentar el sellado</em>:
          usa la misma clave de idempotencia, así que no duplica</li>
        </ul>`,
        detalle: e.stderr,
      }),
    };
  }
  if (e instanceof ErrorDeSincronizacion) {
    return {
      codigo: 503,
      html: paginaDeError({
        ruta,
        titulo: "El testigo no atestiguó",
        clase: `ErrorDeSincronizacion (código 3) · error_class: ${e.clase || "transient"}`,
        mensaje: e.message,
        queHizoElERP:
          "<strong>Nada se perdió.</strong> Los sellos son locales y siguen ahí; lo que falta es " +
          "el tercero que dé fe de la fecha. El cron lo reintentará.",
        queHacer:
          e.clase === "environment"
            ? `<p><strong>Esto no se arregla reintentando</strong> —lo dice la clase del
               error, <code>environment</code>—: el testigo contestó, y lo que contestó no
               encaja con lo que espera la política.</p>
               <ul>
                 <li>Comprueba que la clave del testigo en <code>datos/politica.json</code> es la suya</li>
                 <li>Comprueba que la URL apunta a un testigo de Núcleo y no a un proxy o a otra web</li>
                 <li>Si el testigo perdió su memoria, tiene clave nueva: hay que rehacer la política</li>
               </ul>`
            : `<ul>
          <li>Si es un corte de red, no hay nada que hacer: se arregla solo en el próximo <code>sync</code></li>
          <li>Si dura horas, <code>status</code> empezará a avisar de que la atestación es vieja</li>
          <li>Lo que <strong>no</strong> se hace es dejar de sellar: sellar no depende del testigo</li>
        </ul>`,
        detalle: e.stderr,
      }),
    };
  }
  if (e instanceof ErrorDeIntegridad) {
    return {
      codigo: 409,
      html: paginaDeError({
        ruta,
        titulo: "Núcleo encontró una discrepancia",
        clase: `ErrorDeIntegridad (código 2) · error_class: ${e.clase || "integrity"}`,
        mensaje: e.message,
        queHizoElERP:
          "El ERP <strong>no siguió adelante</strong>. Un código 2 no es un reintento: es un " +
          "incidente, y taparlo con un reintento solo borra la pista.",
        queHacer: `<ul>
          <li>No borres nada y no reinicies nada</li>
          <li>Guarda una copia del directorio del ledger antes de tocarlo</li>
          <li>Ejecuta <code>nucleo verify --full</code> y <code>nucleo status</code>, y guarda las salidas</li>
        </ul>`,
        detalle: e.stderr,
      }),
    };
  }
  if (e instanceof ErrorDeContrato) {
    return {
      codigo: 500,
      html: paginaDeError({
        ruta,
        titulo: "La salida de Núcleo no encaja con el contrato",
        clase: "ErrorDeContrato",
        mensaje: e.message,
        queHizoElERP:
          "El ERP <strong>se detuvo</strong> en vez de adivinar. Un campo que falta no se " +
          "sustituye por un valor por omisión: así es como una salida truncada acaba pareciendo " +
          "un sellado correcto.",
        queHacer: `<ul>
          <li>Comprueba la versión del binario: este ERP habla el contrato de <code>docs/CLI-JSON.md</code></li>
          <li>Si el binario es más nuevo y el campo cambió de tipo, es un fallo del contrato: repórtalo</li>
        </ul>`,
        detalle: e.stderr,
      }),
    };
  }
  if (e instanceof ErrorDeUso) {
    return {
      codigo: 500,
      html: paginaDeError({
        ruta,
        titulo: "Núcleo rechazó la llamada",
        clase: `ErrorDeUso (código 1) · error_class: ${e.clase || "usage"}`,
        mensaje: e.message,
        queHizoElERP: "Nada: se detuvo antes de escribir.",
        queHacer: `<p>Es un error de la integración: mira los argumentos del comando de
          arriba. Lo sabemos sin leer el mensaje porque la salida lo dice —
          <code>error_class: ${esc(e.clase || "usage")}</code>—, y si fuera una condición
          que se resuelve sola (el recibo de un bloque que ningún testigo cubrió todavía)
          esta página sería otra.</p>
          <p class="nota">Esa distinción es ADR-027, y salió de este ejemplo.</p>`,
        detalle: e.stderr,
      }),
    };
  }
  return {
    codigo: 500,
    html: paginaDeError({
      ruta,
      titulo: "Fallo no previsto del ERP",
      clase: e?.name ?? "Error",
      mensaje: e?.message ?? String(e),
      queHizoElERP: "Se detuvo. Esto no viene de Núcleo: es del ejemplo.",
      queHacer: "<p>Mira la consola del servidor.</p>",
      detalle: e instanceof ErrorDeNucleo ? e.stderr : (e?.stack ?? ""),
    }),
  };
}

// ————— el enrutado —————

function cuerpoDe(req) {
  return new Promise((resolve, reject) => {
    let d = "";
    req.on("data", (c) => {
      d += c;
      // Un textarea con un recibo pegado son unos pocos kilobytes; un megabyte es
      // alguien jugando.
      if (d.length > 1_000_000) reject(new Error("cuerpo demasiado grande"));
    });
    req.on("end", () => resolve(new URLSearchParams(d)));
    req.on("error", reject);
  });
}

async function enruta(req, url) {
  const ruta = url.pathname;
  const post = req.method === "POST";

  if (ruta === "/" && !post) return { html: await panel() };
  if (ruta === "/estado" && !post) return { html: await paginaDeEstado() };
  if (ruta === "/verificar" && !post) return { html: await paginaDeVerificacion() };
  if (ruta === "/reconciliar" && !post) return { html: await paginaDeReconciliacion(null) };

  if (ruta === "/facturas" && post) {
    const f = await cuerpoDe(req);
    const { factura } = await erp.emite({
      cliente: f.get("cliente") ?? "",
      ruc: f.get("ruc") ?? "",
      items: [
        {
          concepto: f.get("concepto") ?? "",
          cantidad: Number(f.get("cantidad") ?? 1),
          precioCentavos: Math.round(Number(f.get("precio") ?? 0) * 100),
        },
      ],
    });
    return { redirigeA: `/factura/${factura.numero}` };
  }

  if (ruta === "/estado/ack" && post) {
    await nucleo.reconoceAlarma({ por: "pantalla de estado del ERP" });
    return { redirigeA: "/estado" };
  }

  if (ruta === "/estado/sync" && post) {
    try {
      const sync = await nucleo.sincroniza({ witnessURL: cfg.TESTIGO });
      return { html: await paginaDeEstado({ sync }) };
    } catch (e) {
      if (e instanceof ErrorDeSincronizacion) {
        // Un testigo que no contesta NO es una página de error: es una línea en el
        // estado. El ERP sigue funcionando, y la pantalla tiene que enseñar eso.
        return { html: await paginaDeEstado({ sync: { error: e.message } }) };
      }
      throw e;
    }
  }

  if (ruta === "/verificar" && post) {
    const texto = (await cuerpoDe(req)).get("recibo") ?? "";
    const politica = parsePolicyText(readFileSync(cfg.FICHERO_POLITICA, "utf8"));
    // verifyReceipt NUNCA lanza: devuelve el veredicto con sus razones. Por eso no hay
    // try aquí, y por eso no hace falta acordarse de ponerlo.
    const resultado = await verifyReceipt(texto, politica);
    return { html: await paginaDeVerificacion({ texto, resultado }) };
  }

  if (ruta === "/reconciliar" && post) {
    erp.vivoJSONL(cfg.FICHERO_VIVO);
    const informe = await nucleo.reconcilia({ sourceFile: cfg.FICHERO_VIVO });
    return { html: await paginaDeReconciliacion(informe) };
  }

  const m = ruta.match(/^\/factura\/([0-9]{6})(\/recibo|\/alterar|\/reintentar)?$/);
  if (m) {
    const numero = m[1];
    if (!erp.factura(numero)) return null;
    if (!post && !m[2]) return { html: detalleDeFactura(numero) };
    if (post && m[2] === "/recibo") {
      const para = (await cuerpoDe(req)).get("para") ?? "";
      const f = erp.factura(numero);
      let aviso = "";

      // Un recibo lleva DENTRO el checkpoint cosignado que respalda su prueba de
      // inclusión, así que no se puede emitir el de un bloque que ningún testigo ha
      // cubierto todavía: Núcleo lo rechaza y dice que ejecutes `sync`. El orden
      // correcto es sellar, sincronizar y entonces emitir, y el ERP lo hace en vez de
      // enseñarle al usuario un error que no le toca resolver.
      const est = await nucleo.estado();
      if (!(est.attested && est.attestedSize > f.nucleo.bloque)) {
        try {
          const s = await nucleo.sincroniza({ witnessURL: cfg.TESTIGO });
          aviso = `<div class="tarjeta aviso"><p>El bloque ${f.nucleo.bloque} todavía no estaba
            cubierto por ningún checkpoint cosignado, así que el ERP ha sincronizado antes
            de emitir el recibo: el testigo pasó de ${s.witnessSize} a ${s.localSize} bloques.
            Sellar, sincronizar y entonces emitir: en ese orden.</p></div>`;
        } catch (e) {
          if (!(e instanceof ErrorDeSincronizacion)) throw e;
          return {
            codigo: 503,
            html: paginaDeError({
              ruta,
              titulo: "Todavía no se puede emitir este recibo",
              clase: `ErrorDeSincronizacion (código 3) · error_class: ${e.clase || "transient"}`,
              mensaje: e.message,
              queHizoElERP:
                `La factura <strong>está sellada</strong> (bloque ${f.nucleo.bloque}) y eso no ` +
                "se ha perdido. Lo que falta es la cosignature de un testigo: el recibo la " +
                "lleva dentro, y sin ella no habría tiempo demostrable que entregar.",
              queHacer: `<ul>
                <li>Levanta el testigo (<code>npm run testigo</code>) o espera al próximo <code>sync</code> del cron</li>
                <li>Vuelve a pulsar <em>Emitir el recibo</em>: el sello ya está hecho y no se repite</li>
              </ul>`,
              detalle: e.stderr,
            }),
          };
        }
      }

      const recibo = await nucleo.recibo({ bloque: f.nucleo.bloque, destinatario: para });
      mkdirSync(DIR_RECIBOS, { recursive: true });
      writeFileSync(join(DIR_RECIBOS, `factura-${numero}.txt`), recibo.texto);
      return { html: detalleDeFactura(numero, { recibo, aviso }) };
    }
    if (post && m[2] === "/alterar") {
      const total = (await cuerpoDe(req)).get("total") ?? "0.00";
      erp.altera(numero, { total });
      return { redirigeA: "/reconciliar" };
    }
    if (post && m[2] === "/reintentar") {
      await erp.reintenta(numero);
      return { redirigeA: `/factura/${numero}` };
    }
  }
  return null;
}

const servidor = createServer(async (req, res) => {
  const url = new URL(req.url, "http://localhost");
  try {
    const r = await enruta(req, url);
    if (!r) {
      res.writeHead(404, { "content-type": "text/html; charset=utf-8" });
      res.end(pagina({ titulo: "No está", ruta: url.pathname, cuerpo: "<p>Esa página no existe.</p><a class=\"boton suave\" href=\"/\">Volver</a>" }));
      return;
    }
    if (r.redirigeA) {
      res.writeHead(303, { location: r.redirigeA });
      res.end();
      return;
    }
    res.writeHead(r.codigo ?? 200, { "content-type": "text/html; charset=utf-8" });
    res.end(r.html);
  } catch (e) {
    const { codigo, html } = respuestaDeError(e, url.pathname);
    console.error(`[erp] ${req.method} ${url.pathname} → ${codigo}: ${e?.message}`);
    res.writeHead(codigo, { "content-type": "text/html; charset=utf-8" });
    res.end(html);
  }
});

if (!existsSync(cfg.DIR_LEDGER)) {
  console.error(
    `No hay ledger en ${cfg.DIR_LEDGER}.\n` +
      `Ejecuta primero:  npm run setup\n`,
  );
  process.exit(1);
}

servidor.listen(cfg.PUERTO, () => {
  console.log(`ERP de ejemplo en http://127.0.0.1:${cfg.PUERTO}`);
  console.log(`  ledger  : ${cfg.DIR_LEDGER}`);
  console.log(`  binario : ${cfg.BINARIO}`);
  console.log(`  testigo : ${cfg.TESTIGO}`);
});
