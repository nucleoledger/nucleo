// Las filas del dictamen de la página, en un fichero propio para poder probarlas.
//
// La regla (D.5 del Sprint 7d): con valid=false NINGUNA fila muestra un ✔ sin
// calificar. Las firmas del bloque y del recibo se comprueban contra claves que
// vienen de la política, pero si la cadena de atestación no verifica —clave del
// log equivocada, quórum no alcanzado— esas comprobaciones son verdades LOCALES:
// dicen que unos bytes cuadran con una clave, no que esa clave sea de alguien. La
// segunda auditoría adversarial enseñó tres ✔ debajo de un ✘ y con razón.
window.NUCLEO_DICTAMEN = function (r) {
  const ok = r.valid;
  // Una verdad local, calificada: solo con veredicto positivo es un ✔ a secas.
  const local = (verificado, texto) => {
    if (verificado !== true) return verificado === false ? "✘ NO verifica" : "— no se pudo comprobar";
    return ok ? "✔ " + texto : "◐ cuadra localmente, pero no ancla nada: la cadena de atestación no verificó";
  };
  const filas = [
    ["bloque", r.blockIndex === null ? "—" : String(r.blockIndex)],
    [
      "destinatario",
      r.recipient === null || r.recipient === undefined
        ? "—"
        : ok && r.receiptSignatureVerified === true
          ? r.recipient + "  (firmado por el emisor)"
          : r.recipient + "  ✘ NO VERIFICADO — nada respalda este nombre",
    ],
    ["firma del recibo", local(r.receiptSignatureVerified, "verificada — el destinatario y el texto están firmados")],
    ["firma del bloque", local(r.blockSignatureVerified, "verificada contra la clave del emisor de la política")],
    ["log", r.checkpoint?.origin ?? "—"],
    ["testigos que verifican", r.cosigners.length ? r.cosigners.join(", ") : "ninguno"],
  ];
  if (r.ignoredSignatures.length) {
    filas.push(["firmas ignoradas", r.ignoredSignatures.join(", ") + " (claves que no conoces)"]);
  }
  return filas;
};
