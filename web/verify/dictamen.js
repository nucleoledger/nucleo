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
  // La firma post-cuántica del log: ML-DSA-44 (ADR-007, ADR-034 §D). Este navegador NO la
  // verifica —WebCrypto no tiene ML-DSA—, y "present-unverified" no puede parecer una
  // comprobación superada: ni ✔ ni ◐, y la frase dice dónde se verifica de verdad. Con la
  // clave en la política (logMLDSAKey), el SDK sí exige la línea y su longitud, y un
  // recibo sin ella no llega aquí: es un ✘ con su razón. Sin veredicto positivo no hay
  // fila: las razones ya dicen qué falló.
  if (ok && r.logMLDSA === "present-unverified") {
    const sinClave = r.logMLDSANote && r.logMLDSANote !== "este verificador no implementa ML-DSA-44";
    filas.push([
      "firma post-cuántica del log",
      "⚠ firma post-cuántica presente, NO verificada: este verificador no implementa ML-DSA-44; " +
        "para verificarla, `nucleo verify-receipt` (nucleo verify-receipt --receipt RECIBO --policy-file POLÍTICA)" +
        (sinClave ? ". Además, tu política no fija su clave (logMLDSAKey): ni siquiera se exige que esté" : ""),
    ]);
  } else if (ok && r.logMLDSA === "absent") {
    filas.push([
      "firma post-cuántica del log",
      "ausente: el checkpoint no trae firma ML-DSA-44 del log, y tu política no la exige (logMLDSAKey)",
    ]);
  }
  if (r.ignoredSignatures.length) {
    filas.push(["firmas ignoradas", r.ignoredSignatures.join(", ") + " (claves que no conoces)"]);
  }
  return filas;
};
