#!/usr/bin/env python3
# Genera los vectores de POLÍTICA (PROTOCOL.md §3.2, ADR-018; erasureKey, ADR-032;
# retiredErasureKeys y logMLDSAKey, 0.8-draft, ADR-033 y ADR-034).
#
# Cada vector es un texto de política EXACTO y el veredicto que la tabla de
# PROTOCOL.md §3.2 le da. Los veredictos están escritos a mano aquí, caso por caso,
# leyendo la tabla; ninguna línea de este script usa el código que los vectores
# verifican (internal/policy en Go, sdk/ts/src/policy.ts en TypeScript). Este script
# solo escribe ficheros: no decide nada que no esté escrito debajo.
#
#   python3 testdata/vectors/policy/generar.py
import json, os

AQUI = os.path.dirname(os.path.abspath(__file__))
K1 = "5e423033044f56a13a686799487bcbfa63dd1e39204cec27dd39a26daa615628"
K2 = "79b5562e8fe654f94078b112e8a98ba7901f853ae695bed7e0e3910bad049664"
K3 = "dd7e84d010aed28a416e928f50c4c09ac0f94a8f5b346548168bddb61cdb7263"
K4 = "9ad2d5b3d3cc90105737568e1b5850035c181004e46f967da9ba21188818f004"
# K5 es la pública de la semilla 000102…1f: la clave de supresión de testdata/vectors/erasure/.
K5 = "03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8"
O = "nucleoledger.com/mi-empresa"
W1 = "witness.nucleoledger.com/w1"
W2 = "witness.nucleoledger.com/w2"


def base(**extra):
    # Texto compacto, en el orden de la tabla. Se construye a mano, no con json.dumps,
    # para poder escribir exactamente los bytes que cada caso necesita.
    return extra


VECTORES = []


def v(nombre, valido, texto, descripcion, motivo="", exige=None):
    x = {"name": nombre, "description": descripcion, "text": texto,
         "valid": valido, "reason": motivo}
    if exige:
        # La versión de PROTOCOL que da el veredicto. Un lector anterior rechaza el
        # documento por traer un miembro desconocido (§3.2), sea cual sea "valid".
        x["requires"] = exige
    VECTORES.append(x)


MIN = '{"origin":"%s","logKey":"%s","witnesses":{"%s":"%s"},"quorum":1}' % (O, K1, W1, K3)

# ---- válidas ----
v("valida-minima", True, MIN, "Los cuatro miembros obligatorios, un testigo, quórum 1.")
v("valida-con-signerkey", True,
  '{"origin":"%s","logKey":"%s","signerKey":"%s","witnesses":{"%s":"%s"},"quorum":1}' % (O, K1, K2, W1, K3),
  "Con signerKey, que es opcional en el formato y obligatorio para verificar un recibo.")
v("valida-dos-testigos-quorum-2", True,
  '{"origin":"%s","logKey":"%s","witnesses":{"%s":"%s","%s":"%s"},"quorum":2}' % (O, K1, W1, K3, W2, K4),
  "Dos testigos con claves distintas, quórum 2.")
v("valida-dos-testigos-quorum-1", True,
  '{"origin":"%s","logKey":"%s","witnesses":{"%s":"%s","%s":"%s"},"quorum":1}' % (O, K1, W1, K3, W2, K4),
  "Dos testigos, quórum 1.")
v("valida-sangrada", True,
  '{\n\t"origin": "%s",\r\n  "logKey" : "%s",\n  "witnesses": {\n    "%s": "%s"\n  },\n  "quorum": 1\n}\n' % (O, K1, W1, K3),
  "Espacio en blanco JSON (espacio, tab, LF, CR) entre todos los tokens y al final.")
v("valida-otro-orden", True,
  '{"quorum":1,"witnesses":{"%s":"%s"},"logKey":"%s","origin":"%s"}' % (W1, K3, K1, O),
  "El orden de los miembros no importa.")
v("valida-nombre-con-escape", True,
  '{"\\u006frigin":"%s","logKey":"%s","witnesses":{"%s":"%s"},"quorum":1}' % (O, K1, W1, K3),
  "Un nombre de miembro escrito con escape \\u: tras decodificar es origin.")
v("valida-origin-unicode", True,
  '{"origin":"núcleo.example/log","logKey":"%s","witnesses":{"%s":"%s"},"quorum":1}' % (K1, W1, K3),
  "origin con caracteres no ASCII en UTF-8.")
v("valida-surrogate-par", True,
  '{"origin":"log\\ud83d\\ude00","logKey":"%s","witnesses":{"%s":"%s"},"quorum":1}' % (K1, W1, K3),
  "Un par de surrogates UTF-16 bien formado dentro de una cadena.")
v("valida-escape-barra", True,
  '{"origin":"nucleoledger.com\\/mi-empresa","logKey":"%s","witnesses":{"%s":"%s"},"quorum":1}' % (K1, W1, K3),
  "Escape \\/ dentro de una cadena.")

# ---- inválidas: claves repetidas y variantes ----
v("invalida-miembro-duplicado", False,
  '{"origin":"%s","logKey":"%s","signerKey":"%s","signerKey":"%s","witnesses":{"%s":"%s"},"quorum":1}' % (O, K1, K2, K4, W1, K3),
  "signerKey dos veces. encoding/json y JSON.parse se quedarían con la última en silencio.", "duplicate_member")
v("invalida-duplicado-por-escape", False,
  '{"origin":"%s","logKey":"%s","signerKey":"%s","sign\\u0065rKey":"%s","witnesses":{"%s":"%s"},"quorum":1}' % (O, K1, K2, K4, W1, K3),
  "signerKey y sign\\u0065rKey: el mismo nombre tras decodificar el escape.", "duplicate_member")
v("invalida-variante-mayusculas-junto", False,
  '{"origin":"%s","logKey":"%s","signerKey":"%s","signerkey":"%s","witnesses":{"%s":"%s"},"quorum":1}' % (O, K1, K2, K4, W1, K3),
  "El ataque #4 de la tercera auditoría: signerKey y signerkey en el mismo documento.", "case_variant")
v("invalida-variante-mayusculas-sola", False,
  '{"origin":"%s","LogKey":"%s","witnesses":{"%s":"%s"},"quorum":1}' % (O, K1, W1, K3),
  "LogKey en vez de logKey.", "case_variant")
v("invalida-miembro-desconocido", False,
  '{"origin":"%s","logKey":"%s","witnesses":{"%s":"%s"},"quorum":1,"comment":"hola"}' % (O, K1, W1, K3),
  "Un miembro que la tabla no define.", "unknown_member")
v("invalida-testigo-duplicado", False,
  '{"origin":"%s","logKey":"%s","witnesses":{"%s":"%s","%s":"%s"},"quorum":1}' % (O, K1, W1, K3, W1, K4),
  "El mismo nombre de testigo dos veces dentro de witnesses.", "duplicate_member")

# ---- inválidas: origin ----
v("invalida-sin-origin", False, '{"logKey":"%s","witnesses":{"%s":"%s"},"quorum":1}' % (K1, W1, K3), "Falta origin.", "missing")
v("invalida-origin-vacio", False, '{"origin":"","logKey":"%s","witnesses":{"%s":"%s"},"quorum":1}' % (K1, W1, K3), "origin vacío.", "origin")
v("invalida-origin-numero", False, '{"origin":7,"logKey":"%s","witnesses":{"%s":"%s"},"quorum":1}' % (K1, W1, K3), "origin no es cadena.", "origin")
v("invalida-origin-objeto", False, '{"origin":{},"logKey":"%s","witnesses":{"%s":"%s"},"quorum":1}' % (K1, W1, K3), "origin es un objeto.", "origin")

# ---- inválidas: claves ----
v("invalida-sin-logkey", False, '{"origin":"%s","witnesses":{"%s":"%s"},"quorum":1}' % (O, W1, K3), "Falta logKey.", "missing")
v("invalida-logkey-mayusculas", False, '{"origin":"%s","logKey":"%s","witnesses":{"%s":"%s"},"quorum":1}' % (O, K1.upper(), W1, K3), "logKey en mayúsculas: segunda representación.", "hex")
v("invalida-logkey-63", False, '{"origin":"%s","logKey":"%s","witnesses":{"%s":"%s"},"quorum":1}' % (O, K1[:63], W1, K3), "logKey de 63 caracteres.", "hex")
v("invalida-logkey-65", False, '{"origin":"%s","logKey":"%s0","witnesses":{"%s":"%s"},"quorum":1}' % (O, K1, W1, K3), "logKey de 65 caracteres.", "hex")
v("invalida-logkey-no-hex", False, '{"origin":"%s","logKey":"%sg","witnesses":{"%s":"%s"},"quorum":1}' % (O, K1[:63], W1, K3), "logKey con una g.", "hex")
v("invalida-signerkey-mayusculas", False, '{"origin":"%s","logKey":"%s","signerKey":"%s","witnesses":{"%s":"%s"},"quorum":1}' % (O, K1, K2.upper(), W1, K3), "signerKey en mayúsculas.", "hex")
v("invalida-signerkey-vacia", False, '{"origin":"%s","logKey":"%s","signerKey":"","witnesses":{"%s":"%s"},"quorum":1}' % (O, K1, W1, K3), "signerKey vacía: si está, es una clave.", "hex")
v("invalida-signerkey-null", False, '{"origin":"%s","logKey":"%s","signerKey":null,"witnesses":{"%s":"%s"},"quorum":1}' % (O, K1, W1, K3), "signerKey null.", "null")

# ---- inválidas: testigos ----
v("invalida-sin-witnesses", False, '{"origin":"%s","logKey":"%s","quorum":1}' % (O, K1), "Falta witnesses.", "missing")
v("invalida-witnesses-vacio", False, '{"origin":"%s","logKey":"%s","witnesses":{},"quorum":1}' % (O, K1), "Sin testigos: una política que no verifica nada.", "no_witnesses")
v("invalida-witnesses-array", False, '{"origin":"%s","logKey":"%s","witnesses":["%s"],"quorum":1}' % (O, K1, K3), "witnesses es un array.", "type")
v("invalida-testigo-mayusculas", False, '{"origin":"%s","logKey":"%s","witnesses":{"%s":"%s"},"quorum":1}' % (O, K1, W1, K3.upper()), "Clave de testigo en mayúsculas.", "hex")
v("invalida-testigo-sin-nombre", False, '{"origin":"%s","logKey":"%s","witnesses":{"":"%s"},"quorum":1}' % (O, K1, K3), "Testigo con nombre vacío.", "witness_name")
v("invalida-misma-clave-dos-nombres", False,
  '{"origin":"%s","logKey":"%s","witnesses":{"%s":"%s","alias.example/w1":"%s"},"quorum":2}' % (O, K1, W1, K3, K3),
  "El hallazgo BAJO #7: la misma clave bajo dos nombres cuenta dos veces para el quórum.", "duplicate_key")
v("invalida-testigo-null", False, '{"origin":"%s","logKey":"%s","witnesses":{"%s":null},"quorum":1}' % (O, K1, W1), "Clave de testigo null.", "null")
v("invalida-testigo-objeto", False, '{"origin":"%s","logKey":"%s","witnesses":{"%s":{}},"quorum":1}' % (O, K1, W1), "Clave de testigo que es un objeto (tercer nivel).", "type")

# ---- inválidas: quórum ----
v("invalida-sin-quorum", False, '{"origin":"%s","logKey":"%s","witnesses":{"%s":"%s"}}' % (O, K1, W1, K3), "Falta quorum: nunca vale cero por omisión.", "missing")
for texto, nombre, desc in [
    ("0", "cero", "quorum 0."),
    ("2", "mayor-que-testigos", "quorum 2 con un testigo."),
    ("1.0", "fraccion", "quorum 1.0: literal con fracción."),
    ("1e0", "exponente", "quorum 1e0: literal con exponente."),
    ('"1"', "cadena", "quorum como cadena."),
    ("-1", "negativo", "quorum negativo."),
    ("-0", "menos-cero", "quorum -0."),
    ("01", "cero-a-la-izquierda", "quorum 01: JSON no admite ceros a la izquierda."),
    ("true", "booleano", "quorum true."),
    ("null", "null", "quorum null."),
    ("99999999999999999999", "enorme", "quorum de 20 dígitos."),
]:
    v("invalida-quorum-" + nombre, False, '{"origin":"%s","logKey":"%s","witnesses":{"%s":"%s"},"quorum":%s}' % (O, K1, W1, K3, texto), desc, "quorum")

# ---- erasureKey (ADR-032): opcional, una clave, y distinta de todas las demás ----
v("valida-con-erasurekey", True,
  '{"origin":"%s","logKey":"%s","signerKey":"%s","erasureKey":"%s","witnesses":{"%s":"%s"},"quorum":1}' % (O, K1, K2, K5, W1, K3),
  "Con erasureKey, la clave que autoriza las supresiones: opcional.")
v("valida-erasurekey-sin-signerkey", True,
  '{"origin":"%s","logKey":"%s","erasureKey":"%s","witnesses":{"%s":"%s"},"quorum":1}' % (O, K1, K5, W1, K3),
  "erasureKey sin signerKey: el formato no la ata a signerKey.")
v("invalida-erasurekey-mayusculas", False,
  '{"origin":"%s","logKey":"%s","erasureKey":"%s","witnesses":{"%s":"%s"},"quorum":1}' % (O, K1, K5.upper(), W1, K3),
  "erasureKey en mayúsculas: segunda representación.", "hex")
v("invalida-erasurekey-63", False,
  '{"origin":"%s","logKey":"%s","erasureKey":"%s","witnesses":{"%s":"%s"},"quorum":1}' % (O, K1, K5[:63], W1, K3),
  "erasureKey de 63 caracteres.", "hex")
v("invalida-erasurekey-vacia", False,
  '{"origin":"%s","logKey":"%s","erasureKey":"","witnesses":{"%s":"%s"},"quorum":1}' % (O, K1, W1, K3),
  "erasureKey vacía: si está, es una clave.", "hex")
v("invalida-erasurekey-null", False,
  '{"origin":"%s","logKey":"%s","erasureKey":null,"witnesses":{"%s":"%s"},"quorum":1}' % (O, K1, W1, K3),
  "erasureKey null.", "null")
v("invalida-erasurekey-numero", False,
  '{"origin":"%s","logKey":"%s","erasureKey":1,"witnesses":{"%s":"%s"},"quorum":1}' % (O, K1, W1, K3),
  "erasureKey es un número.", "hex")
v("invalida-erasurekey-variante-mayusculas", False,
  '{"origin":"%s","logKey":"%s","erasurekey":"%s","witnesses":{"%s":"%s"},"quorum":1}' % (O, K1, K5, W1, K3),
  "erasurekey en vez de erasureKey.", "case_variant")
v("invalida-erasurekey-duplicada", False,
  '{"origin":"%s","logKey":"%s","erasureKey":"%s","erasureKey":"%s","witnesses":{"%s":"%s"},"quorum":1}' % (O, K1, K5, K4, W1, K3),
  "erasureKey dos veces.", "duplicate_member")
v("invalida-erasurekey-igual-logkey", False,
  '{"origin":"%s","logKey":"%s","erasureKey":"%s","witnesses":{"%s":"%s"},"quorum":1}' % (O, K1, K1, W1, K3),
  "La clave de supresión es la del log, que está en el servidor: no autoriza nada.", "erasure_key_reused")
v("invalida-erasurekey-igual-signerkey", False,
  '{"origin":"%s","logKey":"%s","signerKey":"%s","erasureKey":"%s","witnesses":{"%s":"%s"},"quorum":1}' % (O, K1, K2, K2, W1, K3),
  "La clave de supresión es la del firmante, que la passphrase abre: es el hallazgo de ADR-032.", "erasure_key_reused")
v("invalida-erasurekey-igual-testigo", False,
  '{"origin":"%s","logKey":"%s","erasureKey":"%s","witnesses":{"%s":"%s","%s":"%s"},"quorum":1}' % (O, K1, K4, W1, K3, W2, K4),
  "La clave de supresión es la de un testigo: una clave, dos papeles.", "erasure_key_reused")

# ---- 0.8-draft (ADR-033, ADR-034): retiredErasureKeys y logMLDSAKey ----
# Los veredictos, a mano desde las filas de PROTOCOL §3.2 y las «Decisiones del dev» de
# los dos ADR. Todos llevan "requires": "0.8-draft".
#
# KB es la pública de la semilla 202122…3f: la clave nueva de testdata/vectors/erasure/.
# K5 (la de 000102…1f) hace de clave retirada. ML es una clave pública ML-DSA-44 que no
# es de nadie: toda cadena de 1312 bytes se decodifica como una (ADR-034 §A), así que
# para la gramática basta con la longitud.
KB = "29acbae141bccaf0b22e1a94d34d0bc7361e526d0bfe12c89794bc9322966dd7"
ML = bytes(i % 256 for i in range(1312)).hex()
assert len(ML) == 2624
V8 = "0.8-draft"


def p8(nombre, valido, cuerpo, descripcion, motivo=""):
    # cuerpo va entre logKey y witnesses, con su coma delante.
    v(nombre, valido, '{"origin":"%s","logKey":"%s"%s,"witnesses":{"%s":"%s"},"quorum":1}' % (O, K1, cuerpo, W1, K3),
      descripcion, motivo, exige=V8)


def ret(objeto):
    return ',"erasureKey":"%s","retiredErasureKeys":%s' % (KB, objeto)


# válidas
p8("valida-retirada-una", True, ret('{"%s":41}' % K5),
   "Una clave retirada con su corte, y la clave actual en erasureKey.")
p8("valida-retiradas-dos", True, ret('{"%s":41,"%s":120}' % (K5, K4)),
   "Dos claves retiradas, cada una con su corte.")
p8("valida-retirada-sin-erasurekey", True, ',"retiredErasureKeys":{"%s":41}' % K5,
   "Sin erasureKey: quien ya no suprime y no quiere que lo suprimido deje de contar (decisión 2).")
p8("valida-retirada-corte-0", True, ret('{"%s":0}' % K5), "Corte 0.")
p8("valida-retirada-corte-maximo", True, ret('{"%s":9007199254740991}' % K5), "Corte 2^53 − 1.")
p8("valida-retirada-sangrada", True, ret('{ "%s" :\n 41 }' % K5),
   "Espacio en blanco JSON dentro del objeto de claves retiradas.")
p8("valida-retirada-con-signerkey", True, ',"signerKey":"%s"' % K2 + ret('{"%s":41}' % K5),
   "Con signerKey, distinta de la clave retirada.")
p8("valida-con-logmldsakey", True, ',"logMLDSAKey":"%s"' % ML,
   "Con logMLDSAKey, la clave pública ML-DSA-44 del log en 2624 hexadecimales.")
p8("valida-con-los-dos-miembros", True,
   ',"signerKey":"%s","logMLDSAKey":"%s"' % (K2, ML) + ret('{"%s":41}' % K5),
   "Los dos miembros de 0.8-draft a la vez, con erasureKey y signerKey.")

# inválidas: retiredErasureKeys, la forma
p8("invalida-retiradas-array", False, ret('[{"key":"%s","until":41}]' % K5),
   "El array [{key, until}] de la idea de partida, descartado (decisión 1).", "type")
p8("invalida-retiradas-vacio", False, ret("{}"),
   "Objeto vacío: significaría lo mismo que no ponerlo.", "no_retired_keys")
p8("invalida-retiradas-null", False, ret("null"), "retiredErasureKeys null.", "null")
p8("invalida-retiradas-cadena", False, ret('"%s"' % K5), "retiredErasureKeys es una cadena.", "type")
p8("invalida-retiradas-duplicado", False,
   ',"erasureKey":"%s","retiredErasureKeys":{"%s":41},"retiredErasureKeys":{"%s":7}' % (KB, K5, K4),
   "El miembro retiredErasureKeys dos veces.", "duplicate_member")
p8("invalida-retiradas-variante-minusculas", False, ',"erasureKey":"%s","retirederasurekeys":{"%s":41}' % (KB, K5),
   "retirederasurekeys en vez de retiredErasureKeys.", "case_variant")
p8("invalida-retiradas-variante-mayuscula-inicial", False, ',"erasureKey":"%s","RetiredErasureKeys":{"%s":41}' % (KB, K5),
   "RetiredErasureKeys en vez de retiredErasureKeys.", "case_variant")

# inválidas: retiredErasureKeys, las claves
p8("invalida-retirada-clave-repetida", False, ret('{"%s":41,"%s":50}' % (K5, K5)),
   "La misma clave retirada dos veces.", "duplicate_member")
p8("invalida-retirada-clave-repetida-por-escape", False, ret('{"%s":41,"\\u0030%s":50}' % (K5, K5[1:])),
   "La misma clave dos veces, la segunda con su primer carácter escrito \\u0030.", "duplicate_member")
p8("invalida-retirada-clave-63", False, ret('{"%s":41}' % K5[:63]), "Clave retirada de 63 caracteres.", "hex")
p8("invalida-retirada-clave-65", False, ret('{"%s0":41}' % K5), "Clave retirada de 65 caracteres.", "hex")
p8("invalida-retirada-clave-mayusculas", False, ret('{"%s":41}' % K5.upper()),
   "Clave retirada en mayúsculas: segunda representación.", "hex")
p8("invalida-retirada-clave-no-hex", False, ret('{"%sg":41}' % K5[:63]), "Clave retirada con una g.", "hex")
p8("invalida-retirada-clave-vacia", False, ret('{"":41}'), "Clave retirada vacía.", "hex")
p8("invalida-retirada-igual-erasurekey", False, ret('{"%s":41}' % KB),
   "La clave retirada es la actual: ¿está retirada o no?", "erasure_key_reused")
p8("invalida-retirada-igual-logkey", False, ret('{"%s":41}' % K1),
   "La clave retirada es la del log.", "erasure_key_reused")
p8("invalida-retirada-igual-signerkey", False, ',"signerKey":"%s"' % K2 + ret('{"%s":41}' % K2),
   "La clave retirada es la del firmante.", "erasure_key_reused")
v("invalida-retirada-igual-testigo", False,
  '{"origin":"%s","logKey":"%s","erasureKey":"%s","retiredErasureKeys":{"%s":41},"witnesses":{"%s":"%s","%s":"%s"},"quorum":1}'
  % (O, K1, KB, K4, W1, K3, W2, K4),
  "La clave retirada es la de un testigo.", "erasure_key_reused", exige=V8)
p8("invalida-retirada-igual-testigo-sin-erasurekey", False, ',"retiredErasureKeys":{"%s":41}' % K3,
   "Sin erasureKey, la clave retirada sigue sin poder ser la de un testigo.", "erasure_key_reused")

# inválidas: retiredErasureKeys, el corte
for texto, nombre, desc in [
    ("-1", "negativo", "Corte negativo."),
    ("-0", "menos-cero", "Corte -0: el corte no lleva signo."),
    ("41.0", "fraccion", "Corte 41.0: literal con fracción."),
    ("4.1e1", "exponente", "Corte 4.1e1: literal con exponente."),
    ("41e0", "exponente-entero", "Corte 41e0: exponente sin fracción."),
    ("041", "cero-a-la-izquierda", "Corte 041: JSON no admite ceros a la izquierda."),
    ('"41"', "cadena", "Corte como cadena."),
    ("null", "null", "Corte null."),
    ("true", "booleano", "Corte true."),
    ("{}", "objeto", "Corte que es un objeto."),
    ("9007199254740992", "2-53", "Corte 2^53, uno más que el índice máximo de PROTOCOL §1."),
    ("99999999999999999999", "enorme", "Corte de 20 dígitos."),
]:
    p8("invalida-retirada-corte-" + nombre, False, ret('{"%s":%s}' % (K5, texto)), desc, "cutoff")

# inválidas: logMLDSAKey
for valor, nombre, desc, motivo in [
    ('"%s"' % ML[:2623], "2623", "logMLDSAKey de 2623 caracteres.", "hex"),
    ('"%s0"' % ML, "2625", "logMLDSAKey de 2625 caracteres.", "hex"),
    ('"%s"' % ML[:2622], "2622", "logMLDSAKey de 2622 caracteres: 1311 bytes.", "hex"),
    ('"%s"' % (ML + "00"), "2626", "logMLDSAKey de 2626 caracteres: 1313 bytes.", "hex"),
    ('"%s"' % K1, "64", "logMLDSAKey con la longitud de una clave Ed25519.", "hex"),
    ('"%s"' % ML.upper(), "mayusculas", "logMLDSAKey en mayúsculas: segunda representación.", "hex"),
    ('"%sA"' % ML[:2623], "una-mayuscula", "logMLDSAKey con una sola mayúscula, al final.", "hex"),
    ('"%sg"' % ML[:2623], "no-hex", "logMLDSAKey con una g.", "hex"),
    ('"%s "' % ML[:2623], "espacio", "logMLDSAKey con un espacio dentro de la cadena.", "hex"),
    ('""', "vacia", "logMLDSAKey vacía: si está, es una clave.", "hex"),
    ("null", "null", "logMLDSAKey null.", "null"),
    ("1", "numero", "logMLDSAKey es un número.", "hex"),
    ('{}', "objeto", "logMLDSAKey es un objeto.", "type"),
]:
    p8("invalida-logmldsakey-" + nombre, False, ',"logMLDSAKey":%s' % valor, desc, motivo)
p8("invalida-logmldsakey-duplicada", False, ',"logMLDSAKey":"%s","logMLDSAKey":"%s"' % (ML, ML),
   "logMLDSAKey dos veces, con el mismo valor.", "duplicate_member")
p8("invalida-logmldsakey-duplicada-por-escape", False, ',"logMLDSAKey":"%s","logMLDSA\\u004bey":"%s"' % (ML, ML),
   "logMLDSAKey y logMLDSA\\u004bey: el mismo nombre tras decodificar el escape.", "duplicate_member")
p8("invalida-logmldsakey-variante-minusculas", False, ',"logmldsakey":"%s"' % ML,
   "logmldsakey en vez de logMLDSAKey.", "case_variant")
p8("invalida-logmldsakey-variante-mixta", False, ',"logMldsaKey":"%s"' % ML,
   "logMldsaKey en vez de logMLDSAKey.", "case_variant")
p8("invalida-logmldsakey-junto-a-variante", False, ',"logMLDSAKey":"%s","logMldsaKey":"%s"' % (ML, ML),
   "logMLDSAKey y logMldsaKey en el mismo documento.", "case_variant")

# ---- inválidas: documento ----
v("invalida-basura-detras", False, MIN + '\n{"signerKey":"%s"} esto no es JSON' % K2, "El hallazgo BAJO #8: contenido después del objeto.", "trailing")
v("invalida-dos-objetos", False, MIN + MIN, "Dos objetos seguidos.", "trailing")
v("invalida-array-raiz", False, "[" + MIN + "]", "El documento es un array.", "type")
v("invalida-bom", False, "﻿" + MIN, "Empieza con BOM.", "bom")
v("invalida-coma-final", False, MIN[:-1] + ",}", "Coma antes de cerrar el objeto.", "syntax")
v("invalida-comentario", False, "// política\n" + MIN, "Comentario: JSON no los tiene.", "syntax")
v("invalida-comillas-simples", False, MIN.replace('"origin"', "'origin'"), "Comillas simples.", "syntax")
v("invalida-surrogate-suelto", False, '{"origin":"log\\ud800","logKey":"%s","witnesses":{"%s":"%s"},"quorum":1}' % (K1, W1, K3),
  "Surrogate alto sin pareja: encoding/json lo convierte en U+FFFD y JSON.parse lo conserva.", "surrogate")
v("invalida-surrogate-bajo-suelto", False, '{"origin":"log\\udc00","logKey":"%s","witnesses":{"%s":"%s"},"quorum":1}' % (K1, W1, K3),
  "Surrogate bajo sin pareja.", "surrogate")
v("invalida-tab-en-cadena", False, '{"origin":"log\tx","logKey":"%s","witnesses":{"%s":"%s"},"quorum":1}' % (K1, W1, K3),
  "Un tabulador sin escapar dentro de una cadena.", "syntax")
v("invalida-escape-desconocido", False, '{"origin":"log\\x41","logKey":"%s","witnesses":{"%s":"%s"},"quorum":1}' % (K1, W1, K3),
  "Escape \\x, que JSON no define.", "syntax")
v("invalida-vacia", False, "", "Documento vacío.", "syntax")
v("invalida-solo-espacios", False, " \n", "Solo espacio en blanco.", "syntax")
v("invalida-true-miembro", False, '{"origin":"%s","logKey":"%s","witnesses":{"%s":"%s"},"quorum":1,"x":true}' % (O, K1, W1, K3), "Un booleano en un miembro.", "type")
v("invalida-demasiado-grande", False, MIN + " " * (65536 - len(MIN.encode()) + 1),
  "Un byte más de 65536, aunque sea espacio en blanco.", "size")
v("valida-justo-65536", True, MIN + " " * (65536 - len(MIN.encode())),
  "Exactamente 65536 bytes.")

if __name__ == "__main__":
    for f in os.listdir(AQUI):
        if f.endswith(".json"):
            os.remove(os.path.join(AQUI, f))
    for x in VECTORES:
        with open(os.path.join(AQUI, x["name"] + ".json"), "w", encoding="utf-8", newline="\n") as fh:
            json.dump(x, fh, ensure_ascii=False, indent=2)
            fh.write("\n")
    print(len(VECTORES), "vectores;", sum(1 for x in VECTORES if x["valid"]), "válidos")
