#!/usr/bin/env python3
# Genera los vectores de POLÍTICA (PROTOCOL.md §3.2, ADR-018).
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
O = "nucleoledger.com/mi-empresa"
W1 = "witness.nucleoledger.com/w1"
W2 = "witness.nucleoledger.com/w2"


def base(**extra):
    # Texto compacto, en el orden de la tabla. Se construye a mano, no con json.dumps,
    # para poder escribir exactamente los bytes que cada caso necesita.
    return extra


VECTORES = []


def v(nombre, valido, texto, descripcion, motivo=""):
    VECTORES.append({"name": nombre, "description": descripcion, "text": texto,
                     "valid": valido, "reason": motivo})


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
