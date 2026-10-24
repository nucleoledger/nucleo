#!/usr/bin/env python3
# Genera los vectores de la AUTORIZACIÓN DE SUPRESIÓN (PROTOCOL.md §5.1, ADR-032) y de
# la ROTACIÓN de su clave (PROTOCOL 0.8-draft §5.1, ADR-033: claves retiradas y
# regularización).
#
# Implementación independiente: el texto firmado se construye aquí a mano, desde la
# definición de PROTOCOL §5.1, y la firma Ed25519 la hace la biblioteca `cryptography`
# de Python. Ninguna línea de este script usa el código que los vectores verifican
# (internal/erasure). Los veredictos de los casos inválidos están escritos a mano,
# caso por caso.
#
#   python3 testdata/vectors/erasure/generar.py
import hashlib, json, os
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

AQUI = os.path.dirname(os.path.abspath(__file__))

SEMILLA = bytes(range(32))  # 000102…1f: una clave que cualquiera reconoce como de prueba
OTRA = bytes(range(32, 64))
ORIGIN = "nucleoledger.com/mi-empresa"
H = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"  # SHA-256 de ""
H2 = "5e423033044f56a13a686799487bcbfa63dd1e39204cec27dd39a26daa615628"
THROUGH = 7


def pub(semilla):
    k = Ed25519PrivateKey.from_private_bytes(semilla).public_key()
    return k.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()


def texto(origin, h, through):
    return ("nucleo.org/erasure-authorization@v1\n"
            "origin %s\nerased_payload_hash %s\nthrough %d\n" % (origin, h, through)).encode("utf-8")


def firma(semilla, origin, h, through):
    digest = hashlib.sha256(texto(origin, h, through)).digest()
    return Ed25519PrivateKey.from_private_bytes(semilla).sign(digest).hex()


def cid(through, sig):
    return "nucleo-erasure-auth@v1:%d:%s" % (through, sig)


SIG = firma(SEMILLA, ORIGIN, H, THROUGH)
CID = cid(THROUGH, SIG)
evento = ('{"erased_payload_hash":"%s"}' % H).encode()

principal = {
    "description": "La autorización de PROTOCOL §5.1 para un contenido, calculada fuera del código.",
    "seed": SEMILLA.hex(),
    "public_key": pub(SEMILLA),
    "origin": ORIGIN,
    "erased_payload_hash": H,
    "through": THROUGH,
    "message": texto(ORIGIN, H, THROUGH).decode(),
    "message_sha256": hashlib.sha256(texto(ORIGIN, H, THROUGH)).hexdigest(),
    "signature": SIG,
    "payload_cid": CID,
    "event_payload_hash": hashlib.sha256(evento).hexdigest(),
}

CASOS = []


def c(nombre, valido, desc, cid_=CID, origin=ORIGIN, h=H, clave=None):
    CASOS.append({"name": nombre, "description": desc, "public_key": clave or pub(SEMILLA),
                  "origin": origin, "erased_payload_hash": h, "payload_cid": cid_, "valid": valido})


c("valida", True, "La autorización principal.")
c("valida-through-0", True, "through 0, sin ceros a la izquierda.",
  cid_=cid(0, firma(SEMILLA, ORIGIN, H, 0)))
c("valida-through-maximo", True, "through 2^53 − 1, el índice máximo de PROTOCOL §1.",
  cid_=cid(2**53 - 1, firma(SEMILLA, ORIGIN, H, 2**53 - 1)))
c("invalida-otra-clave", False, "Firmada por otra clave: la política dice otra erasureKey.",
  cid_=cid(THROUGH, firma(OTRA, ORIGIN, H, THROUGH)))
c("invalida-verificada-con-otra-clave", False, "La firma buena, verificada con la clave de otra política.",
  clave=pub(OTRA))
c("invalida-otro-hash", False, "La firma de otro contenido presentada para este.", h=H2)
c("invalida-otro-origin", False, "La firma de otro log.", origin="nucleoledger.com/otra-empresa")
c("invalida-otro-through", False, "El through del payload_cid no es el que se firmó.",
  cid_=cid(THROUGH + 1, SIG))
c("invalida-none", False, "El payload_cid de 0.6-draft: sin autorización.", cid_="none://")
c("invalida-vacia", False, "payload_cid vacío.", cid_="")
c("invalida-firma-mayusculas", False, "Firma en hexadecimal en mayúsculas: segunda representación.",
  cid_=cid(THROUGH, SIG.upper()))
c("invalida-firma-127", False, "Firma de 127 caracteres.", cid_=cid(THROUGH, SIG[:127]))
c("invalida-firma-129", False, "Firma de 129 caracteres.", cid_=cid(THROUGH, SIG + "0"))
c("invalida-through-cero-a-la-izquierda", False, "through 07.",
  cid_="nucleo-erasure-auth@v1:07:" + firma(SEMILLA, ORIGIN, H, 7))
c("invalida-through-negativo", False, "through -1.", cid_="nucleo-erasure-auth@v1:-1:" + SIG)
c("invalida-through-demasiado-grande", False, "through 2^53, por encima del índice máximo.",
  cid_=cid(2**53, firma(SEMILLA, ORIGIN, H, 2**53)))
c("invalida-through-vacio", False, "Sin through.", cid_="nucleo-erasure-auth@v1::" + SIG)
c("invalida-prefijo-v2", False, "Otra versión del prefijo.", cid_=CID.replace("@v1:", "@v2:"))
c("invalida-espacio-final", False, "Un espacio al final.", cid_=CID + " ")
c("invalida-campo-de-mas", False, "Un campo más.", cid_=CID + ":00")

# ---- la segunda clave (ADR-033): la misma autorización, firmada con la semilla 202122…3f ----
segunda = {
    "description": "La autorización de PROTOCOL §5.1 sobre el mismo texto, con la segunda clave: "
                   "la clave nueva de una rotación (ADR-033).",
    "seed": OTRA.hex(),
    "public_key": pub(OTRA),
    "origin": ORIGIN,
    "erased_payload_hash": H,
    "through": THROUGH,
    "message": texto(ORIGIN, H, THROUGH).decode(),
    "message_sha256": hashlib.sha256(texto(ORIGIN, H, THROUGH)).hexdigest(),
    "signature": firma(OTRA, ORIGIN, H, THROUGH),
    "payload_cid": cid(THROUGH, firma(OTRA, ORIGIN, H, THROUGH)),
    "event_payload_hash": hashlib.sha256(evento).hexdigest(),
}

# ---- la rotación (ADR-033 §C y decisiones 2 y 4) ----
# A es la clave retirada (corte 41), B la actual, C una que la política no lista.
# Cada caso es una cadena DISPERSA: solo se listan los bloques cuyo contenido importa;
# los demás índices tienen contenido que no coincide con ninguno de estos y no son
# eventos de supresión. Las firmas las hace `cryptography`; los VEREDICTOS
# ("expected") están escritos a mano, caso por caso, leyendo §C y la decisión 4: no
# los calcula ninguna línea de este script.
CLAVE_A, CLAVE_B, CLAVE_C = SEMILLA, OTRA, bytes(range(64, 96))
A, B, C = pub(CLAVE_A), pub(CLAVE_B), pub(CLAVE_C)
H3 = "dd7e84d010aed28a416e928f50c4c09ac0f94a8f5b346548168bddb61cdb7263"


def ev_hash(h):
    return hashlib.sha256(('{"erased_payload_hash":"%s"}' % h).encode()).hexdigest()


def registro(index, h):
    return {"index": index, "type": "registro", "payload_hash": h}


def suprime(index, semilla, h, through):
    return {"index": index, "type": "nucleo.erasure.v1", "payload_hash": ev_hash(h),
            "payload_cid": cid(through, firma(semilla, ORIGIN, h, through))}


ROTADA = {"erasureKey": B, "retiredErasureKeys": {A: 41}}
SIN_ACTUAL = {"retiredErasureKeys": {A: 41}}


def actual(index):
    return {"index": index, "authorized": True, "authorized_by": "erasureKey", "key": B, "reason": ""}


def retirada(index):
    return {"index": index, "authorized": True, "authorized_by": "retiredErasureKeys", "key": A, "reason": ""}


def no(index, motivo):
    return {"index": index, "authorized": False, "authorized_by": None, "key": None, "reason": motivo}


ROTACION = []


def r(nombre, desc, politica, bloques, eventos, erased, missing, findings, regularized):
    ROTACION.append({
        "name": nombre, "description": desc, "policy": politica, "blocks": bloques,
        "expected": {"events": eventos, "erased": erased, "missing": missing,
                     "findings": findings, "regularized": regularized},
    })


# Las seis filas de la tabla de ADR-033 («Los tests y los vectores»).
r("a-40", "Evento 40 firmado con A, retirada con corte 41: autorizado.", ROTADA,
  [registro(10, H), suprime(40, CLAVE_A, H, 10)],
  [retirada(40)], [{"index": 10, "erased_by": 40}], [], [], [])
r("a-41-borde", "Evento 41 firmado con A: el corte es incluido, autorizado.", ROTADA,
  [registro(10, H), suprime(41, CLAVE_A, H, 10)],
  [retirada(41)], [{"index": 10, "erased_by": 41}], [], [], [])
r("a-42-despues-del-corte", "Evento 42 firmado con A: después del corte, no autorizado; el bloque falta.", ROTADA,
  [registro(10, H), suprime(42, CLAVE_A, H, 10)],
  [no(42, "retired_after_cutoff")], [], [10], [42], [])
r("b-20-sin-desde", "Evento 20 firmado con B, la actual: autorizado, la clave actual no tiene «desde».", ROTADA,
  [registro(10, H), suprime(20, CLAVE_B, H, 10)],
  [actual(20)], [{"index": 10, "erased_by": 20}], [], [], [])
r("b-42", "Evento 42 firmado con B: autorizado.", ROTADA,
  [registro(10, H), suprime(42, CLAVE_B, H, 10)],
  [actual(42)], [{"index": 10, "erased_by": 42}], [], [], [])
r("c-42-otra-clave", "Evento 42 firmado con C, ni actual ni retirada: no autorizado.", ROTADA,
  [registro(10, H), suprime(42, CLAVE_C, H, 10)],
  [no(42, "unknown_key")], [], [10], [42], [])

# Decisión 2: retiredErasureKeys sin erasureKey.
r("sin-erasurekey-a-40", "Sin erasureKey, evento 40 firmado con A: lo suprimido hasta el corte sigue contando.",
  SIN_ACTUAL, [registro(10, H), suprime(40, CLAVE_A, H, 10)],
  [retirada(40)], [{"index": 10, "erased_by": 40}], [], [], [])
r("sin-erasurekey-b-42", "Sin erasureKey, evento 42 firmado con B: B no está en la política, no autorizado.",
  SIN_ACTUAL, [registro(10, H), suprime(42, CLAVE_B, H, 10)],
  [no(42, "unknown_key")], [], [10], [42], [])

# Decisión 4: la regularización. E es el evento no autorizado; R el que lo regulariza.
r("regulariza-50", "E en 42 firmado con A (después del corte) y R en 50 autorizado con B para el mismo "
  "contenido: E no autorizado, regularizado en el evento 50; no es hallazgo.", ROTADA,
  [registro(10, H), suprime(42, CLAVE_A, H, 10), suprime(50, CLAVE_B, H, 10)],
  [no(42, "retired_after_cutoff"), actual(50)], [{"index": 10, "erased_by": 50}], [], [],
  [{"index": 42, "regularized_by": 50}])
r("regulariza-el-de-menor-indice", "Dos R, en 50 y en 60: se nombra el de menor índice.", ROTADA,
  [registro(10, H), suprime(42, CLAVE_A, H, 10), suprime(50, CLAVE_B, H, 10), suprime(60, CLAVE_B, H, 10)],
  [no(42, "retired_after_cutoff"), actual(50), actual(60)], [{"index": 10, "erased_by": 50}], [], [],
  [{"index": 42, "regularized_by": 50}])
r("regulariza-con-clave-retirada", "E en 30 firmado con C y R en 40 firmado con A, dentro de su corte: R vale "
  "con las claves de SU índice, y regulariza.", ROTADA,
  [registro(10, H), suprime(30, CLAVE_C, H, 10), suprime(40, CLAVE_A, H, 10)],
  [no(30, "unknown_key"), retirada(40)], [{"index": 10, "erased_by": 40}], [], [],
  [{"index": 30, "regularized_by": 40}])
r("no-regulariza-r-no-autorizado", "Condición 1: R en 50 firmado con C tampoco está autorizado.", ROTADA,
  [registro(10, H), suprime(42, CLAVE_A, H, 10), suprime(50, CLAVE_C, H, 10)],
  [no(42, "retired_after_cutoff"), no(50, "unknown_key")], [], [10], [42, 50], [])
r("no-regulariza-r-anterior", "Condición 2: R autorizado con B en 30, ANTES de E en 42: no regulariza; E sigue "
  "siendo hallazgo y el bloque 10 cuenta como suprimido por R.", ROTADA,
  [registro(10, H), suprime(30, CLAVE_B, H, 10), suprime(42, CLAVE_A, H, 10)],
  [actual(30), no(42, "retired_after_cutoff")], [{"index": 10, "erased_by": 30}], [], [42], [])
r("no-regulariza-otro-contenido", "Condición 3: R suprime otro contenido (el del bloque 11).", ROTADA,
  [registro(10, H), registro(11, H2), suprime(42, CLAVE_A, H, 10), suprime(50, CLAVE_B, H2, 11)],
  [no(42, "retired_after_cutoff"), actual(50)], [{"index": 11, "erased_by": 50}], [10], [42], [])
r("no-regulariza-through-corto", "Condición 4: dos copias del contenido, en 10 y en 35; R tiene through 20 y no "
  "cubre la de 35. El through 35 de E no cuenta: su autorización no vale.", ROTADA,
  [registro(10, H), registro(35, H), suprime(42, CLAVE_A, H, 35), suprime(50, CLAVE_B, H, 20)],
  [no(42, "retired_after_cutoff"), actual(50)], [{"index": 10, "erased_by": 50}], [35], [42], [])
r("no-regulariza-sin-contenido-previo", "E en 42, firmado con B, no suprime ningún contenido anterior (el único "
  "bloque con ese contenido es el 45): no hay supresión que regularizar, aunque R en 50 suprima el 45.", ROTADA,
  [suprime(42, CLAVE_B, H3, 41), registro(45, H3), suprime(50, CLAVE_B, H3, 45)],
  [no(42, "no_erased_block"), actual(50)], [{"index": 45, "erased_by": 50}], [], [42], [])

rotacion = {
    "description": "La rotación de la clave de supresión (PROTOCOL 0.8-draft §5.1, ADR-033): qué clave vale "
                   "para qué evento, y la regularización. Cadenas dispersas: solo están los bloques cuyo "
                   "contenido importa; los demás índices no coinciden con ninguno y no son eventos. Las firmas, "
                   "con cryptography; los veredictos, escritos a mano.",
    "origin": ORIGIN,
    "keys": {
        "A": {"seed": CLAVE_A.hex(), "public_key": A, "role": "retirada, corte 41"},
        "B": {"seed": CLAVE_B.hex(), "public_key": B, "role": "actual (erasureKey)"},
        "C": {"seed": CLAVE_C.hex(), "public_key": C, "role": "ni actual ni retirada"},
    },
    "reasons": {
        "retired_after_cutoff": "firmado con una clave retirada cuyo corte es menor que el índice del evento",
        "unknown_key": "la firma no verifica con ninguna clave de la política",
        "no_erased_block": "ningún bloque anterior al evento tiene el contenido que dice suprimir",
    },
    "cases": ROTACION,
}

if __name__ == "__main__":
    for f in os.listdir(AQUI):
        if f.endswith(".json"):
            os.remove(os.path.join(AQUI, f))
    for nombre, obj in [("autorizacion", principal), ("casos", {"cases": CASOS}),
                        ("autorizacion-segunda-clave", segunda), ("rotacion", rotacion)]:
        with open(os.path.join(AQUI, nombre + ".json"), "w", encoding="utf-8", newline="\n") as fh:
            json.dump(obj, fh, ensure_ascii=False, indent=2)
            fh.write("\n")
    print("2 autorizaciones,", len(CASOS), "casos;", sum(1 for x in CASOS if x["valid"]), "válidos;",
          len(ROTACION), "casos de rotación")
