#!/usr/bin/env python3
# Genera los vectores de la AUTORIZACIÓN DE SUPRESIÓN (PROTOCOL.md §5.1, ADR-032).
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

if __name__ == "__main__":
    for f in os.listdir(AQUI):
        if f.endswith(".json"):
            os.remove(os.path.join(AQUI, f))
    for nombre, obj in [("autorizacion", principal), ("casos", {"cases": CASOS})]:
        with open(os.path.join(AQUI, nombre + ".json"), "w", encoding="utf-8", newline="\n") as fh:
            json.dump(obj, fh, ensure_ascii=False, indent=2)
            fh.write("\n")
    print("1 autorización y", len(CASOS), "casos;", sum(1 for x in CASOS if x["valid"]), "válidos")
