#!/usr/bin/env python3
# Genera los vectores del EVENTO DE ANULACIÓN (PROTOCOL 0.9-draft §5.2, ADR-035):
# payload.json, cid.json y reconcile.json.
#
# Implementación independiente: el payload se construye aquí a mano desde §5.2 (JCS de dos
# cadenas, que para estos miembros ASCII es json.dumps con sort_keys y sin espacios), los
# headers de los bloques desde §1 (JCS, SHA-256), y las firmas Ed25519 —la del tenant en cada
# bloque y la de la clave de supresión en las autorizaciones de §5.1— las hace la biblioteca
# `cryptography` de Python. Ninguna línea usa el código de Núcleo. Los SHA-256 de los payloads
# válidos se contrastan además con `sha256sum`, y el de la decisión 3 de ADR-035 tiene que ser
# el que la ADR ya publicó (109 bytes, 33e90e55…).
#
# Los VEREDICTOS están escritos a mano, escenario por escenario, desde §5.2: este script no
# implementa las reglas R1–R6, solo calcula hashes y firmas y rellena, de la cadena, el
# sealed_hash y los tiempos de cada entrada de `voided`.
#
#   python3 testdata/vectors/void/generar.py          # reescribe
#   python3 testdata/vectors/void/generar.py --check  # compara sin escribir
import hashlib, json, os, shutil, subprocess, sys
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

AQUI = os.path.dirname(os.path.abspath(__file__))
REQUIRES = "0.9-draft"

# Las semillas de testdata/vectors/erasure/: A es la clave de supresión (erasureKey) y C, que
# allí no es de nadie, firma los bloques como clave del tenant. PROTOCOL §3.2 exige que
# erasureKey y signerKey sean distintas.
SEMILLA_SUPRESION = bytes(range(32))           # A: 000102…1f
SEMILLA_TENANT = bytes(range(64, 96))          # C: 404142…5f
ORIGIN = "nucleoledger.com/mi-empresa"
TENANT = "0999999999001"                       # un RUC de prueba, que no es de nadie
OTRO_TENANT = "0988888888001"
H = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"  # SHA-256 de ""
MAX = 2**53 - 1

# Los motivos de ADR-035, decisión 5, tal como los dirá la reconciliación.
MOTIVOS = {
    "R1": "el payload_cid de la anulación no tiene la forma nucleo-void@v1:<índice>",
    "R2": "la anulación apunta a un bloque que no es anterior a ella",
    "R3": "la anulación no corresponde al contenido del bloque %s",
    "R4": "no se anula un evento de Núcleo",
    "R5": "la anulación es de otro tenant que la emisión",
}
INVALIDA = "anulación inválida"
REPETIDA = "anulación repetida"
DESCONOCIDO = "evento de Núcleo desconocido"


def sha(b):
    return hashlib.sha256(b).hexdigest()


def pub(semilla):
    k = Ed25519PrivateKey.from_private_bytes(semilla).public_key()
    return k.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()


def jcs(obj):
    # Basta para lo que aquí se serializa: claves y cadenas ASCII y enteros pequeños. No es
    # un JCS general (RFC 8785 §3.2.2.3 para números, §3.2.3 para el orden UTF-16).
    s = json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    assert s.isascii()
    return s.encode("utf-8")


def payload(i, h):
    return jcs({"voided_index": str(i), "voided_payload_hash": h})


def segunda_opinion(b):
    if shutil.which("sha256sum") is None:
        sys.exit("generar.py: hace falta sha256sum (coreutils) para la segunda opinión")
    out = subprocess.run(["sha256sum"], input=b, capture_output=True, check=True).stdout
    return out.split()[0].decode()


# ---------------------------------------------------------------- payload.json

def caso_valido(nombre, desc, i, h):
    b = payload(i, h)
    d = sha(b)
    assert segunda_opinion(b) == d, nombre
    return {"name": nombre, "description": desc, "voided_index": str(i),
            "voided_payload_hash": h, "payload": b.decode(), "payload_length": len(b),
            "payload_sha256": d}


H2 = sha(b"<factura>2</factura>")
VALIDOS = [
    caso_valido("decision-3", "El vector de ADR-035, decisión 3, y de PROTOCOL §5.2.", 3, H),
    caso_valido("indice-0", "El bloque 0 es un bloque como los demás.", 0, H),
    caso_valido("indice-maximo", "2^53 − 1, el índice máximo de PROTOCOL §1.", MAX, H),
    caso_valido("otro-hash", "Otro payload_hash cualquiera.", 3, H2),
]
assert VALIDOS[0]["payload_length"] == 109
assert VALIDOS[0]["payload_sha256"] == "33e90e55d607b81ef2ed49ce302023676d443c424a8bc77506dd3b5c8ae72143"


def caso_invalido(nombre, texto, motivo):
    b = texto.encode("utf-8")
    d = sha(b)
    assert d not in {v["payload_sha256"] for v in VALIDOS}, nombre
    return {"name": nombre, "payload": texto, "payload_sha256": d, "reason": motivo}


INVALIDOS = [
    caso_invalido("indice-numero", '{"voided_index":3,"voided_payload_hash":"%s"}' % H,
                  "voided_index es un número JSON: §5.2 lo exige cadena"),
    caso_invalido("indice-cero-a-la-izquierda", '{"voided_index":"03","voided_payload_hash":"%s"}' % H,
                  "voided_index no tiene la forma 0|[1-9][0-9]*"),
    caso_invalido("indice-2-53", '{"voided_index":"9007199254740992","voided_payload_hash":"%s"}' % H,
                  "voided_index pasa de 2^53 − 1"),
    caso_invalido("hash-mayusculas", '{"voided_index":"3","voided_payload_hash":"%s"}' % H.upper(),
                  "voided_payload_hash no está en hexadecimal en minúscula"),
    caso_invalido("miembro-de-mas",
                  '{"reason":"error","voided_index":"3","voided_payload_hash":"%s"}' % H,
                  "un miembro de más: el payload tiene exactamente dos"),
    caso_invalido("otro-orden", '{"voided_payload_hash":"%s","voided_index":"3"}' % H,
                  "los miembros en otro orden no son la serialización JCS: otros bytes y otro hash"),
]

PAYLOAD = {
    "description": "El payload del evento de anulación (PROTOCOL 0.9-draft §5.2, ADR-035 decisión 3): "
                   "JCS de exactamente dos cadenas. Los válidos, con sus bytes, su longitud y su SHA-256 "
                   "(Python y sha256sum). Los inválidos, con el SHA-256 de esos bytes: un evento cuyo "
                   "payload_hash es uno de ellos no corresponde al contenido del bloque (R3).",
    "requires": REQUIRES,
    "valid": VALIDOS,
    "invalid": INVALIDOS,
}

# ---------------------------------------------------------------- cid.json

CIDS_VALIDOS = [("nucleo-void@v1:0", "0"), ("nucleo-void@v1:3", "3"),
                ("nucleo-void@v1:%d" % MAX, str(MAX))]
CIDS_INVALIDOS = [
    ("nucleo-void@v1:03", "cero a la izquierda"),
    ("nucleo-void@v1:-1", "con signo"),
    ("nucleo-void@v1:9007199254740992", "pasa de 2^53 − 1"),
    ("nucleo-void@v1:", "sin índice"),
    ("nucleo-void@v2:3", "otra versión"),
    ("nucleo-void@v1:3 ", "un espacio de más al final"),
    ("none://", "el payload_cid de un bloque sin blob"),
]
CID = {
    "description": "El payload_cid del evento de anulación (PROTOCOL 0.9-draft §5.2, R1): exactamente "
                   "nucleo-void@v1:<i>, con <i> en 0|[1-9][0-9]* y como mucho 2^53 − 1.",
    "requires": REQUIRES,
    "valid": [{"payload_cid": c, "voided_index": i} for c, i in CIDS_VALIDOS],
    "invalid": [{"payload_cid": c, "description": d, "reason": MOTIVOS["R1"]} for c, d in CIDS_INVALIDOS],
}

# ---------------------------------------------------------------- reconcile.json

PUB_TENANT = pub(SEMILLA_TENANT)
PUB_SUPRESION = pub(SEMILLA_SUPRESION)


class Cadena:
    """Una cadena completa desde el génesis, firmada con la clave del tenant (PROTOCOL §1)."""

    def __init__(self):
        self.bloques = []

    def _sella(self, tipo, ph, cid, tenant=TENANT):
        i = len(self.bloques)
        header = {
            "index": i,
            "prev_hash": self.bloques[-1]["hash"] if self.bloques else "0" * 64,
            "timestamp": "2026-11-23T10:%02d:00Z" % i,
            "tenant": tenant,
            "type": tipo,
            "payload_hash": ph,
            "payload_cid": cid,
            "signer_pubkey": PUB_TENANT,
        }
        digest = hashlib.sha256(jcs(header)).digest()
        firma = Ed25519PrivateKey.from_private_bytes(SEMILLA_TENANT).sign(digest).hex()
        self.bloques.append({"header": header, "hash": digest.hex(), "signature": firma})
        return i

    def registro(self, contenido, tipo="sri.factura.v1"):
        ph = sha(contenido.encode("utf-8"))
        return self._sella(tipo, ph, "blob://" + ph)

    def ph(self, i):
        return self.bloques[i]["header"]["payload_hash"]

    def anulacion(self, i, h=None, cid=None, tenant=TENANT, i_payload=None):
        # i: el índice al que apunta el payload_cid; h: el payload_hash que dice el payload.
        h = self.ph(i) if h is None else h
        ip = i if i_payload is None else i_payload
        return self._sella("nucleo.void.v1", sha(payload(ip, h)),
                           cid if cid is not None else "nucleo-void@v1:%d" % i, tenant)

    def supresion(self, i, through):
        # Una supresión AUTORIZADA por la clave A (PROTOCOL §5.1).
        h = self.ph(i)
        texto = ("nucleo.org/erasure-authorization@v1\norigin %s\nerased_payload_hash %s\n"
                 "through %d\n" % (ORIGIN, h, through)).encode("utf-8")
        firma = Ed25519PrivateKey.from_private_bytes(SEMILLA_SUPRESION).sign(
            hashlib.sha256(texto).digest()).hex()
        return self._sella("nucleo.erasure.v1", sha(jcs({"erased_payload_hash": h})),
                           "nucleo-erasure-auth@v1:%d:%s" % (through, firma))

    def desconocido(self, tipo):
        return self._sella(tipo, sha(b"{}"), "none://")


ESCENARIOS = []


def escenario(nombre, desc, cadena, presentes, cambiados=(), voided=(), erased=(), findings=(),
              codigo=0):
    """voided: pares (bloque anulado, anulación); erased: pares (bloque, evento de supresión);
    findings: diccionarios escritos a mano. Todo esto es el veredicto, y se escribe a mano."""
    b = cadena.bloques
    ESCENARIOS.append({
        "name": nombre,
        "description": desc,
        "blocks": b,
        "live": {"present": list(presentes), "changed": list(cambiados)},
        "expected": {
            "voided": [{"index": i, "sealed_hash": b[i]["header"]["payload_hash"],
                        "sealed_at": b[i]["header"]["timestamp"], "voided_by": v,
                        "voided_at": b[v]["header"]["timestamp"]} for i, v in voided],
            "erased": [{"index": i, "erased_by": e} for i, e in erased],
            "findings": list(findings),
            "exit_code": codigo,
        },
    })


def base(n=4):
    c = Cadena()
    for k in range(n):
        c.registro("<factura>%d</factura>" % k)
    return c


def invalida(i, regla, bloque=None):
    m = MOTIVOS[regla] % bloque if regla == "R3" else MOTIVOS[regla]
    return {"status": INVALIDA, "index": i, "rule": regla, "reason": m}


c = base(); c.anulacion(3)
escenario("valida-factura-presente",
          "Anulación válida de la factura 3, que el sistema vivo conserva igual: verificada y anulada. "
          "El evento (bloque 4) no está en el sistema vivo y no es faltante: es de Núcleo.",
          c, [0, 1, 2, 3], voided=[(3, 4)])

c = base(); c.anulacion(3)
escenario("valida-factura-borrada",
          "Anulación válida, pero el ERP borró la factura: sigue siendo faltante (ADR-035, decisión 6).",
          c, [0, 1, 2], voided=[(3, 4)], findings=[{"status": "faltante", "index": 3}], codigo=2)

c = base(); c.anulacion(3)
escenario("valida-factura-cambiada",
          "Anulación válida, pero el ERP cambió la factura (un estado «anulada» dentro del registro "
          "sellado): discrepancia.",
          c, [0, 1, 2], cambiados=[3], voided=[(3, 4)],
          findings=[{"status": "discrepancia", "index": 3}], codigo=2)

for k, (cid_malo, d) in enumerate(CIDS_INVALIDOS, 1):
    c = base(); c.anulacion(3, cid=cid_malo)
    escenario("r1-cid-%d" % k,
              "R1: el payload_cid es %r (%s); el payload es el bueno para el bloque 3." % (cid_malo, d),
              c, [0, 1, 2, 3], findings=[invalida(4, "R1")], codigo=2)

c = base(); c.anulacion(4, h=H)
escenario("r2-su-propio-indice",
          "R2: el evento 4 apunta al índice 4, el suyo.", c, [0, 1, 2, 3],
          findings=[invalida(4, "R2")], codigo=2)

c = base(); c.anulacion(7, h=H)
escenario("r2-indice-posterior",
          "R2: el evento 4 apunta al índice 7, posterior.", c, [0, 1, 2, 3],
          findings=[invalida(4, "R2")], codigo=2)

c = base(); c.anulacion(3, h=c.ph(2))
escenario("r3-contenido-de-otro-bloque",
          "R3: el payload_cid apunta al 3, pero el payload lleva el payload_hash de la factura 2.",
          c, [0, 1, 2, 3], findings=[invalida(4, "R3", 3)], codigo=2)

c = base(); c.anulacion(3, i_payload=2)
escenario("r3-indice-del-payload-distinto",
          "R3: el payload_cid apunta al 3 y el payload lleva el hash del 3, pero su voided_index dice 2.",
          c, [0, 1, 2, 3], findings=[invalida(4, "R3", 3)], codigo=2)

c = base(2); c.supresion(1, 1); c.anulacion(2)
escenario("r4-anula-una-supresion",
          "R4: se anula el evento de supresión 2 (autorizado, que suprime el registro 1).",
          c, [0], erased=[(1, 2)], findings=[invalida(3, "R4")], codigo=2)

c = base(); c.anulacion(3); c.anulacion(4)
escenario("r4-des-anular",
          "R4: el evento 5 anula la anulación 4. No existe des-anular: la primera sigue valiendo.",
          c, [0, 1, 2, 3], voided=[(3, 4)], findings=[invalida(5, "R4")], codigo=2)

c = base(); c.anulacion(3, tenant=OTRO_TENANT)
escenario("r5-otro-tenant",
          "R5: el evento es de otro tenant que la factura.",
          c, [0, 1, 2, 3], findings=[invalida(4, "R5")], codigo=2)

c = base(); c.anulacion(3); c.anulacion(3)
escenario("r6-repetida",
          "R6: dos anulaciones válidas de la factura 3. Cuenta la primera; la segunda es hallazgo, "
          "con el índice de la primera.",
          c, [0, 1, 2, 3], voided=[(3, 4)],
          findings=[{"status": REPETIDA, "index": 5, "rule": "R6", "first_void": 4}], codigo=2)

c = base(); c.anulacion(3, h=c.ph(2)); c.anulacion(3)
escenario("r6-tras-una-invalida",
          "Una anulación inválida (R3) y después una válida de la misma factura: la válida cuenta, "
          "porque R6 solo mira anulaciones válidas anteriores.",
          c, [0, 1, 2, 3], voided=[(3, 5)], findings=[invalida(4, "R3", 3)], codigo=2)

c = base(2); c.supresion(1, 1); c.anulacion(1)
escenario("suprimida-y-despues-anulada",
          "Se suprime (con autorización) el registro 1 y después se anula: suprimido y anulado.",
          c, [0], voided=[(1, 3)], erased=[(1, 2)])

c = base(2); c.anulacion(1); c.supresion(1, 1)
escenario("anulada-y-despues-suprimida",
          "El orden contrario: se anula el registro 1 y después se suprime.",
          c, [0], voided=[(1, 2)], erased=[(1, 3)])

c = Cadena(); c.registro("<factura>A</factura>"); c.registro("<factura>B</factura>")
c.registro("<factura>A</factura>"); c.anulacion(2)
escenario("mismo-contenido-dos-veces",
          "El mismo contenido sellado en 0 y en 2, y anulada solo la copia 2: la 0 no está anulada.",
          c, [0, 1, 2], voided=[(2, 3)])

c = base(2); c.desconocido("nucleo.algo.v1")
escenario("evento-de-nucleo-desconocido",
          "Un bloque nucleo.algo.v1, que el lector no implementa: hallazgo, ni ignorado ni faltante "
          "(ADR-035, decisión 9).",
          c, [0, 1], findings=[{"status": DESCONOCIDO, "index": 2}], codigo=2)

RECONCILE = {
    "description": "Escenarios de reconciliación con eventos de anulación (PROTOCOL 0.9-draft §5.2, "
                   "ADR-035 decisiones 5 y 6). Cada uno es una cadena completa desde el génesis, con "
                   "sus bloques enteros firmados por la clave del tenant, y el sistema vivo: los índices "
                   "que conserva igual (present), los que conserva cambiados (changed); los demás "
                   "registros no los tiene. Los veredictos están escritos a mano; findings es un "
                   "conjunto, sin orden. voided y erased van siempre, también vacíos (ajuste A1).",
    "requires": REQUIRES,
    "origin": ORIGIN,
    "keys": {
        "tenant": {"seed": SEMILLA_TENANT.hex(), "public_key": PUB_TENANT,
                   "role": "firma los bloques (signerKey)"},
        "erasure": {"seed": SEMILLA_SUPRESION.hex(), "public_key": PUB_SUPRESION,
                    "role": "autoriza las supresiones (erasureKey)"},
    },
    "policy": {"erasureKey": PUB_SUPRESION},
    "statuses": {"invalid": INVALIDA, "repeated": REPETIDA, "unknown": DESCONOCIDO},
    "reasons": MOTIVOS,
    "scenarios": ESCENARIOS,
}


def texto_json(obj):
    return json.dumps(obj, ensure_ascii=False, indent=1) + "\n"


SALIDAS = {"payload.json": PAYLOAD, "cid.json": CID, "reconcile.json": RECONCILE}

if __name__ == "__main__":
    check = "--check" in sys.argv[1:]
    mal = []
    for nombre, obj in SALIDAS.items():
        ruta = os.path.join(AQUI, nombre)
        nuevo = texto_json(obj)
        if check:
            try:
                viejo = open(ruta, encoding="utf-8").read()
            except FileNotFoundError:
                viejo = None
            if viejo != nuevo:
                mal.append(nombre)
        else:
            with open(ruta, "w", encoding="utf-8", newline="\n") as f:
                f.write(nuevo)
    if mal:
        sys.exit("generar.py --check: no coinciden con lo que calcula el generador: " + ", ".join(mal))
    print("void: %d payloads válidos, %d inválidos, %d cid, %d escenarios%s" % (
        len(VALIDOS), len(INVALIDOS), len(CIDS_VALIDOS) + len(CIDS_INVALIDOS), len(ESCENARIOS),
        " (coinciden)" if check else ""))
