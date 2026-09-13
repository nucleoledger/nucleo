#!/usr/bin/env python3
# Vectores golden de la extracción de signer_pubkey del header_json (E.9 del Sprint 7e).
#
# La apertura lee signer_pubkey de CADA bloque para la continuidad del firmante
# (ADR-017). Con json.Unmarshal costaba 1,9 µs por bloque —+35 % en la apertura
# rápida—; la versión rápida lo busca en los bytes. Es segura porque el header_json
# de un bloque verificado ES su forma canónica JCS, y en JCS el miembro aparece una
# vez y no puede aparecer dentro de un valor (las comillas de un valor van escapadas).
#
# Los valores esperados salen de aquí, NO del código Go: los headers canónicos se
# serializan con json.dumps(sort_keys, separators) —JCS para este esquema plano de
# cadenas y enteros— y la clave esperada es la que json.loads extrae. Los casos no
# canónicos esperan error: la regla es "exactamente una aparición del miembro,
# seguida de 64 hexadecimales en minúsculas", y eso está escrito debajo a mano.
#
#   python3 internal/store/testdata/signer/generar.py
import json, os

K = "57857f0ed34d9ab44aad8f122f890075bd60ca3bd9142f787cf91b80a4854f2a"
OTRA = "fc947730f49eb01427a66e050733294d9e520e545c7a27125a780634e0860a27"


def header(**cambios):
    h = {
        "index": 3,
        "payload_cid": "blob://c5b0e7f1",
        "payload_hash": "c5b0e7f18d0d1829df5d6895d1fbac063c5e09af3c5276a9a43d461ef1f8754b",
        "prev_hash": "e29d362566c75076f5388a1c905b2e116cc78bc338b8f2d0931746c2a67ce354",
        "signer_pubkey": K,
        "tenant": "1790012345001",
        "timestamp": "2026-09-07T10:00:00Z",
        "type": "sri.factura.v1",
    }
    h.update(cambios)
    return json.dumps(h, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


casos = []


def valido(nombre, texto):
    esperado = json.loads(texto)["signer_pubkey"]
    casos.append({"name": nombre, "header_json": texto, "signer": esperado})


def invalido(nombre, texto, motivo):
    casos.append({"name": nombre, "header_json": texto, "error": motivo})


valido("canonico", header())
valido("canonico-otra-clave", header(signer_pubkey=OTRA))
valido("tenant-imita-el-miembro", header(tenant='x","signer_pubkey":"' + OTRA))
valido("type-con-unicode", header(type="sri.factura.v1 — núcleo"))
valido("tenant-con-barra-invertida", header(tenant="ACME\\S.A."))
valido("indice-grande", header(index=2**53 + 1))

canon = header()
invalido("miembro-repetido",
         canon.replace('"signer_pubkey":"%s"' % K, '"signer_pubkey":"%s","signer_pubkey":"%s"' % (K, OTRA)),
         "repetido")
invalido("sin-miembro", json.dumps({k: v for k, v in json.loads(canon).items() if k != "signer_pubkey"},
                                   sort_keys=True, separators=(",", ":")), "ausente")
invalido("nombre-con-escape", canon.replace('"signer_pubkey"', '"signer\\u005fpubkey"'), "ausente")
invalido("hex-mayusculas", header(signer_pubkey=K.upper()), "hex")
invalido("hex-63", header(signer_pubkey=K[:63]), "hex")
invalido("hex-65", header(signer_pubkey=K + "0"), "hex")
invalido("valor-no-cadena", canon.replace('"%s"' % K, "12345"), "hex")
invalido("espacio-tras-dos-puntos", canon.replace('"signer_pubkey":"', '"signer_pubkey": "'), "hex")
invalido("vacio", "", "ausente")

here = os.path.dirname(os.path.abspath(__file__))
with open(os.path.join(here, "vectores.json"), "w", encoding="utf-8", newline="\n") as fh:
    json.dump(casos, fh, ensure_ascii=False, indent=2)
    fh.write("\n")
print(len(casos), "casos")
