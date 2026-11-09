#!/usr/bin/env python3
"""El subconjunto sigVer del ACVP del NIST para ML-DSA-44: la referencia OFICIAL.

ADR-034, decisión 7: los vectores de OpenSSL dicen qué hace una implementación
independiente; estos dicen qué manda el NIST. Se extraen de usnistgov/ACVP-Server, en un
commit FIJADO, del fichero gen-val/json-files/ML-DSA-sigVer-FIPS204/internalProjection.json
(el único de los tres que trae a la vez la clave, el mensaje, el contexto, la firma y el
veredicto), cuyo sha256 también se fija. El filtro es el de Núcleo: ML-DSA-44, interfaz
externa, variante pura (sin prehash) y contexto VACÍO.

Aparte, en su propio fichero (Sprint 31), el grupo CON CONTEXTO: los mismos filtros con el
contexto NO vacío, cada caso verificado con su contexto. Núcleo no lo usa —firma y verifica
con el contexto vacío (PROTOCOL §3.3)—; está para que el núcleo del verificador, Go y
OpenSSL, dé el veredicto del NIST también donde el contexto cambia el mensaje firmado. El
subconjunto de contexto vacío no cambia: ni un byte, ni su sha256.

    python3 testdata/vectors/mldsa/acvp.py --extraer   # baja el fichero del commit y reescribe
    python3 testdata/vectors/mldsa/acvp.py --check     # sin red: sha256 del subconjunto y
                                                       # el veredicto de OpenSSL en cada caso

--check falla si el subconjunto no tiene el sha256 fijado o si OpenSSL no da en algún caso
el veredicto del NIST. Lo corren el CI (job mldsa-vectores) y la compuerta.
"""

import hashlib, json, os, sys, urllib.request

AQUI = os.path.dirname(os.path.abspath(__file__))
# Sin __pycache__/ dentro de testdata/: dejaría el árbol sucio después de cada --check.
sys.dont_write_bytecode = True
sys.path.insert(0, AQUI)
import openssl_mldsa as om  # noqa: E402

REPOSITORIO = "https://github.com/usnistgov/ACVP-Server"
COMMIT = "a7f283cdc87d2d6dd93c1bac59e5622c5f9f8324"
RUTA = "gen-val/json-files/ML-DSA-sigVer-FIPS204/internalProjection.json"
FUENTE_SHA256 = "47cdd6314c7f746d02421ffcba89d4dbc7bb875ac49e07a029fdfc26fba55437"
URL = f"https://raw.githubusercontent.com/usnistgov/ACVP-Server/{COMMIT}/{RUTA}"

SALIDA = os.path.join(AQUI, "acvp-sigver-mldsa44.json")
# El sha256 del subconjunto tal como está en el repositorio. Si --extraer produce otra cosa
# —otro filtro, otro formato—, hay que cambiarlo aquí, a la vista.
SUBCONJUNTO_SHA256 = "8e4a9375b883ba5a1d1d86954dc4f0358e6d17b53730ae3a71aed596ff3131c8"

# El grupo con contexto (Sprint 31): otro fichero, con su propio sha256 fijado.
SALIDA_CONTEXTO = os.path.join(AQUI, "acvp-sigver-mldsa44-con-contexto.json")
SUBCONJUNTO_CONTEXTO_SHA256 = "2038ddc698711dbc9351bb3643acf948b05edfe27bb4665e1671a903888f26b8"


def extrae_con_contexto(fuente):
    """Los casos ML-DSA-44 puros de interfaz externa con contexto NO vacío."""
    if hashlib.sha256(fuente).hexdigest() != FUENTE_SHA256:
        raise SystemExit(f"{RUTA} no tiene el sha256 fijado ({FUENTE_SHA256})")
    datos = json.loads(fuente)
    casos = []
    for g in datos["testGroups"]:
        if (g.get("parameterSet"), g.get("signatureInterface"), g.get("preHash"), g.get("externalMu")) != \
                ("ML-DSA-44", "external", "pure", False):
            continue
        for t in g["tests"]:
            if t.get("context", "") == "":
                continue
            casos.append({
                "tgId": g["tgId"],
                "tcId": t["tcId"],
                "pk": t["pk"],
                "message": t["message"],
                "context": t["context"],
                "signature": t["signature"],
                "testPassed": t["testPassed"],
                "reason": t["reason"],
            })
    return {
        "description": "Con contexto: Núcleo no lo usa. Subconjunto sigVer del ACVP del NIST: ML-DSA-44, "
                       "interfaz externa, variante pura, contexto NO vacío; cada caso se verifica con su "
                       "contexto. Hex tal como viene del NIST (mayúsculas). Ver acvp.py.",
        "source": {"repository": REPOSITORIO, "commit": COMMIT, "path": RUTA, "sha256": FUENTE_SHA256},
        "filter": {"parameterSet": "ML-DSA-44", "signatureInterface": "external", "preHash": "pure",
                   "externalMu": False, "context": "no vacío"},
        "tests": casos,
    }


def extrae(fuente):
    if hashlib.sha256(fuente).hexdigest() != FUENTE_SHA256:
        raise SystemExit(f"{RUTA} no tiene el sha256 fijado ({FUENTE_SHA256})")
    datos = json.loads(fuente)
    if (datos.get("algorithm"), datos.get("mode"), datos.get("revision")) != ("ML-DSA", "sigVer", "FIPS204"):
        raise SystemExit("el fichero no es el sigVer FIPS204 de ML-DSA")
    casos = []
    for g in datos["testGroups"]:
        if (g.get("parameterSet"), g.get("signatureInterface"), g.get("preHash"), g.get("externalMu")) != \
                ("ML-DSA-44", "external", "pure", False):
            continue
        for t in g["tests"]:
            if t.get("context", None) != "":
                continue
            casos.append({
                "tgId": g["tgId"],
                "tcId": t["tcId"],
                "pk": t["pk"],
                "message": t["message"],
                "context": t["context"],
                "signature": t["signature"],
                "testPassed": t["testPassed"],
                "reason": t["reason"],
            })
    return {
        "description": "Subconjunto sigVer del ACVP del NIST: ML-DSA-44, interfaz externa, variante pura, "
                       "contexto vacío. Hex tal como viene del NIST (mayúsculas). Ver acvp.py.",
        "source": {"repository": REPOSITORIO, "commit": COMMIT, "path": RUTA, "sha256": FUENTE_SHA256},
        "filter": {"parameterSet": "ML-DSA-44", "signatureInterface": "external", "preHash": "pure",
                   "externalMu": False, "context": ""},
        "tests": casos,
    }


def comprueba():
    codigo = comprueba_fichero(SALIDA, SUBCONJUNTO_SHA256, "")
    return codigo or comprueba_fichero(SALIDA_CONTEXTO, SUBCONJUNTO_CONTEXTO_SHA256, "con contexto, ")


def comprueba_fichero(salida, fijado, rotulo):
    crudo = open(salida, "rb").read()
    if hashlib.sha256(crudo).hexdigest() != fijado:
        print(f"{os.path.basename(salida)} no tiene el sha256 fijado en acvp.py ({fijado})",
              file=sys.stderr)
        return 1
    datos = json.loads(crudo)
    mal = []
    for t in datos["tests"]:
        dice = om.verifica(bytes.fromhex(t["pk"]), bytes.fromhex(t["message"]), bytes.fromhex(t["signature"]),
                           bytes.fromhex(t["context"]))
        if dice != t["testPassed"]:
            mal.append(f"tcId {t['tcId']}: el NIST dice {t['testPassed']} ({t['reason']}) y OpenSSL {dice}")
    if mal:
        print("OpenSSL NO da el veredicto del NIST:\n  " + "\n  ".join(mal), file=sys.stderr)
        return 1
    print(f"{len(datos['tests'])} casos sigVer del ACVP ({rotulo}commit {COMMIT[:8]}): OpenSSL da el veredicto del NIST")
    return 0


def main():
    if "--check" in sys.argv:
        return comprueba()
    if "--extraer" in sys.argv:
        with urllib.request.urlopen(URL, timeout=60) as r:
            fuente = r.read()
        for salida, datos in ((SALIDA, extrae(fuente)), (SALIDA_CONTEXTO, extrae_con_contexto(fuente))):
            texto = json.dumps(datos, ensure_ascii=False, indent=2) + "\n"
            with open(salida, "w", encoding="utf-8", newline="\n") as fh:
                fh.write(texto)
            print(f"{os.path.basename(salida)}: {len(datos['tests'])} casos escritos; sha256 "
                  f"{hashlib.sha256(texto.encode()).hexdigest()}")
        return 0
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
