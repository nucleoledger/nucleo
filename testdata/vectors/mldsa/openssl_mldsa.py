"""ML-DSA-44 desde OpenSSL 3.5.9: la implementación INDEPENDIENTE de los vectores.

Lo importan los dos oráculos que necesitan ML-DSA —mldsa/generar.py y receipt/generar.py— y
mldsa/acvp.py. No implementa nada de FIPS 204: le pide a `openssl` que genere la clave desde
una semilla, que firme en modo determinista y que verifique (ADR-034, decisión 7; ADR-024,
enmienda del 2026-10-24). Escribir ML-DSA en Python es justo lo que ADR-024 descartó.

El openssl es el de ~/.local/opt/openssl-3.5.9, o el de $NUCLEO_OPENSSL. Tiene que decir
que es la 3.5.9: otra versión podría firmar igual, pero los vectores se generaron con esta y
el CI compila esta.
"""

import os, subprocess, tempfile

VERSION = "3.5.9"
RUTA_POR_DEFECTO = os.path.expanduser(f"~/.local/opt/openssl-{VERSION}/bin/openssl")
INSTALA = "./scripts/instala-openssl.sh"

SEMILLA = 32
PUBLICA = 1312
FIRMA = 2420

# La cabecera DER de un SubjectPublicKeyInfo de ML-DSA-44 (RFC 9881: id-ml-dsa-44,
# 2.16.840.1.101.3.4.3.17, sin parámetros), seguida de los 1312 bytes de pkEncode. Es fija
# porque la longitud de la clave lo es; se comprueba en cada clave que sale de OpenSSL.
SPKI = bytes.fromhex("30820532300b06096086480165030403110382052100")

_ruta = None


def openssl():
    """La ruta del openssl 3.5.9, o SystemExit con la orden que lo instala."""
    global _ruta
    if _ruta:
        return _ruta
    ruta = os.environ.get("NUCLEO_OPENSSL") or RUTA_POR_DEFECTO
    falta = (f"hace falta OpenSSL {VERSION} en {ruta} (o en $NUCLEO_OPENSSL), la implementación "
             f"independiente de ML-DSA-44 de los vectores. Instálalo, desde la raíz del repositorio, con:\n"
             f"  {INSTALA}")
    if os.environ.get("NUCLEO_OPENSSL"):
        falta += "\ny quita NUCLEO_OPENSSL, que apunta a otro sitio: unset NUCLEO_OPENSSL"
    if not os.access(ruta, os.X_OK):
        raise SystemExit(falta)
    version = subprocess.run([ruta, "version"], capture_output=True, text=True).stdout
    if not version.startswith(f"OpenSSL {VERSION} "):
        raise SystemExit(f"{ruta} dice {version.strip()!r}, y los vectores son de OpenSSL {VERSION}.\n" + falta)
    _ruta = ruta
    return ruta


def version():
    return subprocess.run([openssl(), "version"], capture_output=True, text=True, check=True).stdout.strip()


def _corre(args, entrada=None):
    return subprocess.run([openssl()] + args, input=entrada, capture_output=True)


def _clave_privada(dir_, semilla):
    if len(semilla) != SEMILLA:
        raise ValueError("una semilla de ML-DSA tiene 32 bytes")
    pem = os.path.join(dir_, "clave.pem")
    r = _corre(["genpkey", "-algorithm", "ML-DSA-44", "-pkeyopt", "hexseed:" + semilla.hex(), "-out", pem])
    if r.returncode != 0:
        raise SystemExit("openssl genpkey falló: " + r.stderr.decode(errors="replace"))
    return pem


def publica(semilla):
    """Los 1312 bytes de la clave pública que deriva la semilla (ML-DSA.KeyGen_internal)."""
    with tempfile.TemporaryDirectory() as d:
        r = _corre(["pkey", "-in", _clave_privada(d, semilla), "-pubout", "-outform", "DER"])
    if r.returncode != 0:
        raise SystemExit("openssl pkey falló: " + r.stderr.decode(errors="replace"))
    der = r.stdout
    if len(der) != len(SPKI) + PUBLICA or not der.startswith(SPKI):
        raise SystemExit("openssl devolvió una clave pública que no es la SPKI de ML-DSA-44")
    return der[len(SPKI):]


def firma(semilla, mensaje, contexto=b""):
    """ML-DSA.Sign determinista (rnd = 0^32), variante pura, con ese contexto."""
    with tempfile.TemporaryDirectory() as d:
        msg = os.path.join(d, "mensaje")
        with open(msg, "wb") as fh:
            fh.write(mensaje)
        args = ["pkeyutl", "-sign", "-rawin", "-inkey", _clave_privada(d, semilla), "-in", msg,
                "-pkeyopt", "deterministic:1"]
        if contexto:
            args += ["-pkeyopt", "hexcontext-string:" + contexto.hex()]
        r = _corre(args)
    if r.returncode != 0 or len(r.stdout) != FIRMA:
        raise SystemExit("openssl pkeyutl -sign falló: " + r.stderr.decode(errors="replace"))
    return r.stdout


def verifica(pub, mensaje, sig, contexto=b""):
    """ML-DSA.Verify, variante pura, con ese contexto: True, False, o SystemExit si openssl
    no da ni lo uno ni lo otro (una clave que no carga no es un «no verifica»)."""
    with tempfile.TemporaryDirectory() as d:
        rutas = {}
        for nombre, datos in (("pub.der", SPKI + pub), ("mensaje", mensaje), ("firma", sig)):
            rutas[nombre] = os.path.join(d, nombre)
            with open(rutas[nombre], "wb") as fh:
                fh.write(datos)
        args = ["pkeyutl", "-verify", "-rawin", "-pubin", "-keyform", "DER", "-inkey", rutas["pub.der"],
                "-in", rutas["mensaje"], "-sigfile", rutas["firma"]]
        if contexto:
            args += ["-pkeyopt", "hexcontext-string:" + contexto.hex()]
        r = _corre(args)
    salida = r.stdout + r.stderr
    if r.returncode == 0 and b"Signature Verified Successfully" in salida:
        return True
    if r.returncode == 1 and b"Signature Verification Failure" in salida:
        return False
    raise SystemExit("openssl pkeyutl -verify no dio veredicto: " + salida.decode(errors="replace"))
