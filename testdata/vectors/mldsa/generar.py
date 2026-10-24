#!/usr/bin/env python3
"""Vectores ML-DSA-44 (FIPS 204) desde una implementación INDEPENDIENTE: OpenSSL 3.5.9.

ADR-034, «Los vectores»: (clave pública, mensaje, firma, veredicto), con las claves
derivadas de semillas fijas, las firmas DETERMINISTAS (rnd = 0^32), la variante pura y el
contexto vacío, que es lo que firma checkpoint.MLDSASigner (mldsa.Options{}). El veredicto
es el de ML-DSA.Verify con contexto vacío. Ninguna línea de Go entra aquí: lo que vale
cada vector lo dice OpenSSL, y el generador se niega a escribir un vector cuyo veredicto
declarado no sea el que da OpenSSL.

Los negativos: un bit cambiado en cada parte de la firma —c̃, z y las pistas h, en sus
dos zonas: índices y cuentas—, la firma de otra clave, el mensaje cambiado en un byte, la
firma de 2419 y de 2421 bytes, y una firma con contexto NO vacío, que con el contexto vacío
no verifica (la separación de dominios de FIPS 204, §5.2).

Cada caso dice cómo se hizo su firma —semilla, mensaje firmado, contexto— y qué mutación se
le aplicó después. Con eso el test de Go (internal/checkpoint, TestMLDSAVectoresOpenSSL)
comprueba lo que de verdad importa: que crypto/mldsa, con la misma semilla y el mismo
mensaje, firma EXACTAMENTE los mismos bytes, y que da el mismo veredicto.

    python3 testdata/vectors/mldsa/generar.py          # reescribe firmas.json
    python3 testdata/vectors/mldsa/generar.py --check  # falla si difiere (CI y compuerta)
"""

import hashlib, json, os, sys

AQUI = os.path.dirname(os.path.abspath(__file__))
# Sin __pycache__/ dentro de testdata/: dejaría el árbol sucio después de cada --check.
sys.dont_write_bytecode = True
sys.path.insert(0, AQUI)
import openssl_mldsa as om  # noqa: E402

SALIDA = os.path.join(AQUI, "firmas.json")

# La clave A es la del log de los vectores de recibo (semilla 200..231, la misma que
# usaba material/mldsa.json); la B, una segunda clave cualquiera.
SEMILLA_A = bytes(range(200, 232))
SEMILLA_B = bytes(range(100, 132))

NOTA = b"nucleoledger.com/recibos\n5\nq83vEjRWeJCrze8SNFZ4kKvN7xI0VniQq83vEjRWeJA=\n"
LARGO = bytes(i % 251 for i in range(3000))
CONTEXTO = b"nucleo"

# El layout de una firma ML-DSA-44 (FIPS 204, sigEncode; λ = 128, ℓ = 4, γ1 = 2^17, ω = 80,
# k = 4): c̃ (32 bytes) ‖ z (4 polinomios de 256 coeficientes de 18 bits = 2304 bytes) ‖
# h (ω + k = 84 bytes: primero los índices de las pistas, después una cuenta por polinomio).
C_TILDE = (0, 32)
Z = (32, 32 + 2304)
H_INDICES = (2336, 2336 + 80)
H_CUENTAS = (2416, 2420)
assert H_CUENTAS[1] == om.FIRMA


def cambia_bit(sig, byte, bit):
    b = bytearray(sig)
    b[byte] ^= 1 << bit
    return bytes(b)


def casos():
    pub_a, pub_b = om.publica(SEMILLA_A), om.publica(SEMILLA_B)
    claves = {"A": (SEMILLA_A, pub_a), "B": (SEMILLA_B, pub_b)}
    out = []

    def caso(nombre, desc, clave_pub, mensaje, valido, firmante, firmado, contexto=b"", mutacion=None, sig=None):
        semilla = claves[firmante][0]
        if sig is None:
            sig = om.firma(semilla, firmado, contexto)
        original = sig
        if mutacion:
            sig = mutacion[1](sig)
        pub = claves[clave_pub][1]
        dice = om.verifica(pub, mensaje, sig)
        if dice != valido:
            raise SystemExit(f"{nombre}: el vector declara valid={valido} y OpenSSL dice {dice}")
        out.append({
            "name": nombre,
            "description": desc,
            "public_key": pub.hex(),
            "message": mensaje.hex(),
            "signature": sig.hex(),
            "valid": valido,
            "how": {
                "key": clave_pub,
                "signed_by": firmante,
                "signed_message": firmado.hex(),
                "signed_context": contexto.hex(),
                "mutation": mutacion[0] if mutacion else "",
                "unmutated_signature_sha256": hashlib.sha256(original).hexdigest(),
            },
        })

    # Sin mensaje vacío: `openssl pkeyutl -rawin` no lo firma («Could not allocate 0 bytes
    # for oneshot sign/verify buffer»). Un cuerpo de nota nunca está vacío.
    caso("valido-a-un-byte", "Un mensaje de un byte (0x00), clave A.", "A", b"\x00", True, "A", b"\x00")
    caso("valido-a-abc", "El mensaje «abc», clave A.", "A", b"abc", True, "A", b"abc")
    caso("valido-a-nota", "Un cuerpo de checkpoint (c2sp.org/tlog-checkpoint), clave A: lo que firma el log.",
         "A", NOTA, True, "A", NOTA)
    caso("valido-a-largo", "Un mensaje de 3000 bytes, clave A.", "A", LARGO, True, "A", LARGO)
    caso("valido-b-abc", "El mensaje «abc», clave B.", "B", b"abc", True, "B", b"abc")

    base = om.firma(SEMILLA_A, b"abc")
    for nombre, desc, (ini, fin), byte, bit in (
        ("invalido-bit-en-c", "Un bit cambiado en c̃, el compromiso (bytes 0-31).", C_TILDE, 5, 0),
        ("invalido-bit-en-z", "Un bit cambiado en z (bytes 32-2335).", Z, 32 + 1000, 3),
        ("invalido-bit-en-z-ultimo", "Un bit cambiado en el último byte de z.", Z, Z[1] - 1, 7),
        ("invalido-bit-en-pistas-indice", "Un bit cambiado en el primer índice de las pistas h (bytes 2336-2415).",
         H_INDICES, H_INDICES[0], 0),
        ("invalido-bit-en-pistas-cuenta", "Un bit cambiado en la última cuenta de las pistas h (bytes 2416-2419).",
         H_CUENTAS, H_CUENTAS[1] - 1, 0),
    ):
        assert ini <= byte < fin
        caso(nombre, desc + " Firma de A sobre «abc».", "A", b"abc", False, "A", b"abc",
             mutacion=(f"bit {bit} del byte {byte}", lambda s, byte=byte, bit=bit: cambia_bit(s, byte, bit)),
             sig=base)

    caso("invalido-otra-clave", "Firma válida de B sobre «abc», verificada con la clave A.",
         "A", b"abc", False, "B", b"abc")
    caso("invalido-otro-mensaje", "Firma de A sobre «abc», verificada sobre «abd» (un byte).",
         "A", b"abd", False, "A", b"abc")
    caso("invalido-longitud-2419", "La firma de A sobre «abc» sin su último byte: 2419 bytes.",
         "A", b"abc", False, "A", b"abc", mutacion=("sin el último byte", lambda s: s[:-1]), sig=base)
    caso("invalido-longitud-2421", "La firma de A sobre «abc» con un byte 0x00 de más: 2421 bytes.",
         "A", b"abc", False, "A", b"abc", mutacion=("un byte 0x00 al final", lambda s: s + b"\x00"), sig=base)
    caso("invalido-otro-contexto",
         "Firma de A sobre «abc» con el contexto «nucleo»; con el contexto vacío no verifica (FIPS 204 §5.2).",
         "A", b"abc", False, "A", b"abc", contexto=CONTEXTO)

    return {
        "description": "ML-DSA-44 (FIPS 204), variante pura, firmas deterministas (rnd = 0^32); el veredicto es "
                       "ML-DSA.Verify con contexto VACÍO. Generados con OpenSSL, no con el código bajo prueba "
                       "(ADR-034, «Los vectores»).",
        "generated_with": om.version(),
        "keys": [{"name": n, "seed": s.hex(), "public_key": p.hex()} for n, (s, p) in claves.items()],
        "cases": out,
    }


def main():
    texto = json.dumps(casos(), ensure_ascii=False, indent=2) + "\n"
    if "--check" in sys.argv:
        actual = open(SALIDA, encoding="utf-8").read() if os.path.exists(SALIDA) else ""
        if actual != texto:
            print("mldsa/firmas.json NO coincide con lo que genera OpenSSL", file=sys.stderr)
            return 1
        print(f"{len(json.loads(texto)['cases'])} vectores ML-DSA-44 coinciden con OpenSSL")
        return 0
    with open(SALIDA, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(texto)
    print(f"{len(json.loads(texto)['cases'])} vectores ML-DSA-44 escritos")
    return 0


if __name__ == "__main__":
    sys.exit(main())
