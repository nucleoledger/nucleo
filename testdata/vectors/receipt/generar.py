#!/usr/bin/env python3
"""Oráculo INDEPENDIENTE de los recibos golden (PROTOCOL.md §2 y §3).

Este fichero existe por el hallazgo más grave de la cuarta auditoría, que no era
criptográfico: el README afirmaba que "todo valor golden se calcula FUERA del código bajo
prueba", y los recibos golden los generaba internal/receipt, es decir, el paquete que
verifican. Un vector producido por el código que valida no valida nada: reproduce sus
propios errores.

Aquí no se importa una sola línea de Go. Los formatos se implementan a partir de la
especificación —PROTOCOL.md, RFC 6962 §2.1, RFC 8785, c2sp.org/signed-note y
c2sp.org/tlog-cosignature@v1— con hashlib, json y la primitiva Ed25519 de `cryptography`,
que es la única pieza prestada y es la que ningún oráculo razonable reimplementa.

Si Go y este fichero discrepan, uno de los dos está mal, y esa discusión es justo la que
un vector debe provocar.

    python3 testdata/vectors/receipt/generar.py          # reescribe los vectores
    python3 testdata/vectors/receipt/generar.py --check  # falla si difieren (lo usa el CI)

El vector valido-firma-mldsa-del-log NO sale de aquí: lleva una firma ML-DSA-44 y no hay
ML-DSA en esta caja de herramientas. Lo genera Go y el README lo dice.
"""

import base64, hashlib, json, os, struct, sys
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

AQUI = os.path.dirname(os.path.abspath(__file__))

ORIGIN = "nucleoledger.com/recibos"
TENANT = "1790012345001"
TIPO = "sri.factura.v1"
CID = "blob://x"
GENESIS = "0" * 64
BASE = 1788705000  # 2026-09-06T14:30:00Z en segundos Unix
MAGIC = "nucleo.org/receipt@v2"
SEPARADOR = "--- prueba verificable ---"
NOTA_DESTINATARIO = "  (firmado por el emisor)"
SIN_TIEMPO = "SIN TIEMPO DEMOSTRABLE"
AVISO_LEGAL = (
    "ADVERTENCIA LEGAL\n"
    "Este recibo es evidencia técnica de integridad y tiempo. No constituye por sí\n"
    "mismo un acto público, una certificación notarial ni un pronunciamiento de\n"
    "autoridad. Su valor probatorio lo determina un perito o un juez."
)
ALG_ED25519 = 0x01
ALG_COSIGNATURE = 0x04


def clave(b):
    """La misma convención determinista que usan los tests de Go: semilla b, b+1, ..."""
    return Ed25519PrivateKey.from_private_bytes(bytes((b + i) % 256 for i in range(32)))


def publica(sk):
    return sk.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def rfc3339(unix):
    import datetime

    return datetime.datetime.fromtimestamp(unix, datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def jcs(obj):
    """RFC 8785 para el esquema plano del header: claves ordenadas, sin espacios."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def sha256(b):
    return hashlib.sha256(b).digest()


# --- Merkle RFC 6962 con la regla de hoja leaf/v2 (PROTOCOL.md §2.1) ---------------


def leaf_hash(data):
    return sha256(b"\x00" + data)


def node_hash(izq, der):
    return sha256(b"\x01" + izq + der)


def mayor_potencia_de_dos_debajo(n):
    k = 1
    while k * 2 < n:
        k *= 2
    return k


def raiz(hojas):
    if not hojas:
        return sha256(b"")
    if len(hojas) == 1:
        return leaf_hash(hojas[0])
    k = mayor_potencia_de_dos_debajo(len(hojas))
    return node_hash(raiz(hojas[:k]), raiz(hojas[k:]))


def camino(hojas, m):
    if len(hojas) == 1:
        return []
    k = mayor_potencia_de_dos_debajo(len(hojas))
    if m < k:
        return camino(hojas[:k], m) + [raiz(hojas[k:])]
    return camino(hojas[k:], m - k) + [raiz(hojas[:k])]


# --- Notas firmadas (c2sp.org/signed-note) y cosignatures -------------------------


def key_hash(nombre, pub, alg):
    return hashlib.sha256(nombre.encode() + b"\n" + bytes([alg]) + pub).digest()[:4]


def linea_de_firma(nombre, key_hash_bytes, firma):
    return "— " + nombre + " " + base64.b64encode(key_hash_bytes + firma).decode() + "\n"


def cuerpo_checkpoint(origin, size, root):
    return f"{origin}\n{size}\n{base64.b64encode(root).decode()}\n"


def nota(origin, size, root, log_sk, cosignatures):
    """cosignatures: lista de (nombre, sk, unix). La firma del log va primero."""
    cuerpo = cuerpo_checkpoint(origin, size, root)
    lineas = linea_de_firma(origin, key_hash(origin, publica(log_sk), ALG_ED25519), log_sk.sign(cuerpo.encode()))
    for nombre, sk, unix in cosignatures:
        mensaje = f"cosignature/v1\ntime {unix}\n".encode() + cuerpo.encode()
        blob = struct.pack(">Q", unix) + sk.sign(mensaje)
        lineas += linea_de_firma(nombre, key_hash(nombre, publica(sk), ALG_COSIGNATURE), blob)
    return cuerpo + "\n" + lineas


# --- Bloques y recibos ------------------------------------------------------------


def header(indice, prev_hash, payload, timestamp, signer_pub):
    return {
        "index": indice,
        "payload_cid": CID,
        "payload_hash": hashlib.sha256(payload).hexdigest(),
        "prev_hash": prev_hash,
        "signer_pubkey": signer_pub.hex(),
        "tenant": TENANT,
        "timestamp": timestamp,
        "type": TIPO,
    }


def cadena(n, tenant_sk, fraccion_en_bloque_0=None):
    """Devuelve la lista de (header, canónico, hash, firma) de n bloques."""
    pub = publica(tenant_sk)
    bloques, prev = [], GENESIS
    for i in range(n):
        ts = rfc3339(BASE + i * 60)
        if i == 0 and fraccion_en_bloque_0:
            ts = fraccion_en_bloque_0
        h = header(i, prev, b'{"factura":%d,"importe":"1250.00"}' % i, ts, pub)
        canon = jcs(h)
        digest = sha256(canon)
        bloques.append((h, canon, digest, tenant_sk.sign(digest)))
        prev = digest.hex()
    return bloques


def texto_legible(h, destinatario, provable):
    tiempo = f"TIEMPO DEMOSTRABLE: {provable}  (atestiguado por testigos)" if provable else f"TIEMPO DEMOSTRABLE: {SIN_TIEMPO}"
    return (
        f"{MAGIC}\n"
        f"destinatario      : {destinatario}{NOTA_DESTINATARIO}\n"
        f"emisor (tenant)   : {h['tenant']}\n"
        f"tipo de registro  : {h['type']}\n"
        f"hash del contenido: {h['payload_hash']}\n"
        f"bloque            : {h['index']}\n"
        "\n"
        f"TIEMPO DECLARADO  : {h['timestamp']}  (declarado por el sistema emisor)\n"
        f"{tiempo}\n"
        "\n"
        f"{AVISO_LEGAL}\n\n"
    )


def tlog_proof(indice, path, nota_bytes):
    out = "c2sp.org/tlog-proof@v1\n" + str(indice) + "\n"
    for nodo in path:
        out += base64.b64encode(nodo).decode() + "\n"
    return out + "\n" + nota_bytes


def recibo(bloques, idx, destinatario, nota_bytes, provable, tenant_sk):
    h, canon, digest, firma = bloques[idx]
    hojas = [d + f for (_, _, d, f) in bloques]
    size = json.loads(nota_bytes.split("\n")[1]) if False else int(nota_bytes.split("\n")[1])
    prueba = tlog_proof(idx, camino(hojas[:size], idx), nota_bytes)
    cabeza = texto_legible(h, destinatario, provable)
    sin_firma = cabeza + SEPARADOR + "\n" + canon.decode() + "\n" + base64.b64encode(firma).decode() + "\n" + prueba
    firma_recibo = tenant_sk.sign(sha256(sin_firma.encode()))
    linea = "— " + TENANT + " " + base64.b64encode(firma_recibo).decode() + "\n"
    corte = sin_firma.index(prueba)
    return sin_firma[:corte] + linea + prueba, hojas[idx], firma


# --- Los vectores -----------------------------------------------------------------

TENANT_SK = clave(1)
LOG_SK = clave(50)
W1_SK = clave(90)
W2_SK = clave(91)
DESTINATARIO = "María Pérez (cédula 1712345678)"
W1 = "witness.example/w1"


def politica(witnesses, quorum, signer_pub=None):
    return {
        "origin": ORIGIN,
        "log_key": publica(LOG_SK).hex(),
        "signer_key": (signer_pub or publica(TENANT_SK)).hex(),
        "witnesses": {n: publica(sk).hex() for n, sk in witnesses},
        "quorum": quorum,
    }


def vector(nombre, descripcion, rec, hoja, firma_bloque, pol, valido, declared, provable, indice, motivo=""):
    v = {
        "name": nombre,
        "description": descripcion,
        "receipt": rec,
        "policy": pol,
        "leaf_data": hoja.hex(),
        "leaf_rule": "leaf/v2",
        "block_signature": firma_bloque.hex(),
        "valid": valido,
    }
    if motivo:
        v["reason"] = motivo
    v["declared_time"] = declared
    if provable:
        v["provable_time"] = provable
    v["block_index"] = indice
    return v


def escena(n, cosigners=1, nombre_testigo=W1, fraccion=None, tiempos=None):
    bloques = cadena(n, TENANT_SK, fraccion)
    hojas = [d + f for (_, _, d, f) in bloques]
    r = raiz(hojas)
    # Los testigos cosignan en instantes distintos y decrecientes, como la escena de Go.
    cos = tiempos if tiempos else [(nombre_testigo if i == 0 else f"witness.example/w{i+1}",
                                    [W1_SK, W2_SK][i], BASE + (30 - 10 * i) * 60) for i in range(cosigners)]
    return bloques, hojas, nota(ORIGIN, n, r, LOG_SK, cos), min(t for (_, _, t) in cos)


def genera():
    out = []

    def valido(nombre, desc, n, idx, cosigners=1, destinatario=DESTINATARIO, **kw):
        bloques, _, nota_bytes, provable = escena(n, cosigners, **kw)
        rec, hoja, firma = recibo(bloques, idx, destinatario, nota_bytes, rfc3339(provable), TENANT_SK)
        wits = [(W1, W1_SK)] if cosigners == 1 else [(W1, W1_SK), ("witness.example/w2", W2_SK)]
        if kw.get("nombre_testigo"):
            wits = [(kw["nombre_testigo"], W1_SK)]
        out.append(vector(nombre, desc, rec, hoja, firma, politica(wits, len(wits)), True,
                          bloques[idx][0]["timestamp"], rfc3339(provable), idx))
        return rec, bloques, nota_bytes, provable

    rec5, bloques5, nota5, prov5 = valido(
        "valido-1-cosignature", "Recibo correcto con una cosignature de un testigo aceptado. Debe verificar.", 5, 2)

    # alterado-encabezado: el tenant cambiado EN EL TEXTO.
    alterado = rec5.replace("emisor (tenant)   : " + TENANT, "emisor (tenant)   : 9999999999001", 1)
    assert alterado != rec5
    hoja5 = bloques5[2][2] + bloques5[2][3]
    out.append(vector("alterado-encabezado",
                      "El mismo recibo con el tenant cambiado EN EL TEXTO. La prueba verifica, pero el encabezado ya no se deriva de ella: debe rechazarse.",
                      alterado, hoja5, bloques5[2][3], politica([(W1, W1_SK)], 1), False,
                      bloques5[2][0]["timestamp"], None, 2, "header_mismatch"))

    # cosignature-no-confiable: política que acepta a OTRO testigo, que no cosignó.
    out.append(vector("cosignature-no-confiable",
                      "El mismo recibo verificado con una política que acepta a OTRO testigo, que no cosignó. La firma del log verifica, pero ningún testigo aceptado respalda la nota: quórum no alcanzado, debe rechazarse.",
                      rec5, hoja5, bloques5[2][3], politica([("otro.example/w9", clave(99))], 1), False,
                      bloques5[2][0]["timestamp"], None, 2, "untrusted_cosignature"))

    # Tamaños 1, 2, 4, 8 y 9, índices 0 y último.
    for n in (1, 2, 4, 8, 9):
        for idx in sorted({0, n - 1}):
            valido(f"valido-n{n}-i{idx}", f"log de {n} bloques, recibo del bloque {idx}", n, idx)

    # El destinatario que imita una línea de firma.
    valido("valido-destinatario-imita-firma",
           "el destinatario es un texto con la forma de una línea de firma; tiene que viajar como nombre y nada más",
           5, 2, destinatario="— 1790012345001 AAAA")

    # Timestamp con fracción: el recibo YA EMITIDO, de antes de ADR-019.
    valido("valido-timestamp-con-fraccion",
           "header con fracción de segundo, como los recibos emitidos antes de ADR-019: el texto lleva el literal del header y los tres verificadores lo aceptan",
           5, 0, fraccion="2026-09-06T14:30:00.123456789Z")

    # Un testigo llamado __proto__.
    valido("valido-testigo-proto",
           "el testigo se llama __proto__: en JavaScript asignarlo a un objeto normal cambia el prototipo en vez de crear un miembro, y el testigo desaparecía del mapa",
           5, 2, nombre_testigo="__proto__")

    # Dos cosignatures del MISMO testigo, la tardía primero: vale la más temprana.
    bloques, hojas, _, _ = escena(5)
    r = raiz(hojas)
    temprana, tardia = BASE + 30 * 60, BASE + 5 * 3600
    nota_dos = nota(ORIGIN, 5, r, LOG_SK, [(W1, W1_SK, tardia), (W1, W1_SK, temprana)])
    rec, hoja, firma = recibo(bloques, 2, DESTINATARIO, nota_dos, rfc3339(temprana), TENANT_SK)
    out.append(vector("valido-dos-cosignatures-mismo-testigo",
                      "El mismo testigo cosigna dos veces, la línea tardía primero. Un testigo cuenta una vez y vale su cosignature más temprana (PROTOCOL.md §3.3). Debe verificar con el tiempo temprano.",
                      rec, hoja, firma, politica([(W1, W1_SK)], 1), True,
                      bloques[2][0]["timestamp"], rfc3339(temprana), 2))

    # La cosignature duplicada con política 2-de-2: un testigo cuenta una vez.
    bloques, hojas, nota_una, prov = escena(5)
    linea_w1 = [l for l in nota_una.split("\n") if l.startswith("— " + W1 + " ")][0]
    nota_dup = nota_una + linea_w1 + "\n"
    rec, hoja, firma = recibo(bloques, 2, DESTINATARIO, nota_dup, rfc3339(prov), TENANT_SK)
    pol2 = politica([(W1, W1_SK), ("witness.example/w2", W2_SK)], 2)
    out.append(vector("invalido-cosignature-duplicada",
                      "Un solo testigo cosigna y su línea aparece DOS veces; el emisor re-firmó el recibo. La política exige 2 de 2 testigos: un testigo cuenta una vez (PROTOCOL.md §3.3). Debe rechazarse.",
                      rec, hoja, firma, pol2, False, bloques[2][0]["timestamp"], None, 2, "duplicate_cosignature"))
    return out


def main():
    check = "--check" in sys.argv
    vectores = genera()
    diferentes = []
    for v in vectores:
        ruta = os.path.join(AQUI, v["name"] + ".json")
        texto = json.dumps(v, ensure_ascii=False, indent=2) + "\n"
        if check:
            actual = open(ruta, encoding="utf-8").read() if os.path.exists(ruta) else ""
            if actual != texto:
                diferentes.append(v["name"])
            continue
        with open(ruta, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(texto)
    if check:
        if diferentes:
            print("los vectores del repositorio NO coinciden con el oráculo:", ", ".join(diferentes), file=sys.stderr)
            return 1
        print(f"{len(vectores)} vectores coinciden con el oráculo")
        return 0
    print(f"{len(vectores)} vectores escritos")
    return 0


if __name__ == "__main__":
    sys.exit(main())
