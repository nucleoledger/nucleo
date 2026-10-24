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

Las firmas ML-DSA-44 de la nota se las pide a OpenSSL 3.5.9 (testdata/vectors/mldsa/
openssl_mldsa.py), la implementación independiente que aprobó el dev (ADR-034, decisión 7).
Hasta el 2026-10-24 eran bytes prestados por Go, material/mldsa.json (ADR-024 y su
enmienda): OpenSSL firma, con la misma semilla y sobre el mismo cuerpo, exactamente los
mismos bytes, así que valido-firma-mldsa-del-log no cambió ni uno al cambiar de origen. Sin
ese openssl, este oráculo no corre, y dice la orden que lo instala.

Los vectores con "requires": "0.8-draft" (ADR-034 §F) llevan una política que fija la
clave ML-DSA del log (log_mldsa_key) y declaran el veredicto de cada verificador en
"verdicts": el de Go, que la verifica, el de TypeScript y PHP, que con la opción B no la
verifican y dicen "present-unverified", y el de una política sin log_mldsa_key, que es
el de todo lector 0.7-draft. "valid" y "reason" son los de Go.
"""

import base64, hashlib, json, os, struct, sys
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

AQUI = os.path.dirname(os.path.abspath(__file__))
# Sin __pycache__/ dentro de testdata/: dejaría el árbol sucio después de cada --check.
sys.dont_write_bytecode = True
sys.path.insert(0, os.path.join(AQUI, "..", "mldsa"))
import openssl_mldsa as om  # noqa: E402

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
# El byte de extensión de c2sp.org/signed-note y el identificador que Núcleo puso detrás
# (ADR-007). Entran en el key ID de la firma ML-DSA, así que este oráculo los recompone y
# no se los cree a nadie.
ALG_EXT = 0xFF
MLDSA_EXT_ID = "nucleoledger.com/sig/ml-dsa-44@v1"
# Las semillas ML-DSA-44: la del log (la misma 200..231 con la que Go firmaba el material
# prestado) y la de una clave que ninguna política fija.
LOG_MLDSA_SEED = bytes(range(200, 232))
OTRA_MLDSA_SEED = bytes(range(100, 132))
# El byte y el bit que cambia la firma ML-DSA «alterada»: dentro de z (bytes 32-2335).
MLDSA_BYTE_ALTERADO, MLDSA_BIT_ALTERADO = 32 + 1000, 3
REQUIERE = "0.8-draft"


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


def key_hash_mldsa(nombre, pub):
    """El key ID de la firma ML-DSA: el byte 0xff lleva detrás el identificador largo."""
    h = hashlib.sha256()
    h.update(nombre.encode() + b"\n" + bytes([ALG_EXT]) + MLDSA_EXT_ID.encode() + b"\n" + pub)
    return h.digest()[:4]


def firma_mldsa(tipo, cuerpo):
    """(pub, firma) de una línea ML-DSA-44 del log, desde OpenSSL.

    "buena": la clave del log; "mala": la misma con un bit de z cambiado; "ajena": una
    clave que la política no fija. OpenSSL confirma cada veredicto antes de que entre en
    un vector: una "mala" que verificara no probaría nada.
    """
    semilla = OTRA_MLDSA_SEED if tipo == "ajena" else LOG_MLDSA_SEED
    pub, firma = om.publica(semilla), om.firma(semilla, cuerpo)
    if tipo == "mala":
        b = bytearray(firma)
        b[MLDSA_BYTE_ALTERADO] ^= 1 << MLDSA_BIT_ALTERADO
        firma = bytes(b)
    if om.verifica(pub, cuerpo, firma) != (tipo != "mala"):
        raise SystemExit(f"OpenSSL no da el veredicto esperado para la firma ML-DSA {tipo!r}")
    return pub, firma


def nota(origin, size, root, log_sk, cosignatures, mldsa=()):
    """cosignatures: lista de (nombre, sk, unix). La firma del log va primero, y detrás
    las líneas ML-DSA-44 que pida mldsa ("buena", "mala", "ajena"), en ese orden."""
    cuerpo = cuerpo_checkpoint(origin, size, root)
    lineas = linea_de_firma(origin, key_hash(origin, publica(log_sk), ALG_ED25519), log_sk.sign(cuerpo.encode()))
    for tipo in mldsa:
        pub, firma = firma_mldsa(tipo, cuerpo.encode())
        lineas += linea_de_firma(origin, key_hash_mldsa(origin, pub), firma)
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


def cadena(n, tenant_sk, fraccion_en_bloque_0=None, firmante=None):
    """Devuelve la lista de (header, canónico, hash, firma) de n bloques.

    firmante(i), si se da, elige la clave que firma el bloque i —y cuya pública va en su
    signer_pubkey—; sin él, todos los firma tenant_sk."""
    bloques, prev = [], GENESIS
    for i in range(n):
        sk = firmante(i) if firmante else tenant_sk
        ts = rfc3339(BASE + i * 60)
        if i == 0 and fraccion_en_bloque_0:
            ts = fraccion_en_bloque_0
        h = header(i, prev, b'{"factura":%d,"importe":"1250.00"}' % i, ts, publica(sk))
        canon = jcs(h)
        digest = sha256(canon)
        bloques.append((h, canon, digest, sk.sign(digest)))
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
# La clave del atacante del exploit de ADR-017: no está en ninguna política.
ATACANTE_SK = clave(70)
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


def escena(n, cosigners=1, nombre_testigo=W1, fraccion=None, tiempos=None, mldsa=()):
    bloques = cadena(n, TENANT_SK, fraccion)
    hojas = [d + f for (_, _, d, f) in bloques]
    r = raiz(hojas)
    # Los testigos cosignan en instantes distintos y decrecientes, como la escena de Go.
    cos = tiempos if tiempos else [(nombre_testigo if i == 0 else f"witness.example/w{i+1}",
                                    [W1_SK, W2_SK][i], BASE + (30 - 10 * i) * 60) for i in range(cosigners)]
    return bloques, hojas, nota(ORIGIN, n, r, LOG_SK, cos, mldsa), min(t for (_, _, t) in cos)


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

    # La firma ML-DSA-44 del log: misma escena que valido-1-cosignature más su línea, que
    # firma OpenSSL. Con una política sin logMLDSAKey ningún verificador la comprueba; lo
    # que el vector prueba es que los tres la IGNORAN sin listarla como clave desconocida.
    valido("valido-firma-mldsa-del-log",
           "la nota trae además la firma ML-DSA-44 del log (ADR-007): se ignora al verificar y la página la reconoce como del log",
           5, 2, mldsa=("buena",))

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

    # El exploit del recibo de ADR-017, tal como lo ejecutó la segunda auditoría: los
    # bloques 1-4 re-firmados con la clave del atacante —signer_pubkey apuntando a ella,
    # firmas autoconsistentes—, el checkpoint firmado por la clave REAL del log y cosignado
    # por el testigo REAL, y el recibo del bloque 2 firmado como emisor por el atacante.
    # Todo verifica salvo una cosa: la política fija signerKey, y no es la del header.
    bloques = cadena(5, TENANT_SK, firmante=lambda i: TENANT_SK if i == 0 else ATACANTE_SK)
    hojas = [d + f for (_, _, d, f) in bloques]
    prov = BASE + 30 * 60
    nota_real = nota(ORIGIN, 5, raiz(hojas), LOG_SK, [(W1, W1_SK, prov)])
    rec, hoja, firma = recibo(bloques, 2, DESTINATARIO, nota_real, rfc3339(prov), ATACANTE_SK)
    out.append(vector("invalido-bloque-de-clave-ajena",
                      "El exploit del recibo de ADR-017: los bloques 1-4 re-firmados con una clave ajena, autoconsistentes, bajo un checkpoint firmado por la clave real del log y cosignado por el testigo real; el recibo del bloque 2 lo firma el atacante como emisor. Firmas, inclusión y quórum verifican; la política fija signerKey y el header declara otra clave: debe rechazarse.",
                      rec, hoja, firma, politica([(W1, W1_SK)], 1), False,
                      bloques[2][0]["timestamp"], None, 2, "unexpected_signer"))

    out.extend(genera_mldsa())
    return out


# --- La política que fija la clave ML-DSA del log (ADR-034, PROTOCOL 0.8-draft §3.3) ----


def genera_mldsa():
    """Los recibos de ADR-034 §F: la misma escena que valido-1-cosignature, con una
    política que fija log_mldsa_key y distintas líneas ML-DSA-44 en la nota."""
    out = []
    pol = dict(politica([(W1, W1_SK)], 1), log_mldsa_key=om.publica(LOG_MLDSA_SEED).hex())

    def caso(nombre, desc, lineas, go, sin_clave):
        """go: (valid, log_mldsa o motivo); sin_clave: log_mldsa con una política sin la
        clave, donde todos valen. TS y PHP (opción B, decisión 5): exigen una línea de la
        clave de 2420 bytes y no la verifican."""
        bloques, _, nota_bytes, provable = escena(5, mldsa=lineas)
        rec, hoja, firma = recibo(bloques, 2, DESTINATARIO, nota_bytes, rfc3339(provable), TENANT_SK)
        de_la_clave = "buena" in lineas or "mala" in lineas
        sdk = ({"valid": True, "log_mldsa": "present-unverified"} if de_la_clave
               else {"valid": False, "reason": "mldsa_signature_missing"})
        v = {
            "name": nombre,
            "description": desc,
            "requires": REQUIERE,
            "receipt": rec,
            "policy": pol,
            "leaf_data": hoja.hex(),
            "leaf_rule": "leaf/v2",
            "block_signature": firma.hex(),
            "valid": go[0],
        }
        if not go[0]:
            v["reason"] = go[1]
        v["declared_time"] = bloques[2][0]["timestamp"]
        # Se publica siempre: es el tiempo de los verificadores que dan el recibo por bueno.
        v["provable_time"] = rfc3339(provable)
        v["block_index"] = 2
        v["verdicts"] = {
            "go": {"valid": True, "log_mldsa": go[1]} if go[0] else {"valid": False, "reason": go[1]},
            "ts": sdk,
            "php": sdk,
            "without_log_mldsa_key": {"valid": True, "log_mldsa": sin_clave},
        }
        out.append(v)

    caso("valido-mldsa-fijada-verificada",
         "La política fija la clave ML-DSA-44 del log y la nota trae su firma, válida. Go la verifica; TypeScript y PHP "
         "la exigen y dicen que no la verificaron.",
         ("buena",), (True, "verified"), "present-unverified")
    caso("invalido-mldsa-fijada-ausente",
         "La política fija la clave ML-DSA-44 del log y la nota no trae ninguna línea ML-DSA: inválido en los tres "
         "(«la política fija la clave ML-DSA del log y el checkpoint no trae su firma»).",
         (), (False, "mldsa_signature_missing"), "absent")
    caso("invalido-mldsa-fijada-alterada",
         f"La línea de la clave fijada trae la firma con el bit {MLDSA_BIT_ALTERADO} del byte {MLDSA_BYTE_ALTERADO} "
         "cambiado (en z). Inválido en Go; válido con \"present-unverified\" en TypeScript y PHP, que no verifican "
         "ML-DSA (la divergencia declarada de la decisión 5); válido con una política sin la clave.",
         ("mala",), (False, "mldsa_signature_invalid"), "present-unverified")
    caso("invalido-mldsa-fijada-dos-lineas-una-mala",
         "Dos líneas de la clave fijada, la buena primero y después la alterada: toda línea de una clave de la "
         "política tiene que verificar (PROTOCOL §3.3), así que inválido en Go aunque una verifique.",
         ("buena", "mala"), (False, "mldsa_signature_invalid"), "present-unverified")
    caso("invalido-mldsa-solo-de-otra-clave",
         "La única línea con forma de ML-DSA-44 a nombre del log es de OTRA clave, firma válida: se ignora "
         "(c2sp.org/signed-note) y equivale a no traer ninguna. Inválido en los tres.",
         ("ajena",), (False, "mldsa_signature_missing"), "present-unverified")
    caso("valido-mldsa-fijada-y-linea-de-otra-clave",
         "La línea buena de la clave fijada y otra de una clave que la política no conoce: esa se ignora y el "
         "recibo vale.",
         ("buena", "ajena"), (True, "verified"), "present-unverified")
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
