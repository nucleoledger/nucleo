#!/usr/bin/env python3
"""Genera los vectores de la regla de hoja leaf/v2 de PROTOCOL.md §2.1.

Implementación INDEPENDIENTE del código Go: solo hashlib. Es la regla
anti-circularidad del proyecto — un vector calculado con la función que se quiere
probar no prueba nada.

    leaf_data = hash(32 crudos) ‖ signature(64 crudos)
    leaf_hash = SHA-256(0x00 ‖ leaf_data)          RFC 6962
    node      = SHA-256(0x01 ‖ izq ‖ der)          RFC 6962

    python3 testdata/vectors/leaf/generar.py > testdata/vectors/leaf/v2.json
"""
import hashlib, json


def leaf_hash(data: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + data).digest()


def node_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


def root(leaves):
    """RFC 6962 §2.1, escrito desde el RFC y no desde nuestro merkle.go."""
    if not leaves:
        return hashlib.sha256(b"").digest()
    if len(leaves) == 1:
        return leaf_hash(leaves[0])
    k = 1
    while k * 2 < len(leaves):
        k *= 2
    return node_hash(root(leaves[:k]), root(leaves[k:]))


def caso(nombre, h: bytes, sig: bytes, nota):
    assert len(h) == 32 and len(sig) == 64
    data = h + sig
    return {
        "name": nombre,
        "note": nota,
        "hash_hex": h.hex(),
        "signature_hex": sig.hex(),
        "leaf_data_hex": data.hex(),
        "leaf_data_len": len(data),
        "leaf_hash_hex": leaf_hash(data).hex(),
    }


casos = [
    caso("ceros", bytes(32), bytes(64),
         "todo a cero: detecta una implementación que confunda vacío con ausente"),
    caso("hash-ff-firma-00", b"\xff" * 32, bytes(64),
         "el hash entra ANTES de la firma; invertir el orden da otra hoja"),
    caso("hash-00-firma-ff", bytes(32), b"\xff" * 64,
         "el caso espejo del anterior: los dos juntos fijan el orden"),
    caso("contados", bytes(range(32)), bytes((i * 7) % 256 for i in range(64)),
         "bytes distinguibles en las dos mitades"),
    caso("sha256-de-bloque", hashlib.sha256(b"bloque de prueba").digest(),
         hashlib.sha256(b"firma").digest() * 2,
         "un hash realista con una firma de 64 bytes"),
]

# Un árbol de 8 hojas leaf/v2, para fijar también la raíz.
hojas = [bytes([i]) * 32 + bytes([255 - i]) * 64 for i in range(8)]
arbol = {
    "note": "8 hojas leaf/v2; leaf_data[i] = (i repetido 32) ‖ (255-i repetido 64)",
    "leaves_hex": [h.hex() for h in hojas],
    "roots_hex": {str(n): root(hojas[:n]).hex() for n in range(1, 9)},
}

print(json.dumps({
    "source": "PROTOCOL.md §2.1 (leaf/v2) + RFC 6962 §2.1",
    "note": "Calculado por testdata/vectors/leaf/generar.py, solo con hashlib. "
            "NO por el código Go que estos vectores verifican.",
    "leaf_rule": "leaf/v2",
    "cases": casos,
    "tree": arbol,
}, indent=2, ensure_ascii=False))
