from __future__ import annotations

from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import _HKDF_expand

def _xor_bytes(a: bytes, b: bytes) -> bytes:
    if len(a) != len(b):
        raise ValueError("xor length mismatch")
    return bytes(x ^ y for x, y in zip(a, b))

def _F(key: bytes, r: bytes, out_len: int) -> bytes:
    return _HKDF_expand(
        prk=key,
        info=r,
        L=out_len,
        hashmod=SHA256,
    )

def encrypt(key: bytes, msg: bytes, length: int = 8) -> bytes:
    if len(msg) != length:
        raise ValueError(f"msg must be exactly {length} bytes (got {len(msg)})")

    r = get_random_bytes(length)
    ks = _F(key, r, length)
    c = _xor_bytes(ks, msg)
    return r + c


def decrypt(key: bytes, ciphertext: bytes, length: int = 8) -> bytes:
    if len(ciphertext) != 2 * length:
        raise ValueError(
            f"ciphertext must be exactly {2*length} bytes (got {len(ciphertext)})"
        )

    r = ciphertext[:length]
    c = ciphertext[length:]
    ks = _F(key, r, length)
    return _xor_bytes(ks, c)
