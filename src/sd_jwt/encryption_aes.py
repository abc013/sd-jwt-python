from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES

def encrypt(key: bytes, msg: bytes, length: int = 8):
    assert(len(msg) == length)

    randomness = get_random_bytes(length)

    cipher = AES.new(key, AES.MODE_GCM, nonce=randomness)
    ct = cipher.encrypt(msg)

    return randomness + ct

def decrypt(key: bytes, ciphertext: bytes, length: int = 8):
    randomness = ciphertext[:length]
    msg = ciphertext[length:]

    assert(len(randomness) == length)
    assert(len(msg) == length)

    cipher = AES.new(key, AES.MODE_GCM, nonce=randomness)
    pt = cipher.decrypt(msg)

    return pt