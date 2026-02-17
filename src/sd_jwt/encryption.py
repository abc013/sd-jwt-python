from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES

def aes_encrypt(key: bytes, msg: bytes):
    assert(len(msg) == 8)

    randomness = get_random_bytes(8)

    cipher = AES.new(key, AES.MODE_CTR, nonce=randomness)
    ct = cipher.encrypt(msg)

    return randomness + ct

def aes_decrypt(key: bytes, ciphertext: bytes):
    randomness = ciphertext[:8]
    msg = ciphertext[8:]

    assert(len(randomness) == 8)
    assert(len(msg) == 8)

    cipher = AES.new(key, AES.MODE_CTR, nonce=randomness)
    pt = cipher.decrypt(msg)

    return pt