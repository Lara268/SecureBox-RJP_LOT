import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


AES_KEY_SIZE = 32
GCM_NONCE_SIZE = 12


def generate_aes_key() -> bytes:
    return os.urandom(AES_KEY_SIZE)


def generate_nonce() -> bytes:
    return os.urandom(GCM_NONCE_SIZE)


def encrypt_aead(key: bytes, plaintext: bytes, aad: bytes = b"") -> tuple[bytes, bytes]:
    if len(key) != AES_KEY_SIZE:
        raise ValueError("La clave AES debe tener 32 bytes")

    nonce = generate_nonce()
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, aad)
    return nonce, ciphertext


def decrypt_aead(key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes = b"") -> bytes:
    if len(key) != AES_KEY_SIZE:
        raise ValueError("La clave AES debe tener 32 bytes")

    if len(nonce) != GCM_NONCE_SIZE:
        raise ValueError("El nonce GCM debe tener 12 bytes")

    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, aad)