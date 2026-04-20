import hashlib
import os

from cryptography.hazmat.primitives.asymmetric import x25519
from securebox.crypto.kdf import derive_key_hkdf

from cryptography.hazmat.primitives import serialization

from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

from securebox.crypto.aead import generate_aes_key, encrypt_aead, decrypt_aead
from securebox.crypto.formats import b64_encode, b64_decode


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def encrypt_rsa_envelope(plaintext: bytes, recipient_public_key) -> dict:
    # 1. Generar clave simétrica
    aes_key = generate_aes_key()

    # 2. Cifrar datos
    nonce, ciphertext = encrypt_aead(aes_key, plaintext, b"sbox-1")

    # 3. Envolver clave con RSA
    wrapped_key = recipient_public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # 4. Crear contenedor
    container = {
        "version": "sbox-1",
        "mode": "rsa",
        "enc_alg": "aes_256_gcm",
        "wrap_alg": "rsa_oaep_sha256",
        "recipient_id": get_key_id(recipient_public_key),
        "nonce": b64_encode(nonce),
        "ciphertext": b64_encode(ciphertext),
        "wrapped_key": b64_encode(wrapped_key),
        "ephemeral_public_key": None,
        "salt": None,
        "signature": None
    }

    return container


def decrypt_rsa_envelope(container: dict, recipient_private_key) -> bytes:
    # 1. Decodificar campos
    nonce = b64_decode(container["nonce"])
    ciphertext = b64_decode(container["ciphertext"])
    wrapped_key = b64_decode(container["wrapped_key"])

    # 2. Desencriptar clave AES
    aes_key = recipient_private_key.decrypt(
        wrapped_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # 3. Descifrar datos
    plaintext = decrypt_aead(aes_key, nonce, ciphertext, b"sbox-1")

    return plaintext

def get_key_id(public_key) -> str:
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return hashlib.sha256(pem).hexdigest()

def encrypt_ecc_envelope(plaintext: bytes, recipient_public_key) -> dict:
    # 1. clave efímera del emisor
    ephemeral_private_key = x25519.X25519PrivateKey.generate()
    ephemeral_public_key = ephemeral_private_key.public_key()

    # 2. secreto compartido
    shared_secret = ephemeral_private_key.exchange(recipient_public_key)

    # 3. derivación de clave AES
    salt = os.urandom(16)
    info = b"sbox-1|x25519_hkdf_sha256|aes_256_gcm"
    aes_key = derive_key_hkdf(shared_secret, salt, info, length=32)

    # 4. cifrar datos
    nonce, ciphertext = encrypt_aead(aes_key, plaintext, b"sbox-1")

    # 5. serializar pública efímera
    eph_pub_bytes = ephemeral_public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )

    # 6. contenedor
    container = {
        "version": "sbox-1",
        "mode": "ecc",
        "enc_alg": "aes_256_gcm",
        "wrap_alg": "x25519_hkdf_sha256",
        "recipient_id": get_key_id(recipient_public_key),
        "nonce": b64_encode(nonce),
        "ciphertext": b64_encode(ciphertext),
        "wrapped_key": None,
        "ephemeral_public_key": b64_encode(eph_pub_bytes),
        "salt": b64_encode(salt),
        "signature": None,
        "sig_alg": None,
    }

    return container


def decrypt_ecc_envelope(container: dict, recipient_private_key) -> bytes:
    nonce = b64_decode(container["nonce"])
    ciphertext = b64_decode(container["ciphertext"])
    eph_pub_bytes = b64_decode(container["ephemeral_public_key"])
    salt = b64_decode(container["salt"])

    ephemeral_public_key = x25519.X25519PublicKey.from_public_bytes(eph_pub_bytes)

    shared_secret = recipient_private_key.exchange(ephemeral_public_key)

    info = b"sbox-1|x25519_hkdf_sha256|aes_256_gcm"
    aes_key = derive_key_hkdf(shared_secret, salt, info, length=32)

    plaintext = decrypt_aead(aes_key, nonce, ciphertext, b"sbox-1")
    return plaintext