from __future__ import annotations

from typing import Tuple, Union

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, x25519, ed25519


PublicKeyType = Union[
    rsa.RSAPublicKey,
    x25519.X25519PublicKey,
    ed25519.Ed25519PublicKey,
]

PrivateKeyType = Union[
    rsa.RSAPrivateKey,
    x25519.X25519PrivateKey,
    ed25519.Ed25519PrivateKey,
]


def gen_rsa_private_key(public_exponent: int = 65537, key_size: int = 2048) -> rsa.RSAPrivateKey:
    if key_size not in (2048, 3072):
        raise ValueError("RSA key_size debe ser 2048 o 3072")
    return rsa.generate_private_key(
        public_exponent=public_exponent,
        key_size=key_size,
    )


def gen_ecdh_keypair() -> Tuple[x25519.X25519PrivateKey, x25519.X25519PublicKey]:
    private_key = x25519.X25519PrivateKey.generate()
    public_key = private_key.public_key()
    return private_key, public_key


def gen_sign_keypair() -> Tuple[ed25519.Ed25519PrivateKey, ed25519.Ed25519PublicKey]:
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    return private_key, public_key


def pem_serialize_public_key(pk: PublicKeyType) -> bytes:
    return pk.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def pem_serialize_encrypted_private_key(sk: PrivateKeyType, password_bytes: bytes) -> bytes:
    if not password_bytes:
        raise ValueError("La contraseña no puede estar vacía")

    return sk.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(password_bytes),
    )


def pem_load_public_key(pem_bytes: bytes) -> PublicKeyType:
    public_key = serialization.load_pem_public_key(pem_bytes)

    if not isinstance(
        public_key,
        (rsa.RSAPublicKey, x25519.X25519PublicKey, ed25519.Ed25519PublicKey),
    ):
        raise TypeError("Tipo de clave pública no soportado")

    return public_key


def pem_load_private_key(pem_bytes: bytes, password_bytes: bytes) -> PrivateKeyType:
    private_key = serialization.load_pem_private_key(
        pem_bytes,
        password=password_bytes,
    )

    if not isinstance(
        private_key,
        (rsa.RSAPrivateKey, x25519.X25519PrivateKey, ed25519.Ed25519PrivateKey),
    ):
        raise TypeError("Tipo de clave privada no soportado")

    return private_key