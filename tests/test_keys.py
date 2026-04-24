from cryptography.hazmat.primitives.asymmetric import ed25519, rsa, x25519

from securebox.keys import (
    gen_ecdh_keypair,
    gen_rsa_private_key,
    gen_sign_keypair,
    pem_load_private_key,
    pem_load_public_key,
    pem_serialize_encrypted_private_key,
    pem_serialize_public_key,
)


PASSWORD = b"clave_segura_123"


def test_rsa_key_serialization_roundtrip():
    private_key = gen_rsa_private_key()
    public_key = private_key.public_key()

    private_pem = pem_serialize_encrypted_private_key(private_key, PASSWORD)
    public_pem = pem_serialize_public_key(public_key)

    loaded_private = pem_load_private_key(private_pem, PASSWORD)
    loaded_public = pem_load_public_key(public_pem)

    assert isinstance(loaded_private, rsa.RSAPrivateKey)
    assert isinstance(loaded_public, rsa.RSAPublicKey)


def test_ecdh_key_serialization_roundtrip():
    private_key, public_key = gen_ecdh_keypair()

    private_pem = pem_serialize_encrypted_private_key(private_key, PASSWORD)
    public_pem = pem_serialize_public_key(public_key)

    loaded_private = pem_load_private_key(private_pem, PASSWORD)
    loaded_public = pem_load_public_key(public_pem)

    assert isinstance(loaded_private, x25519.X25519PrivateKey)
    assert isinstance(loaded_public, x25519.X25519PublicKey)


def test_sign_key_serialization_roundtrip():
    private_key, public_key = gen_sign_keypair()

    private_pem = pem_serialize_encrypted_private_key(private_key, PASSWORD)
    public_pem = pem_serialize_public_key(public_key)

    loaded_private = pem_load_private_key(private_pem, PASSWORD)
    loaded_public = pem_load_public_key(public_pem)

    assert isinstance(loaded_private, ed25519.Ed25519PrivateKey)
    assert isinstance(loaded_public, ed25519.Ed25519PublicKey)
