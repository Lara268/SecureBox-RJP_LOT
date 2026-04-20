from securebox.keys import gen_rsa_private_key, gen_ecdh_keypair
from securebox.crypto.hybrid import (
    encrypt_rsa_envelope, decrypt_rsa_envelope,
    encrypt_ecc_envelope, decrypt_ecc_envelope,
)

def test_rsa_encrypt_decrypt():
    msg = b"hola"
    sk = gen_rsa_private_key()
    pk = sk.public_key()

    c = encrypt_rsa_envelope(msg, pk)
    out = decrypt_rsa_envelope(c, sk)

    assert out == msg


def test_ecc_encrypt_decrypt():
    msg = b"hola ecc"
    sk, pk = gen_ecdh_keypair()

    c = encrypt_ecc_envelope(msg, pk)
    out = decrypt_ecc_envelope(c, sk)

    assert out == msg