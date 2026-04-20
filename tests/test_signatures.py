from securebox.keys import gen_rsa_private_key, gen_sign_keypair
from securebox.crypto.hybrid import encrypt_rsa_envelope
from securebox.crypto.signatures import sign_container, verify_container

def test_sign_and_verify():
    msg = b"firmado"
    rsa_sk = gen_rsa_private_key()
    rsa_pk = rsa_sk.public_key()

    sign_sk, sign_pk = gen_sign_keypair()

    c = encrypt_rsa_envelope(msg, rsa_pk)
    c = sign_container(c, sign_sk)

    assert verify_container(c, sign_pk) is True


def test_signature_tampering():
    msg = b"firmado"
    rsa_sk = gen_rsa_private_key()
    rsa_pk = rsa_sk.public_key()

    sign_sk, sign_pk = gen_sign_keypair()

    c = encrypt_rsa_envelope(msg, rsa_pk)
    c = sign_container(c, sign_sk)

    c["ciphertext"] = "AAAA"

    assert verify_container(c, sign_pk) is False