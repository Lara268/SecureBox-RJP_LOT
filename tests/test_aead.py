import pytest
from cryptography.exceptions import InvalidTag

from securebox.crypto.aead import decrypt_aead, encrypt_aead, generate_aes_key


def test_aead_encrypt_decrypt_roundtrip():
    message = b"esto es una prueba de cifrado"
    aad = b"sbox-1"

    key = generate_aes_key()
    nonce, ciphertext = encrypt_aead(key, message, aad)
    plaintext = decrypt_aead(key, nonce, ciphertext, aad)

    assert plaintext == message


def test_modified_ciphertext_is_rejected():
    message = b"mensaje con ciphertext alterado"
    aad = b"sbox-1"

    key = generate_aes_key()
    nonce, ciphertext = encrypt_aead(key, message, aad)
    tampered_ciphertext = bytes([ciphertext[0] ^ 1]) + ciphertext[1:]

    with pytest.raises(InvalidTag):
        decrypt_aead(key, nonce, tampered_ciphertext, aad)


def test_modified_tag_is_rejected():
    message = b"mensaje con tag alterado"
    aad = b"sbox-1"

    key = generate_aes_key()
    nonce, ciphertext = encrypt_aead(key, message, aad)
    tampered_ciphertext = ciphertext[:-1] + bytes([ciphertext[-1] ^ 1])

    with pytest.raises(InvalidTag):
        decrypt_aead(key, nonce, tampered_ciphertext, aad)
