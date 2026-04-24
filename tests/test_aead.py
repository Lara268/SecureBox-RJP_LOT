from securebox.crypto.aead import decrypt_aead, encrypt_aead, generate_aes_key


def test_aead_encrypt_decrypt_roundtrip():
    message = b"esto es una prueba de cifrado"
    aad = b"sbox-1"

    key = generate_aes_key()
    nonce, ciphertext = encrypt_aead(key, message, aad)
    plaintext = decrypt_aead(key, nonce, ciphertext, aad)

    assert plaintext == message
