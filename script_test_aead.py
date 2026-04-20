from securebox.crypto.aead import generate_aes_key, encrypt_aead, decrypt_aead

mensaje = b"esto es una prueba de cifrado"
aad = b"sbox-1"

key = generate_aes_key()
nonce, ciphertext = encrypt_aead(key, mensaje, aad)
plaintext = decrypt_aead(key, nonce, ciphertext, aad)

print("Nonce:", nonce)
print("Ciphertext:", ciphertext)
print("Plaintext:", plaintext)