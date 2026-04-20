from securebox.keys import gen_rsa_private_key
from securebox.crypto.hybrid import encrypt_rsa_envelope, decrypt_rsa_envelope

mensaje = b"mensaje secreto de prueba"

# generar claves
sk = gen_rsa_private_key()
pk = sk.public_key()

# cifrar
container = encrypt_rsa_envelope(mensaje, pk)

print("SBOX:", container)

# descifrar
resultado = decrypt_rsa_envelope(container, sk)

print("RESULTADO:", resultado)