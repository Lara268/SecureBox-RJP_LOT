from securebox.keys import gen_ecdh_keypair
from securebox.crypto.hybrid import encrypt_ecc_envelope, decrypt_ecc_envelope

mensaje = b"mensaje secreto con ECC"

sk, pk = gen_ecdh_keypair()

container = encrypt_ecc_envelope(mensaje, pk)
print("SBOX ECC:", container)

resultado = decrypt_ecc_envelope(container, sk)
print("RESULTADO:", resultado)