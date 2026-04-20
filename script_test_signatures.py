from securebox.keys import gen_rsa_private_key, gen_sign_keypair
from securebox.crypto.hybrid import encrypt_rsa_envelope
from securebox.crypto.signatures import sign_container, verify_container

mensaje = b"mensaje secreto firmado"

# claves
rsa_sk = gen_rsa_private_key()
rsa_pk = rsa_sk.public_key()

sign_sk, sign_pk = gen_sign_keypair()

# cifrar
container = encrypt_rsa_envelope(mensaje, rsa_pk)

# firmar
container = sign_container(container, sign_sk)

print("SBOX firmado:", container)

# verificar
ok = verify_container(container, sign_pk)

print("VERIFICACION:", ok)

# probar manipulación
container["ciphertext"] = "AAAAAAA"

ok2 = verify_container(container, sign_pk)

print("VERIFICACION tras manipulación:", ok2)