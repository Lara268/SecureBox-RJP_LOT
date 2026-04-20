from securebox.keys import gen_rsa_private_key
from securebox.crypto.hybrid import encrypt_rsa_envelope, decrypt_rsa_envelope
from securebox.crypto.formats import save_sbox, load_sbox

mensaje = b"mensaje guardado en fichero"

# claves
sk = gen_rsa_private_key()
pk = sk.public_key()

# cifrar
container = encrypt_rsa_envelope(mensaje, pk)

# guardar en archivo
save_sbox(container, "mensaje.sbox")

print("Archivo guardado")

# cargar desde archivo
loaded = load_sbox("mensaje.sbox")

print("Archivo cargado")

# descifrar
resultado = decrypt_rsa_envelope(loaded, sk)

print("RESULTADO:", resultado)