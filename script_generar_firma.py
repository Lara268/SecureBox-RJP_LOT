from securebox.keys import gen_sign_keypair, pem_serialize_public_key, pem_serialize_encrypted_private_key

sk, pk = gen_sign_keypair()

with open("sign_private.pem", "wb") as f:
    f.write(pem_serialize_encrypted_private_key(sk, b"1234"))

with open("sign_public.pem", "wb") as f:
    f.write(pem_serialize_public_key(pk))

print("Claves de firma creadas")