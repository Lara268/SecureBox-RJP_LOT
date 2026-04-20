from securebox.keys import (
    gen_rsa_private_key,
    gen_ecdh_keypair,
    gen_sign_keypair,
    pem_serialize_public_key,
    pem_serialize_encrypted_private_key,
    pem_load_public_key,
    pem_load_private_key,
)

password = b"clave_segura_123"

# RSA
rsa_sk = gen_rsa_private_key()
rsa_pk = rsa_sk.public_key()

rsa_sk_pem = pem_serialize_encrypted_private_key(rsa_sk, password)
rsa_pk_pem = pem_serialize_public_key(rsa_pk)

rsa_sk_loaded = pem_load_private_key(rsa_sk_pem, password)
rsa_pk_loaded = pem_load_public_key(rsa_pk_pem)

print(type(rsa_sk_loaded))
print(type(rsa_pk_loaded))

# X25519
ecdh_sk, ecdh_pk = gen_ecdh_keypair()
ecdh_sk_pem = pem_serialize_encrypted_private_key(ecdh_sk, password)
ecdh_pk_pem = pem_serialize_public_key(ecdh_pk)

print(type(pem_load_private_key(ecdh_sk_pem, password)))
print(type(pem_load_public_key(ecdh_pk_pem)))

# Ed25519
sign_sk, sign_pk = gen_sign_keypair()
sign_sk_pem = pem_serialize_encrypted_private_key(sign_sk, password)
sign_pk_pem = pem_serialize_public_key(sign_pk)

print(type(pem_load_private_key(sign_sk_pem, password)))
print(type(pem_load_public_key(sign_pk_pem)))