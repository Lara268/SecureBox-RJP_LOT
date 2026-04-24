# Como ejecutar SecureBox

## 1. Instalar dependencias

```bash
python -m pip install -r requirements.txt
```

## 2. Crear claves RSA

```bash
python -m securebox.cli keygen --password 1234
```

Este comando genera los ficheros `rsa_private.pem` y `rsa_public.pem`.

## 3. Crear claves de firma

```bash
python script_generar_firma.py
```

Este script genera los ficheros `sign_private.pem` y `sign_public.pem`.
La contraseña configurada para la clave privada de firma es `1234`.

## 4. Cifrar un archivo en modo RSA

```bash
python -m securebox.cli encrypt mensaje.txt salida_rsa.sbox --key rsa_public.pem --mode rsa
```

## 5. Descifrar un archivo en modo RSA

```bash
python -m securebox.cli decrypt salida_rsa.sbox resultado_rsa.txt --key rsa_private.pem --password 1234
```

## 6. Firmar y verificar un contenedor

```bash
python -m securebox.cli sign salida_rsa.sbox --key sign_private.pem --password 1234
python -m securebox.cli verify salida_rsa.sbox --key sign_public.pem
```

## 7. Inspeccionar un contenedor .sbox

```bash
python -m securebox.cli inspect salida_rsa.sbox
```

## 8. Cifrar un archivo en modo ECC

Primero se genera un par de claves X25519:

```bash
python -c "from securebox.keys import gen_ecdh_keypair,pem_serialize_public_key,pem_serialize_encrypted_private_key; sk,pk=gen_ecdh_keypair(); open('ecc_private.pem','wb').write(pem_serialize_encrypted_private_key(sk,b'1234')); open('ecc_public.pem','wb').write(pem_serialize_public_key(pk)); print('Claves ECC generadas')"
```

Despues se puede cifrar y descifrar:

```bash
python -m securebox.cli encrypt mensaje.txt salida_ecc.sbox --key ecc_public.pem --mode ecc
python -m securebox.cli decrypt salida_ecc.sbox resultado_ecc.txt --key ecc_private.pem --password 1234
```

## 9. Ejecutar la demo de handshake

```bash
python -m securebox.cli handshake-demo
```

## 10. Ejecutar los tests

```bash
python -m pytest -q
```

Si se quiere mas detalle:

```bash
python -m pytest -v
```