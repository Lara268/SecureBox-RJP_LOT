import argparse
from pathlib import Path

from securebox.keys import (
    gen_rsa_private_key,
    pem_serialize_public_key,
    pem_serialize_encrypted_private_key,
)
from securebox.crypto.hybrid import (
    encrypt_rsa_envelope,
    decrypt_rsa_envelope,
    encrypt_ecc_envelope,
    decrypt_ecc_envelope,
)
from securebox.crypto.signatures import sign_container, verify_container
from securebox.crypto.formats import save_sbox, load_sbox


def cmd_keygen(args):
    sk = gen_rsa_private_key()
    pk = sk.public_key()

    password = args.password.encode()

    Path("rsa_private.pem").write_bytes(
        pem_serialize_encrypted_private_key(sk, password)
    )
    Path("rsa_public.pem").write_bytes(
        pem_serialize_public_key(pk)
    )

    print("Claves RSA generadas")


def cmd_encrypt(args):
    data = Path(args.input).read_bytes()

    if args.mode == "rsa":
        from cryptography.hazmat.primitives import serialization
        pk = serialization.load_pem_public_key(Path(args.key).read_bytes())
        container = encrypt_rsa_envelope(data, pk)

    else:
        from cryptography.hazmat.primitives import serialization
        pk = serialization.load_pem_public_key(Path(args.key).read_bytes())
        container = encrypt_ecc_envelope(data, pk)

    save_sbox(container, args.output)
    print("Archivo cifrado")


def cmd_decrypt(args):
    from cryptography.hazmat.primitives import serialization

    container = load_sbox(args.input)
    sk = serialization.load_pem_private_key(
        Path(args.key).read_bytes(),
        password=args.password.encode()
    )

    if container["mode"] == "rsa":
        plaintext = decrypt_rsa_envelope(container, sk)
    else:
        plaintext = decrypt_ecc_envelope(container, sk)

    Path(args.output).write_bytes(plaintext)
    print("Archivo descifrado")


def cmd_sign(args):
    from cryptography.hazmat.primitives import serialization

    container = load_sbox(args.input)
    sk = serialization.load_pem_private_key(
        Path(args.key).read_bytes(),
        password=args.password.encode()
    )

    container = sign_container(container, sk)
    save_sbox(container, args.input)

    print("Archivo firmado")


def cmd_verify(args):
    from cryptography.hazmat.primitives import serialization

    container = load_sbox(args.input)
    pk = serialization.load_pem_public_key(Path(args.key).read_bytes())

    ok = verify_container(container, pk)
    print("Firma válida:", ok)


def cmd_inspect(args):
    container = load_sbox(args.input)
    for k, v in container.items():
        print(f"{k}: {v}")


def main():
    parser = argparse.ArgumentParser(prog="securebox")
    sub = parser.add_subparsers(dest="command")

    p = sub.add_parser("keygen")
    p.add_argument("--password", required=True)
    p.set_defaults(func=cmd_keygen)

    p = sub.add_parser("encrypt")
    p.add_argument("input")
    p.add_argument("output")
    p.add_argument("--key", required=True)
    p.add_argument("--mode", choices=["rsa", "ecc"], default="rsa")
    p.set_defaults(func=cmd_encrypt)

    p = sub.add_parser("decrypt")
    p.add_argument("input")
    p.add_argument("output")
    p.add_argument("--key", required=True)
    p.add_argument("--password", required=True)
    p.set_defaults(func=cmd_decrypt)

    p = sub.add_parser("sign")
    p.add_argument("input")
    p.add_argument("--key", required=True)
    p.add_argument("--password", required=True)
    p.set_defaults(func=cmd_sign)

    p = sub.add_parser("verify")
    p.add_argument("input")
    p.add_argument("--key", required=True)
    p.set_defaults(func=cmd_verify)

    p = sub.add_parser("inspect")
    p.add_argument("input")
    p.set_defaults(func=cmd_inspect)

    args = parser.parse_args()
    if hasattr(args, "func"):
        args.func(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()