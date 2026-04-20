from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from securebox.crypto.formats import b64_encode, b64_decode, canonicalize_for_signature


def sign_container(container: dict, private_key: Ed25519PrivateKey) -> dict:
    container["sig_alg"] = "ed25519"
    container["signature"] = None

    data = canonicalize_for_signature(container)
    signature = private_key.sign(data)

    container["signature"] = b64_encode(signature)
    return container


def verify_container(container: dict, public_key: Ed25519PublicKey) -> bool:
    if "signature" not in container or container["signature"] is None:
        raise ValueError("El contenedor no tiene firma")

    signature = b64_decode(container["signature"])
    data = canonicalize_for_signature(container)

    try:
        public_key.verify(signature, data)
        return True
    except Exception:
        return False