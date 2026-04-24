from securebox.crypto.formats import (
    b64_decode,
    b64_encode,
    canonicalize_for_signature,
    load_sbox,
    save_sbox,
)


def test_base64_roundtrip():
    data = b"hola que tal"

    encoded = b64_encode(data)
    decoded = b64_decode(encoded)

    assert decoded == data


def test_save_and_load_sbox(tmp_path):
    container = {
        "version": "sbox-1",
        "data": b64_encode(b"hola que tal"),
    }
    path = tmp_path / "test.sbox"

    save_sbox(container, path)
    loaded = load_sbox(path)

    assert loaded == container


def test_canonicalize_excludes_signature_fields():
    container = {
        "version": "sbox-1",
        "mode": "rsa",
        "ciphertext": "abcd",
        "signature": "firma",
        "sig_alg": "ed25519",
    }

    canonical = canonicalize_for_signature(container)

    assert b'"signature"' not in canonical
    assert b'"sig_alg"' not in canonical


def test_canonicalize_is_stable_for_equivalent_payloads():
    container_a = {
        "ciphertext": "abcd",
        "mode": "rsa",
        "version": "sbox-1",
        "signature": "firma_a",
        "sig_alg": "ed25519",
    }
    container_b = {
        "version": "sbox-1",
        "sig_alg": "ed25519",
        "mode": "rsa",
        "signature": "firma_b",
        "ciphertext": "abcd",
    }

    assert canonicalize_for_signature(container_a) == canonicalize_for_signature(container_b)
