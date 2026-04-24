from securebox.crypto.kdf import derive_key_hkdf


def test_hkdf_same_inputs_produce_same_key():
    shared_secret = b"shared-secret"
    salt = b"0123456789abcdef"
    info = b"sbox-1|context"

    key_a = derive_key_hkdf(shared_secret, salt, info, length=32)
    key_b = derive_key_hkdf(shared_secret, salt, info, length=32)

    assert key_a == key_b


def test_hkdf_different_salt_changes_key():
    shared_secret = b"shared-secret"
    info = b"sbox-1|context"

    key_a = derive_key_hkdf(shared_secret, b"0123456789abcdef", info, length=32)
    key_b = derive_key_hkdf(shared_secret, b"fedcba9876543210", info, length=32)

    assert key_a != key_b


def test_hkdf_respects_requested_length():
    shared_secret = b"shared-secret"
    salt = b"0123456789abcdef"
    info = b"sbox-1|context"

    key = derive_key_hkdf(shared_secret, salt, info, length=64)

    assert len(key) == 64
