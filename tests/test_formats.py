from securebox.crypto.formats import b64_decode, b64_encode, load_sbox, save_sbox


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
