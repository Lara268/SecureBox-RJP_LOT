from securebox.crypto.formats import b64_encode, b64_decode, save_sbox, load_sbox

data = b"hola que tal"

encoded = b64_encode(data)
decoded = b64_decode(encoded)

print(encoded)
print(decoded)

container = {
    "version": "sbox-1",
    "data": encoded
}

save_sbox(container, "test.sbox")

loaded = load_sbox("test.sbox")

print(loaded)