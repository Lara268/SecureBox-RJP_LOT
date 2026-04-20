from __future__ import annotations

import os
from dataclasses import dataclass

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.exceptions import InvalidSignature

from securebox.crypto.kdf import derive_key_hkdf
from securebox.crypto.aead import encrypt_aead, decrypt_aead
from securebox.keys import gen_sign_keypair


def build_transcript(alice_pub_bytes: bytes, bob_pub_bytes: bytes, salt: bytes) -> bytes:
    return b"|".join([
        b"sbox-1",
        b"handshake",
        alice_pub_bytes,
        bob_pub_bytes,
        salt,
    ])


def derive_session_keys(shared_secret: bytes, salt: bytes) -> tuple[bytes, bytes]:
    key_material = derive_key_hkdf(
        shared_secret=shared_secret,
        salt=salt,
        info=b"sbox-1|handshake|session-keys",
        length=64,
    )
    return key_material[:32], key_material[32:]


def make_message_aad(sender: str, counter: int) -> bytes:
    return f"{sender}|{counter}".encode("utf-8")


@dataclass
class PeerState:
    name: str
    eph_private: x25519.X25519PrivateKey
    eph_public: x25519.X25519PublicKey
    sign_private_key: object
    sign_public_key: object
    send_key: bytes | None = None
    recv_key: bytes | None = None
    send_counter: int = 0
    recv_counter: int = 0

    @classmethod
    def create(cls, name: str) -> "PeerState":
        eph_private = x25519.X25519PrivateKey.generate()
        eph_public = eph_private.public_key()
        sign_private_key, sign_public_key = gen_sign_keypair()
        return cls(
            name=name,
            eph_private=eph_private,
            eph_public=eph_public,
            sign_private_key=sign_private_key,
            sign_public_key=sign_public_key,
        )

    def eph_public_bytes(self) -> bytes:
        return self.eph_public.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )


def sign_transcript(peer: PeerState, transcript: bytes) -> bytes:
    return peer.sign_private_key.sign(transcript)


def verify_transcript(signature: bytes, transcript: bytes, public_key) -> bool:
    try:
        public_key.verify(signature, transcript)
        return True
    except InvalidSignature:
        return False


def encrypt_session_message(sender: PeerState, plaintext: bytes) -> dict:
    if sender.send_key is None:
        raise ValueError("La clave de envío no está inicializada")

    aad = make_message_aad(sender.name, sender.send_counter)
    nonce, ciphertext = encrypt_aead(sender.send_key, plaintext, aad)

    packet = {
        "sender": sender.name,
        "counter": sender.send_counter,
        "nonce": nonce,
        "ciphertext": ciphertext,
    }

    sender.send_counter += 1
    return packet


def decrypt_session_message(receiver: PeerState, packet: dict) -> bytes:
    if receiver.recv_key is None:
        raise ValueError("La clave de recepción no está inicializada")

    sender = packet["sender"]
    counter = packet["counter"]

    if counter != receiver.recv_counter:
        raise ValueError(
            f"Replay o mensaje fuera de orden detectado: esperado {receiver.recv_counter}, recibido {counter}"
        )

    aad = make_message_aad(sender, counter)
    plaintext = decrypt_aead(
        receiver.recv_key,
        packet["nonce"],
        packet["ciphertext"],
        aad,
    )

    receiver.recv_counter += 1
    return plaintext


def run_handshake_demo() -> None:
    print("=== HANDSHAKE DEMO SECUREBOX ===")

    alice = PeerState.create("alice")
    bob = PeerState.create("bob")

    alice_pub = alice.eph_public_bytes()
    bob_pub = bob.eph_public_bytes()
    salt = os.urandom(16)

    print("1. Claves efímeras X25519 generadas")

    alice_shared_secret = alice.eph_private.exchange(
        x25519.X25519PublicKey.from_public_bytes(bob_pub)
    )
    bob_shared_secret = bob.eph_private.exchange(
        x25519.X25519PublicKey.from_public_bytes(alice_pub)
    )

    if alice_shared_secret != bob_shared_secret:
        raise ValueError("Los secretos compartidos no coinciden")

    print("2. Secreto compartido calculado correctamente")

    alice_tx, alice_rx = derive_session_keys(alice_shared_secret, salt)
    bob_tx, bob_rx = derive_session_keys(bob_shared_secret, salt)

    alice.send_key = alice_tx
    alice.recv_key = alice_rx
    bob.send_key = bob_rx
    bob.recv_key = bob_tx

    print("3. Claves de sesión derivadas con HKDF")

    transcript = build_transcript(alice_pub, bob_pub, salt)

    alice_sig = sign_transcript(alice, transcript)
    bob_sig = sign_transcript(bob, transcript)

    if not verify_transcript(alice_sig, transcript, alice.sign_public_key):
        raise ValueError("Firma de Alice no válida")

    if not verify_transcript(bob_sig, transcript, bob.sign_public_key):
        raise ValueError("Firma de Bob no válida")

    print("4. Transcript autenticado correctamente")

    messages = [
        (alice, bob, b"Hola Bob, soy Alice"),
        (bob, alice, b"Hola Alice, recibido"),
        (alice, bob, b"Te envio el mensaje 3"),
        (bob, alice, b"Recibido el mensaje 4"),
        (alice, bob, b"Ultimo mensaje cifrado"),
    ]

    print("5. Intercambio de mensajes AEAD:")
    for sender, receiver, plaintext in messages:
        packet = encrypt_session_message(sender, plaintext)
        recovered = decrypt_session_message(receiver, packet)
        print(f"   {sender.name} -> {receiver.name}: {recovered!r}")

    print("=== HANDSHAKE COMPLETADO OK ===")