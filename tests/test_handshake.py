import os

import pytest
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric import x25519

from securebox.crypto.handshake import (
    PeerState,
    build_transcript,
    decrypt_session_message,
    derive_session_keys,
    encrypt_session_message,
    sign_transcript,
    verify_transcript,
)


def _establish_secure_channel():
    alice = PeerState.create("alice")
    bob = PeerState.create("bob")

    alice_pub = alice.eph_public_bytes()
    bob_pub = bob.eph_public_bytes()
    salt = os.urandom(16)

    alice_shared_secret = alice.eph_private.exchange(
        x25519.X25519PublicKey.from_public_bytes(bob_pub)
    )
    bob_shared_secret = bob.eph_private.exchange(
        x25519.X25519PublicKey.from_public_bytes(alice_pub)
    )

    alice_tx, alice_rx = derive_session_keys(alice_shared_secret, salt)
    bob_tx, bob_rx = derive_session_keys(bob_shared_secret, salt)

    alice.send_key = alice_tx
    alice.recv_key = alice_rx
    bob.send_key = bob_rx
    bob.recv_key = bob_tx

    transcript = build_transcript(alice_pub, bob_pub, salt)
    return alice, bob, transcript


def test_handshake_transcript_authenticates_peers():
    alice, bob, transcript = _establish_secure_channel()

    alice_signature = sign_transcript(alice, transcript)
    bob_signature = sign_transcript(bob, transcript)

    assert verify_transcript(alice_signature, transcript, alice.sign_public_key) is True
    assert verify_transcript(bob_signature, transcript, bob.sign_public_key) is True


def test_handshake_exchanges_five_encrypted_messages():
    alice, bob, _ = _establish_secure_channel()
    messages = [
        (alice, bob, b"Hola Bob, soy Alice"),
        (bob, alice, b"Hola Alice, recibido"),
        (alice, bob, b"Te envio el mensaje 3"),
        (bob, alice, b"Recibido el mensaje 4"),
        (alice, bob, b"Ultimo mensaje cifrado"),
    ]

    recovered_messages = []
    for sender, receiver, plaintext in messages:
        packet = encrypt_session_message(sender, plaintext)
        recovered_messages.append(decrypt_session_message(receiver, packet))

    assert recovered_messages == [plaintext for _, _, plaintext in messages]


def test_handshake_replay_is_rejected():
    alice, bob, _ = _establish_secure_channel()

    packet = encrypt_session_message(alice, b"mensaje unico")

    assert decrypt_session_message(bob, packet) == b"mensaje unico"

    with pytest.raises(ValueError, match="Replay o mensaje fuera de orden"):
        decrypt_session_message(bob, packet)


def test_handshake_tampered_ciphertext_is_rejected():
    alice, bob, _ = _establish_secure_channel()

    packet = encrypt_session_message(alice, b"mensaje alterado")
    packet["ciphertext"] = packet["ciphertext"][:-1] + bytes([packet["ciphertext"][-1] ^ 1])

    with pytest.raises(InvalidTag):
        decrypt_session_message(bob, packet)
