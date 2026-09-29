"""Local demo of CypherChat message encryption (HPKE Auth mode). No server involved.

Two fictitious participants, Alice (sender) and Bob (recipient), each generate or load a
private key file (mode 0600, never overwritten). Each side "trusts" the other's public
key and fingerprint, which in real use must be verified out of band.

Usage:
    uv run python examples/e2ee_demo.py            # temporary keys, discarded at the end
    uv run python examples/e2ee_demo.py KEYS_DIR   # keeps/reuses KEYS_DIR/alice.key and bob.key
"""

import json
import sys
import tempfile
from pathlib import Path
from uuid import uuid4

from seguranca_auditoria.client import (
    DecryptionError,
    Envelope,
    TrustedKey,
    decrypt_message,
    encrypt_message,
)
from seguranca_auditoria.client.keyfiles import (
    generate_private_key_file,
    load_private_key_file,
    public_key_bytes,
)
from seguranca_auditoria.security import keys as key_utils


def load_or_create(path: Path) -> bytes:
    if path.exists():
        print(f"loading existing key {path}")
        return load_private_key_file(path)
    print(f"generating new key {path} (mode 0600)")
    generate_private_key_file(path)
    return load_private_key_file(path)


def trusted_key(private_key: bytes) -> TrustedKey:
    """Stands in for 'public key fetched from the API and fingerprint verified out of band'."""
    raw = public_key_bytes(private_key)
    return TrustedKey(uuid4(), uuid4(), key_utils.encode_public_key(raw), key_utils.fingerprint(raw))


def run(keys_dir: Path) -> None:
    alice_private = load_or_create(keys_dir / "alice.key")
    bob_private = load_or_create(keys_dir / "bob.key")
    alice, bob = trusted_key(alice_private), trusted_key(bob_private)
    print("alice fingerprint:", alice.fingerprint)
    print("bob   fingerprint:", bob.fingerprint)

    print("\n1) Alice encrypts a fictitious message for Bob")
    envelope = encrypt_message(
        "Olá, Bob! Esta é uma mensagem fictícia 🔐",
        sender_private_key=alice_private, sender=alice, recipient=bob,
    )
    print(json.dumps(envelope.to_dict(), indent=2))

    print("\n2) Bob decrypts it (expecting Alice as sender)")
    result = decrypt_message(
        envelope.to_json(), recipient_private_key=bob_private, recipient=bob, sender=alice
    )
    print("message id:", result.message_id)
    print("plaintext :", result.plaintext)

    print("\n3) A tampered envelope is rejected")
    tampered = bytearray(envelope.ciphertext)
    tampered[0] ^= 1
    bad = Envelope(envelope.message_id, envelope.sender, envelope.recipient, envelope.enc, bytes(tampered))
    try:
        decrypt_message(bad, recipient_private_key=bob_private, recipient=bob, sender=alice)
    except DecryptionError as exc:
        print("rejected:", exc)
    else:
        sys.exit("BUG: tampered envelope was accepted")


if __name__ == "__main__":
    if len(sys.argv) > 2:
        sys.exit(__doc__)
    if len(sys.argv) == 2:
        directory = Path(sys.argv[1])
        directory.mkdir(mode=0o700, exist_ok=True)
        run(directory)
    else:
        with tempfile.TemporaryDirectory() as tmp:
            run(Path(tmp))
