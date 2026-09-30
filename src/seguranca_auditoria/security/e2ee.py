"""Client-side envelope encryption. Private keys never belong on the server."""

import base64
import json
import os
from dataclasses import dataclass
from hashlib import sha256
from uuid import UUID

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

ALGORITHM = "X25519-HKDF-SHA256-AES256GCM-Ed25519-v1"


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def unb64(value: str) -> bytes:
    if not isinstance(value, str):
        raise ValueError("Base64 inválido")
    raw = base64.b64decode(value, validate=True)
    if b64(raw) != value:
        raise ValueError("Base64 não canônico")
    return raw


def fingerprint(encryption_public_key: bytes, signing_public_key: bytes) -> str:
    return sha256(encryption_public_key + signing_public_key).hexdigest()


def _raw_public(key: x25519.X25519PublicKey | ed25519.Ed25519PublicKey) -> bytes:
    from cryptography.hazmat.primitives import serialization

    return key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def _raw_private(key: x25519.X25519PrivateKey | ed25519.Ed25519PrivateKey) -> bytes:
    from cryptography.hazmat.primitives import serialization

    return key.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )


@dataclass(frozen=True)
class Identity:
    encryption_key: x25519.X25519PrivateKey
    signing_key: ed25519.Ed25519PrivateKey

    @classmethod
    def generate(cls) -> "Identity":
        return cls(x25519.X25519PrivateKey.generate(), ed25519.Ed25519PrivateKey.generate())

    @property
    def public_key(self) -> bytes:
        return _raw_public(self.encryption_key.public_key())

    @property
    def signing_public_key(self) -> bytes:
        return _raw_public(self.signing_key.public_key())

    @property
    def fingerprint(self) -> str:
        return fingerprint(self.public_key, self.signing_public_key)

    def protect(self, password: str) -> bytes:
        """Encrypt both private keys for storage in the local user's home folder."""
        if len(password) < 12:
            raise ValueError("A senha local deve ter pelo menos 12 caracteres")
        salt, nonce = os.urandom(16), os.urandom(12)
        key = Scrypt(salt=salt, length=32, n=2**15, r=8, p=1).derive(password.encode())
        payload = json.dumps(
            {"encryption": b64(_raw_private(self.encryption_key)),
             "signing": b64(_raw_private(self.signing_key))},
            separators=(",", ":"),
        ).encode()
        return json.dumps({"version": 1, "salt": b64(salt), "nonce": b64(nonce),
                           "data": b64(AESGCM(key).encrypt(nonce, payload, b"cypherchat-key-v1"))}).encode()

    @classmethod
    def unprotect(cls, blob: bytes, password: str) -> "Identity":
        data = json.loads(blob)
        if data.get("version") != 1:
            raise ValueError("Formato de chave não suportado")
        key = Scrypt(salt=unb64(data["salt"]), length=32, n=2**15, r=8, p=1).derive(password.encode())
        raw = AESGCM(key).decrypt(unb64(data["nonce"]), unb64(data["data"]), b"cypherchat-key-v1")
        keys = json.loads(raw)
        return cls(x25519.X25519PrivateKey.from_private_bytes(unb64(keys["encryption"])),
                   ed25519.Ed25519PrivateKey.from_private_bytes(unb64(keys["signing"])))


def _signed_bytes(envelope: dict) -> bytes:
    fields = ("algorithm", "sender_id", "recipient_id", "ephemeral_public_key", "nonce", "ciphertext")
    return json.dumps({name: envelope[name] for name in fields}, sort_keys=True, separators=(",", ":")).encode()


def _derive(shared_secret: bytes, nonce: bytes, sender_id: UUID, recipient_id: UUID) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=nonce,
                info=b"cypherchat-v1" + sender_id.bytes + recipient_id.bytes).derive(shared_secret)


def encrypt(identity: Identity, recipient_public_key: bytes, sender_id: UUID,
            recipient_id: UUID, plaintext: str) -> dict[str, str]:
    ephemeral = x25519.X25519PrivateKey.generate()
    recipient = x25519.X25519PublicKey.from_public_bytes(recipient_public_key)
    nonce = os.urandom(12)
    key = _derive(ephemeral.exchange(recipient), nonce, sender_id, recipient_id)
    aad = sender_id.bytes + recipient_id.bytes
    envelope = {
        "algorithm": ALGORITHM,
        "sender_id": str(sender_id),
        "recipient_id": str(recipient_id),
        "ephemeral_public_key": b64(_raw_public(ephemeral.public_key())),
        "nonce": b64(nonce),
        "ciphertext": b64(AESGCM(key).encrypt(nonce, plaintext.encode(), aad)),
    }
    envelope["signature"] = b64(identity.signing_key.sign(_signed_bytes(envelope)))
    return envelope


def decrypt(identity: Identity, sender_signing_public_key: bytes, envelope: dict) -> str:
    if envelope.get("algorithm") != ALGORITHM:
        raise ValueError("Algoritmo inválido")
    ed25519.Ed25519PublicKey.from_public_bytes(sender_signing_public_key).verify(
        unb64(envelope["signature"]), _signed_bytes(envelope)
    )
    sender_id, recipient_id = UUID(envelope["sender_id"]), UUID(envelope["recipient_id"])
    nonce = unb64(envelope["nonce"])
    if len(nonce) != 12:
        raise ValueError("Nonce inválido")
    ephemeral = x25519.X25519PublicKey.from_public_bytes(unb64(envelope["ephemeral_public_key"]))
    key = _derive(identity.encryption_key.exchange(ephemeral), nonce, sender_id, recipient_id)
    return AESGCM(key).decrypt(nonce, unb64(envelope["ciphertext"]), sender_id.bytes + recipient_id.bytes).decode()
