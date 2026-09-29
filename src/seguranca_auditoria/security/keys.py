"""Validation of client-supplied public keys (format only, not proof of possession)."""

import base64
import binascii
import hashlib

from cryptography.hazmat.primitives.asymmetric import x25519

SUPPORTED_ALGORITHM = "X25519"
X25519_KEY_SIZE = 32


class InvalidPublicKeyError(ValueError):
    """The submitted public key is not a valid key for the algorithm."""


def decode_public_key(encoded: str) -> bytes:
    """Decode a canonical Base64 (RFC 4648, with padding) X25519 public key.

    Returns the 32 raw bytes. Rejects invalid Base64, non-canonical encodings,
    wrong length and small-order points (which yield an all-zero shared secret).
    """
    try:
        raw = base64.b64decode(encoded, validate=True)
    except (binascii.Error, ValueError):
        raise InvalidPublicKeyError("public_key must be valid Base64") from None
    if base64.b64encode(raw).decode("ascii") != encoded:
        raise InvalidPublicKeyError("public_key must use canonical Base64 with padding")
    if len(raw) != X25519_KEY_SIZE:
        raise InvalidPublicKeyError(
            f"X25519 public keys must have {X25519_KEY_SIZE} bytes"
        )
    try:
        peer = x25519.X25519PublicKey.from_public_bytes(raw)
        # Small-order points make the shared secret all zeros; OpenSSL rejects them.
        x25519.X25519PrivateKey.generate().exchange(peer)
    except ValueError:
        raise InvalidPublicKeyError("public_key is not a valid X25519 key") from None
    return raw


def encode_public_key(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def fingerprint(raw: bytes) -> str:
    """SHA-256 (lowercase hex) over the 32 raw public key bytes."""
    return hashlib.sha256(raw).hexdigest()
