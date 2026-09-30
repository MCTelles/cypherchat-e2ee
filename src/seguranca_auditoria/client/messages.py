"""Message encryption with HPKE (RFC 9180), run on the client.

Suite: mode Auth, DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-128-GCM, via PyHPKE.
Every message gets a fresh encapsulation and a fresh HPKE context that seals once,
so nonces are handled by the protocol (no external nonce). The envelope metadata is
authenticated as AAD. See the README ("Criptografia de mensagens") for the format.
"""

import base64
import binascii
import hmac
import json
from dataclasses import dataclass
from typing import Any
from uuid import UUID, uuid4

from pyhpke import AEADId, CipherSuite, KDFId, KEMId, KEMKeyPair

from seguranca_auditoria.client.keyfiles import public_key_bytes
from seguranca_auditoria.security import keys as key_utils

VERSION = 1
MODE = "auth"
SUITE_ID = "HPKE-Auth-X25519-SHA256-AES128GCM"  # RFC 9180 ids 0x0020 / 0x0001 / 0x0001
INFO = b"CypherChat E2EE v1"

MAX_PLAINTEXT_BYTES = 64 * 1024
MAX_ENVELOPE_BYTES = 128 * 1024
_ENC_SIZE = 32  # serialized X25519 ephemeral public key
_TAG_SIZE = 16  # AES-GCM tag
_MAX_CIPHERTEXT_BYTES = MAX_PLAINTEXT_BYTES + _TAG_SIZE

_ENVELOPE_FIELDS = {"version", "mode", "suite", "message_id", "sender", "recipient", "enc", "ciphertext"}
_PARTICIPANT_FIELDS = {"user_id", "key_id", "fingerprint"}


class E2EEError(Exception):
    """Base class for all errors raised by this module."""


class EnvelopeError(E2EEError):
    """Malformed, oversized or unsupported envelope."""


class ParticipantMismatchError(EnvelopeError):
    """The envelope names participants/keys other than the ones the client expects."""


class KeyMismatchError(E2EEError):
    """A private key does not match the trusted public key declared for it."""


class DecryptionError(E2EEError):
    """Authentication or decryption failed (deliberately uninformative)."""

    def __init__(self) -> None:
        super().__init__("message could not be decrypted or verified")


# ---------------------------------------------------------------- data types

@dataclass(frozen=True)
class TrustedKey:
    """A public key the client has decided to trust.

    `fingerprint` must come from a trusted channel (ideally verified out of band);
    it is checked against the key bytes, never taken from an envelope.
    """

    user_id: UUID
    key_id: UUID
    public_key: str  # canonical Base64 of the 32 raw bytes, as served by the API
    fingerprint: str  # lowercase hex SHA-256 of the raw bytes

    def __post_init__(self) -> None:
        if not isinstance(self.user_id, UUID) or not isinstance(self.key_id, UUID):
            raise TypeError("user_id and key_id must be UUIDs")
        try:
            raw = key_utils.decode_public_key(self.public_key)
        except key_utils.InvalidPublicKeyError as exc:
            raise ValueError(str(exc)) from None
        if not hmac.compare_digest(key_utils.fingerprint(raw), self.fingerprint):
            raise ValueError("fingerprint does not match the public key")

    @property
    def raw(self) -> bytes:
        return key_utils.decode_public_key(self.public_key)

    def _reference(self) -> dict[str, str]:
        return {
            "user_id": str(self.user_id),
            "key_id": str(self.key_id),
            "fingerprint": self.fingerprint,
        }


@dataclass(frozen=True)
class Envelope:
    message_id: UUID
    sender: dict[str, str]
    recipient: dict[str, str]
    enc: bytes
    ciphertext: bytes
    version: int = VERSION
    mode: str = MODE
    suite: str = SUITE_ID

    def _metadata(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "mode": self.mode,
            "suite": self.suite,
            "message_id": str(self.message_id),
            "sender": self.sender,
            "recipient": self.recipient,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            **self._metadata(),
            "enc": _b64(self.enc),
            "ciphertext": _b64(self.ciphertext),
        }

    def to_json(self) -> str:
        return _canonical_json(self.to_dict())

    @classmethod
    def from_json(cls, data: str | bytes) -> "Envelope":
        """Strict parser: size limit, no duplicate/unknown fields, canonical Base64."""
        if isinstance(data, str):
            try:
                data = data.encode("utf-8")
            except UnicodeEncodeError:
                raise EnvelopeError("invalid envelope") from None
        if not isinstance(data, bytes | bytearray):
            raise EnvelopeError("invalid envelope")
        if len(data) > MAX_ENVELOPE_BYTES:
            raise EnvelopeError("envelope too large")
        try:
            obj = json.loads(
                bytes(data).decode("utf-8"),
                object_pairs_hook=_no_duplicate_keys,
                parse_constant=_reject_constant,
            )
        except (ValueError, RecursionError):
            raise EnvelopeError("invalid envelope") from None
        return cls._from_obj(obj)

    @classmethod
    def _from_obj(cls, obj: Any) -> "Envelope":
        if not isinstance(obj, dict) or set(obj) != _ENVELOPE_FIELDS:
            raise EnvelopeError("invalid envelope structure")
        # Unsupported versions/modes/suites are rejected outright: no fallback.
        if type(obj["version"]) is not int or obj["version"] != VERSION:
            raise EnvelopeError("unsupported version")
        if obj["mode"] != MODE:
            raise EnvelopeError("unsupported mode")
        if obj["suite"] != SUITE_ID:
            raise EnvelopeError("unsupported suite")
        return cls(
            message_id=_parse_uuid(obj["message_id"]),
            sender=_parse_participant(obj["sender"]),
            recipient=_parse_participant(obj["recipient"]),
            enc=_b64decode(obj["enc"], _ENC_SIZE, _ENC_SIZE),
            ciphertext=_b64decode(obj["ciphertext"], _TAG_SIZE + 1, _MAX_CIPHERTEXT_BYTES),
        )


@dataclass(frozen=True)
class DecryptedMessage:
    message_id: UUID
    plaintext: str


# ------------------------------------------------------------- public API

def encrypt_message(
    plaintext: str,
    *,
    sender_private_key: bytes,
    sender: TrustedKey,
    recipient: TrustedKey,
    message_id: UUID | None = None,
) -> Envelope:
    """Encrypt `plaintext` from `sender` to `recipient` (HPKE Auth mode).

    `sender_private_key` is the raw 32-byte X25519 key matching `sender.public_key`.
    `recipient` must be a public key the caller has verified.
    """
    if not isinstance(plaintext, str):
        raise TypeError("plaintext must be str")
    data = plaintext.encode("utf-8")
    if not data:
        raise EnvelopeError("message must not be empty")
    if len(data) > MAX_PLAINTEXT_BYTES:
        raise EnvelopeError("message too large")
    _check_private_key(sender_private_key, sender)

    envelope = Envelope(
        message_id=message_id or uuid4(),
        sender=sender._reference(),
        recipient=recipient._reference(),
        enc=b"",
        ciphertext=b"",
    )
    enc, ciphertext = _seal(
        sender_private_key, recipient.raw, INFO, _aad(envelope), data
    )
    return Envelope(
        message_id=envelope.message_id,
        sender=envelope.sender,
        recipient=envelope.recipient,
        enc=enc,
        ciphertext=ciphertext,
    )


def decrypt_message(
    envelope: Envelope | str | bytes,
    *,
    recipient_private_key: bytes,
    recipient: TrustedKey,
    sender: TrustedKey,
) -> DecryptedMessage:
    """Decrypt and verify an envelope addressed to `recipient` from `sender`.

    `recipient` (the caller) and `sender` (the expected sender) come from the client's
    own trust store: the envelope's participants are only compared against them.
    Nothing is returned unless authentication succeeds.
    """
    if not isinstance(envelope, Envelope):
        envelope = Envelope.from_json(envelope)
    _check_private_key(recipient_private_key, recipient)

    if envelope.sender != sender._reference() or envelope.recipient != recipient._reference():
        raise ParticipantMismatchError("envelope participants do not match the expected ones")

    try:
        data = _open(
            envelope.enc, recipient_private_key, sender.raw, INFO, _aad(envelope), envelope.ciphertext
        )
        return DecryptedMessage(envelope.message_id, data.decode("utf-8"))
    except Exception:
        raise DecryptionError from None


# ---------------------------------------------------------------- internals

def _suite() -> CipherSuite:
    return CipherSuite.new(KEMId.DHKEM_X25519_HKDF_SHA256, KDFId.HKDF_SHA256, AEADId.AES128_GCM)


def _seal(
    sender_sk: bytes,
    recipient_pk: bytes,
    info: bytes,
    aad: bytes,
    plaintext: bytes,
    _ephemeral: KEMKeyPair | None = None,  # tests only (RFC 9180 vectors); never set in production
) -> tuple[bytes, bytes]:
    """One fresh Auth-mode sender context, one seal. Returns (enc, ciphertext||tag)."""
    suite = _suite()
    enc, context = suite.create_sender_context(
        suite.kem.deserialize_public_key(recipient_pk),
        info=info,
        sks=suite.kem.deserialize_private_key(sender_sk),
        eks=_ephemeral,
    )
    return enc, context.seal(plaintext, aad=aad)


def _open(
    enc: bytes, recipient_sk: bytes, sender_pk: bytes, info: bytes, aad: bytes, ciphertext: bytes
) -> bytes:
    suite = _suite()
    context = suite.create_recipient_context(
        enc,
        suite.kem.deserialize_private_key(recipient_sk),
        info=info,
        pks=suite.kem.deserialize_public_key(sender_pk),
    )
    return context.open(ciphertext, aad=aad)


def _check_private_key(private_key: bytes, trusted: TrustedKey) -> None:
    if not isinstance(private_key, bytes | bytearray) or len(private_key) != 32:
        raise KeyMismatchError("private key must be 32 raw bytes")
    try:
        derived_public = public_key_bytes(bytes(private_key))
    except Exception:
        raise KeyMismatchError("invalid private key") from None
    if not hmac.compare_digest(derived_public, trusted.raw):
        raise KeyMismatchError("private key does not match the trusted public key")


def _aad(envelope: Envelope) -> bytes:
    """Deterministic serialization of the authenticated metadata."""
    return _canonical_json(envelope._metadata()).encode("ascii")


def _canonical_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def _b64decode(value: Any, min_size: int, max_size: int) -> bytes:
    if not isinstance(value, str) or len(value) > (max_size + 2) // 3 * 4:
        raise EnvelopeError("invalid envelope field")
    try:
        raw = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError):
        raise EnvelopeError("invalid envelope field") from None
    if _b64(raw) != value or not min_size <= len(raw) <= max_size:
        raise EnvelopeError("invalid envelope field")
    return raw


def _parse_uuid(value: Any) -> UUID:
    try:
        parsed = UUID(value)
    except (ValueError, TypeError, AttributeError):
        raise EnvelopeError("invalid envelope field") from None
    if str(parsed) != value:  # canonical lowercase hyphenated form only
        raise EnvelopeError("invalid envelope field")
    return parsed


def _parse_participant(value: Any) -> dict[str, str]:
    if not isinstance(value, dict) or set(value) != _PARTICIPANT_FIELDS:
        raise EnvelopeError("invalid envelope structure")
    fingerprint = value["fingerprint"]
    if (
        not isinstance(fingerprint, str)
        or len(fingerprint) != 64
        or any(c not in "0123456789abcdef" for c in fingerprint)
    ):
        raise EnvelopeError("invalid envelope field")
    return {
        "user_id": str(_parse_uuid(value["user_id"])),
        "key_id": str(_parse_uuid(value["key_id"])),
        "fingerprint": fingerprint,
    }


def _no_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate key")
        result[key] = value
    return result


def _reject_constant(_: str) -> Any:
    raise ValueError("invalid JSON constant")
