"""Client-side end-to-end encryption (no server, database or JWT dependencies)."""

from seguranca_auditoria.client.messages import (
    MAX_ENVELOPE_BYTES,
    MAX_PLAINTEXT_BYTES,
    SUITE_ID,
    DecryptedMessage,
    DecryptionError,
    E2EEError,
    Envelope,
    EnvelopeError,
    KeyMismatchError,
    ParticipantMismatchError,
    TrustedKey,
    decrypt_message,
    encrypt_message,
)

__all__ = [
    "MAX_ENVELOPE_BYTES",
    "MAX_PLAINTEXT_BYTES",
    "SUITE_ID",
    "DecryptedMessage",
    "DecryptionError",
    "E2EEError",
    "Envelope",
    "EnvelopeError",
    "KeyMismatchError",
    "ParticipantMismatchError",
    "TrustedKey",
    "decrypt_message",
    "encrypt_message",
]
