import copy
import json
import os
import subprocess
import sys
from pathlib import Path
from uuid import UUID, uuid4

import pytest
from pyhpke import AEADId, CipherSuite, KDFId, KEMId

from seguranca_auditoria.client import (
    MAX_ENVELOPE_BYTES,
    MAX_PLAINTEXT_BYTES,
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
from seguranca_auditoria.client import messages
from seguranca_auditoria.client.keyfiles import (
    generate_private_key_file,
    load_private_key_file,
    public_key_bytes,
)
from seguranca_auditoria.security import keys as key_utils


class Party:
    def __init__(self):
        self.user_id, self.key_id = uuid4(), uuid4()
        self.private = os.urandom(32)  # any 32 bytes is a valid X25519 private key
        raw = public_key_bytes(self.private)
        self.trusted = TrustedKey(
            self.user_id, self.key_id, key_utils.encode_public_key(raw), key_utils.fingerprint(raw)
        )


@pytest.fixture
def alice():
    return Party()


@pytest.fixture
def bob():
    return Party()


def enc(alice, bob, text="Olá, Bob! Mensagem fictícia."):
    return encrypt_message(text, sender_private_key=alice.private, sender=alice.trusted, recipient=bob.trusted)


def dec(envelope, alice, bob, **overrides):
    kwargs = dict(recipient_private_key=bob.private, recipient=bob.trusted, sender=alice.trusted)
    kwargs.update(overrides)
    return decrypt_message(envelope, **kwargs)


# ---------- official RFC 9180 vector (mode auth, DHKEM(X25519), HKDF-SHA256, AES-128-GCM) ----------

VECTOR = json.loads((Path(__file__).parent / "fixtures" / "rfc9180_a1_3_auth.json").read_text())


def test_rfc9180_vector_suite_ids_match_our_suite():
    assert (VECTOR["mode"], VECTOR["kem_id"], VECTOR["kdf_id"], VECTOR["aead_id"]) == (2, 0x20, 1, 1)


def test_rfc9180_vector_seal_matches_official_ciphertexts():
    suite = messages._suite()
    ephemeral = suite.kem.derive_key_pair(bytes.fromhex(VECTOR["ikmE"]))
    for item in VECTOR["encryptions"][:1]:  # our contexts seal exactly once (sequence 0)
        enc_, ct = messages._seal(
            bytes.fromhex(VECTOR["skSm"]),
            bytes.fromhex(VECTOR["pkRm"]),
            bytes.fromhex(VECTOR["info"]),
            bytes.fromhex(item["aad"]),
            bytes.fromhex(item["pt"]),
            _ephemeral=ephemeral,
        )
        assert enc_.hex() == VECTOR["enc"] == VECTOR["pkEm"]
        assert ct.hex() == item["ct"]


def test_rfc9180_vector_open_matches_official_plaintext():
    item = VECTOR["encryptions"][0]
    pt = messages._open(
        bytes.fromhex(VECTOR["enc"]),
        bytes.fromhex(VECTOR["skRm"]),
        bytes.fromhex(VECTOR["pkSm"]),
        bytes.fromhex(VECTOR["info"]),
        bytes.fromhex(item["aad"]),
        bytes.fromhex(item["ct"]),
    )
    assert pt.hex() == item["pt"]


def test_rfc9180_vector_rejects_wrong_sender_key():
    item = VECTOR["encryptions"][0]
    with pytest.raises(Exception):
        messages._open(
            bytes.fromhex(VECTOR["enc"]), bytes.fromhex(VECTOR["skRm"]), public_key_bytes(os.urandom(32)),
            bytes.fromhex(VECTOR["info"]), bytes.fromhex(item["aad"]), bytes.fromhex(item["ct"]),
        )


def test_rfc9180_vector_internal_values_via_library():
    # Sanity: the library itself derives the vector's key schedule outputs.
    suite = CipherSuite.new(KEMId.DHKEM_X25519_HKDF_SHA256, KDFId.HKDF_SHA256, AEADId.AES128_GCM)
    ephemeral = suite.kem.derive_key_pair(bytes.fromhex(VECTOR["ikmE"]))
    shared, enc_ = suite.kem.encap(
        suite.kem.deserialize_public_key(bytes.fromhex(VECTOR["pkRm"])),
        suite.kem.deserialize_private_key(bytes.fromhex(VECTOR["skSm"])),
        ephemeral,
    )
    assert shared.hex() == VECTOR["shared_secret"] and enc_.hex() == VECTOR["enc"]


# ---------- round trip ----------

def test_round_trip(alice, bob):
    envelope = enc(alice, bob)
    result = dec(envelope.to_json(), alice, bob)
    assert result.plaintext == "Olá, Bob! Mensagem fictícia."
    assert result.message_id == envelope.message_id


@pytest.mark.parametrize("text", ["Ação, coração e pão de queijo 🇧🇷", "😀🔐🚀", "a", "日本語 العربية", "linha1\nlinha2\t\u0000fim"])
def test_round_trip_unicode(alice, bob, text):
    assert dec(enc(alice, bob, text), alice, bob).plaintext == text


def test_envelope_accepts_object_or_json_string_or_bytes(alice, bob):
    envelope = enc(alice, bob)
    for value in (envelope, envelope.to_json(), envelope.to_json().encode()):
        assert dec(value, alice, bob).plaintext


def test_envelope_format_and_no_plaintext_leak(alice, bob):
    envelope = enc(alice, bob, "segredo-fictício")
    obj = json.loads(envelope.to_json())
    assert set(obj) == {"version", "mode", "suite", "message_id", "sender", "recipient", "enc", "ciphertext"}
    assert obj["version"] == 1 and obj["mode"] == "auth" and obj["suite"] == messages.SUITE_ID
    assert obj["sender"] == {"user_id": str(alice.user_id), "key_id": str(alice.key_id), "fingerprint": alice.trusted.fingerprint}
    assert "nonce" not in obj and "segredo" not in envelope.to_json()
    assert len(envelope.enc) == 32 and len(envelope.ciphertext) == len("segredo-fictício".encode()) + 16
    assert len(messages.SUITE_ID) <= 50  # fits encrypted_messages.algorithm


def test_two_encryptions_of_same_message_differ(alice, bob):
    a = enc(alice, bob, "igual")
    b = encrypt_message("igual", sender_private_key=alice.private, sender=alice.trusted,
                        recipient=bob.trusted, message_id=a.message_id)
    assert a.message_id == b.message_id
    assert a.enc != b.enc and a.ciphertext != b.ciphertext


def test_aad_is_deterministic(alice, bob):
    e = enc(alice, bob)
    assert messages._aad(e) == messages._aad(Envelope.from_json(e.to_json()))


# ---------- wrong keys / trust ----------

def test_wrong_recipient_private_key(alice, bob):
    with pytest.raises(KeyMismatchError):
        dec(enc(alice, bob), alice, bob, recipient_private_key=os.urandom(32))


def test_recipient_private_key_of_someone_else_who_is_trusted_as_recipient(alice, bob):
    eve = Party()
    # Eve pretends to be the recipient with her own key pair: participants do not match.
    with pytest.raises(ParticipantMismatchError):
        dec(enc(alice, bob), alice, bob, recipient_private_key=eve.private, recipient=eve.trusted)


def test_wrong_sender_public_key(alice, bob):
    mallory = Party()
    envelope = enc(alice, bob)
    with pytest.raises(ParticipantMismatchError):
        dec(envelope, alice, bob, sender=mallory.trusted)
    # Same ids and fingerprint claims, but a substituted key: TrustedKey itself refuses.
    with pytest.raises(ValueError):
        TrustedKey(alice.user_id, alice.key_id, mallory.trusted.public_key, alice.trusted.fingerprint)


def test_crypto_layer_rejects_wrong_sender_key_even_if_participants_match(alice, bob):
    # Bypass the metadata comparison: the HPKE Auth mode itself must fail.
    envelope = enc(alice, bob)
    mallory = Party()
    with pytest.raises(Exception):
        messages._open(envelope.enc, bob.private, mallory.trusted.raw, messages.INFO,
                       messages._aad(envelope), envelope.ciphertext)


def test_fingerprint_mismatch_when_building_trusted_key(alice):
    with pytest.raises(ValueError):
        TrustedKey(alice.user_id, alice.key_id, alice.trusted.public_key, "0" * 64)
    with pytest.raises(ValueError):
        TrustedKey(alice.user_id, alice.key_id, alice.trusted.public_key, alice.trusted.fingerprint.upper())


def test_sender_private_key_must_match_declared_sender(alice, bob):
    with pytest.raises(KeyMismatchError):
        encrypt_message("x", sender_private_key=os.urandom(32), sender=alice.trusted, recipient=bob.trusted)
    with pytest.raises(KeyMismatchError):
        encrypt_message("x", sender_private_key=b"short", sender=alice.trusted, recipient=bob.trusted)


def test_envelope_public_keys_are_never_trusted_from_the_envelope(alice, bob):
    # There is simply no public key field in the envelope to trust.
    assert "public_key" not in json.loads(enc(alice, bob).to_json())


# ---------- tampering ----------

def flip(b: bytes, i=0) -> bytes:
    return b[:i] + bytes([b[i] ^ 1]) + b[i + 1:]


def with_fields(envelope: Envelope, **changes) -> Envelope:
    obj = envelope.to_dict()
    obj.update(changes)
    return Envelope.from_json(json.dumps(obj))


def test_tampered_ciphertext(alice, bob):
    e = enc(alice, bob)
    for i in (0, len(e.ciphertext) // 2, len(e.ciphertext) - 1):  # body and tag
        bad = Envelope(e.message_id, e.sender, e.recipient, e.enc, flip(e.ciphertext, i))
        with pytest.raises(DecryptionError):
            dec(bad, alice, bob)


def test_tampered_encapsulation(alice, bob):
    e = enc(alice, bob)
    for i in (0, 31):
        bad = Envelope(e.message_id, e.sender, e.recipient, flip(e.enc, i), e.ciphertext)
        with pytest.raises(DecryptionError):
            dec(bad, alice, bob)


def test_low_order_encapsulation_is_rejected(alice, bob):
    e = enc(alice, bob)
    bad = Envelope(e.message_id, e.sender, e.recipient, bytes(32), e.ciphertext)
    with pytest.raises(DecryptionError):
        dec(bad, alice, bob)


def test_tampered_message_id_breaks_authentication(alice, bob):
    e = enc(alice, bob)
    bad = with_fields(e, message_id=str(uuid4()))
    with pytest.raises(DecryptionError):
        dec(bad, alice, bob)


@pytest.mark.parametrize("who,field", [("sender", "user_id"), ("sender", "key_id"), ("recipient", "user_id"), ("recipient", "key_id")])
def test_tampered_participant_ids_are_bound_by_aad(alice, bob, who, field):
    """Even if the receiving client is fooled into expecting the forged value,
    the AAD (and therefore authentication) no longer matches."""
    e = enc(alice, bob)
    forged = str(uuid4())
    party = alice if who == "sender" else bob
    fake_trusted = TrustedKey(
        UUID(forged) if field == "user_id" else party.user_id,
        UUID(forged) if field == "key_id" else party.key_id,
        party.trusted.public_key, party.trusted.fingerprint,
    )
    bad = with_fields(e, **{who: {**e.to_dict()[who], field: forged}})
    kwargs = {"sender": fake_trusted} if who == "sender" else {"recipient": fake_trusted}
    with pytest.raises(DecryptionError):
        dec(bad, alice, bob, **kwargs)


@pytest.mark.parametrize("who", ["sender", "recipient"])
@pytest.mark.parametrize("field", ["user_id", "key_id", "fingerprint"])
def test_tampered_participants_rejected_against_expected_values(alice, bob, who, field):
    e = enc(alice, bob)
    value = "a" * 64 if field == "fingerprint" else str(uuid4())
    bad = with_fields(e, **{who: {**e.to_dict()[who], field: value}})
    with pytest.raises(ParticipantMismatchError):
        dec(bad, alice, bob)


def test_swapped_direction_is_rejected(alice, bob):
    with pytest.raises(E2EEError):
        decrypt_message(enc(alice, bob), recipient_private_key=alice.private, recipient=alice.trusted, sender=bob.trusted)


def test_failure_message_is_uninformative_and_holds_no_plaintext(alice, bob):
    e = enc(alice, bob, "conteudo-secreto")
    bad = Envelope(e.message_id, e.sender, e.recipient, e.enc, flip(e.ciphertext, 3))
    with pytest.raises(DecryptionError) as exc:
        dec(bad, alice, bob)
    assert "secreto" not in str(exc.value) and exc.value.__cause__ is None
    assert exc.value.__suppress_context__ is True


# ---------- malformed envelopes and limits ----------

def test_truncated_and_garbage_envelopes(alice, bob):
    text = enc(alice, bob).to_json()
    for bad in (text[:-1], text[: len(text) // 2], "", "{}", "[]", "null", "not json", b"\xff\xfe"):
        with pytest.raises(EnvelopeError):
            dec(bad, alice, bob)


def test_unknown_missing_and_duplicate_fields(alice, bob):
    obj = enc(alice, bob).to_dict()
    with_extra = {**obj, "nonce": "AAAA"}
    missing = {k: v for k, v in obj.items() if k != "enc"}
    for bad in (json.dumps(with_extra), json.dumps(missing)):
        with pytest.raises(EnvelopeError):
            dec(bad, alice, bob)
    dup = enc(alice, bob).to_json().replace('"mode":"auth"', '"mode":"auth","mode":"auth"')
    with pytest.raises(EnvelopeError):
        dec(dup, alice, bob)


@pytest.mark.parametrize(
    "field,value",
    [
        ("message_id", "not-a-uuid"), ("message_id", str(uuid4()).upper()), ("message_id", 1), ("message_id", None),
        ("enc", "!!!!"), ("enc", 5), ("enc", "AAAA"), ("ciphertext", "AAAA"), ("ciphertext", ""),
        ("sender", "x"), ("recipient", {}), ("sender", {"user_id": 1, "key_id": 2, "fingerprint": 3}),
    ],
)
def test_invalid_field_values(alice, bob, field, value):
    bad = {**enc(alice, bob).to_dict(), field: value}
    with pytest.raises(EnvelopeError):
        dec(json.dumps(bad), alice, bob)


def test_non_canonical_base64_rejected(alice, bob):
    e = enc(alice, bob)
    obj = e.to_dict()
    obj["enc"] = obj["enc"].rstrip("=")
    with pytest.raises(EnvelopeError):
        dec(json.dumps(obj), alice, bob)


def test_participant_fingerprint_format(alice, bob):
    obj = enc(alice, bob).to_dict()
    obj["sender"] = {**obj["sender"], "fingerprint": obj["sender"]["fingerprint"].upper()}
    with pytest.raises(EnvelopeError):
        dec(json.dumps(obj), alice, bob)


def test_size_limits(alice, bob):
    with pytest.raises(EnvelopeError):
        enc(alice, bob, "")
    biggest = "a" * MAX_PLAINTEXT_BYTES
    assert dec(enc(alice, bob, biggest), alice, bob).plaintext == biggest
    assert len(enc(alice, bob, biggest).to_json()) < MAX_ENVELOPE_BYTES
    with pytest.raises(EnvelopeError):
        enc(alice, bob, "a" * (MAX_PLAINTEXT_BYTES + 1))
    with pytest.raises(EnvelopeError):
        enc(alice, bob, "é" * (MAX_PLAINTEXT_BYTES // 2 + 1))  # counted in UTF-8 bytes
    with pytest.raises(EnvelopeError):
        dec("x" * (MAX_ENVELOPE_BYTES + 1), alice, bob)
    with pytest.raises(TypeError):
        encrypt_message(b"bytes", sender_private_key=alice.private, sender=alice.trusted, recipient=bob.trusted)


def test_oversized_ciphertext_field_rejected(alice, bob):
    obj = enc(alice, bob).to_dict()
    obj["ciphertext"] = "A" * 4 * ((MAX_PLAINTEXT_BYTES + 16) // 3 + 2)
    with pytest.raises(EnvelopeError):
        dec(json.dumps(obj), alice, bob)


@pytest.mark.parametrize(
    "field,value",
    [("version", 2), ("version", 0), ("version", "1"), ("version", True), ("version", 1.0),
     ("mode", "base"), ("mode", "psk"), ("mode", "auth_psk"), ("mode", "AUTH"),
     ("suite", "HPKE-Base-X25519-SHA256-AES128GCM"), ("suite", "HPKE-Auth-X25519-SHA256-CHACHA20"), ("suite", "")],
)
def test_unsupported_version_mode_suite(alice, bob, field, value):
    bad = {**enc(alice, bob).to_dict(), field: value}
    with pytest.raises(EnvelopeError) as exc:
        dec(json.dumps(bad), alice, bob)
    assert not isinstance(exc.value, (DecryptionError,))


def test_nan_and_deep_nesting_rejected(alice, bob):
    for bad in ('{"version": NaN}', "[" * 100000 + "]" * 100000):
        with pytest.raises(EnvelopeError):
            dec(bad, alice, bob)


# ---------- independence, key files ----------

def test_client_module_does_not_import_server_stack():
    code = (
        "import sys, seguranca_auditoria.client;"
        "bad=[m for m in ('fastapi','sqlmodel','sqlalchemy','jwt','pydantic','pydantic_settings','psycopg','starlette') if m in sys.modules];"
        "print(bad)"
    )
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, check=True).stdout
    assert out.strip() == "[]"


def test_private_key_files(tmp_path):
    path = tmp_path / "k.bin"
    raw = generate_private_key_file(path)
    assert oct(path.stat().st_mode & 0o777) == "0o600" and len(raw) == 32
    assert load_private_key_file(path) == raw
    with pytest.raises(FileExistsError):
        generate_private_key_file(path)
    assert load_private_key_file(path) == raw  # not overwritten
    path.chmod(0o644)
    with pytest.raises(PermissionError):
        load_private_key_file(path)
    short = tmp_path / "short.bin"
    short.write_bytes(b"x")
    short.chmod(0o600)
    with pytest.raises(ValueError):
        load_private_key_file(short)
