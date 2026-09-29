from pwdlib import PasswordHash
from pwdlib.hashers.argon2 import Argon2Hasher

_password_hash = PasswordHash((Argon2Hasher(),))

# Verified against when the user does not exist, so that unknown users cost
# roughly the same as a wrong password.
_DUMMY_HASH = _password_hash.hash("dummy-password-for-timing-equalization")


def hash_password(password: str) -> str:
    return _password_hash.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    return _password_hash.verify(password, password_hash)


def verify_dummy_password(password: str) -> None:
    _password_hash.verify(password, _DUMMY_HASH)
