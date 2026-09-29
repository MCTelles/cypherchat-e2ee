"""Local storage of X25519 private keys: raw 32 bytes, file mode 0600, never overwritten."""

import os
import stat
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import x25519

PRIVATE_KEY_SIZE = 32


def generate_private_key_file(path: str | Path) -> bytes:
    """Create a new private key file (fails if it exists) and return the raw key."""
    raw = x25519.X25519PrivateKey.generate().private_bytes_raw()
    # O_EXCL: never overwrite an existing file. 0600: owner only.
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(raw)
    return raw


def load_private_key_file(path: str | Path) -> bytes:
    """Load a private key, refusing files that other users can read or write."""
    mode = stat.S_IMODE(os.stat(path).st_mode)
    if mode & 0o077:
        raise PermissionError(f"{path}: private key file must not be accessible to group/others (chmod 600)")
    raw = Path(path).read_bytes()
    if len(raw) != PRIVATE_KEY_SIZE:
        raise ValueError(f"{path}: not a raw X25519 private key")
    return raw


def public_key_bytes(private_key: bytes) -> bytes:
    return x25519.X25519PrivateKey.from_private_bytes(private_key).public_key().public_bytes_raw()
