"""Local example: generate an X25519 key pair on the CLIENT side.

Only the public key (Base64 of the 32 raw bytes) and its fingerprint are printed.
The private key is written to a file readable only by you and must never be sent
to the server. This script is a standalone example, not part of the API.

Usage:  uv run python examples/generate_keypair.py private_key.bin
"""

import base64
import hashlib
import os
import sys

from cryptography.hazmat.primitives.asymmetric import x25519


def main(private_key_path: str) -> None:
    private_key = x25519.X25519PrivateKey.generate()
    raw_public = private_key.public_key().public_bytes_raw()

    # O_EXCL: never overwrite an existing file. Mode 0600: owner only.
    fd = os.open(private_key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(private_key.private_bytes_raw())

    print("public_key :", base64.b64encode(raw_public).decode("ascii"))
    print("fingerprint:", hashlib.sha256(raw_public).hexdigest())
    print(f"private key saved to {private_key_path} (keep it secret)", file=sys.stderr)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    main(sys.argv[1])
