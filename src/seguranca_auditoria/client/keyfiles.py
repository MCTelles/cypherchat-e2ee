"""Raw X25519 keys, protected by POSIX modes or Windows ACLs, never overwritten."""

import os
import stat
import subprocess
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import x25519

PRIVATE_KEY_SIZE = 32


def _windows_acl(path: str | Path, *, secure: bool = False) -> None:
    # Pass paths as data, never interpolate them into PowerShell source.
    script = """
$ErrorActionPreference = 'Stop'
$path = $env:CYPHERCHAT_KEY_PATH
$sid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
"""
    if secure:
        script += """
$acl = New-Object System.Security.AccessControl.FileSecurity
$acl.SetOwner($sid)
$acl.SetAccessRuleProtection($true, $false)
$rule = New-Object System.Security.AccessControl.FileSystemAccessRule($sid, 'FullControl', 'Allow')
$acl.AddAccessRule($rule)
Set-Acl -LiteralPath $path -AclObject $acl
"""
    script += """
$acl = Get-Acl -LiteralPath $path
if ($acl.GetOwner([System.Security.Principal.SecurityIdentifier]) -ne $sid) { exit 1 }
if (-not $acl.AreAccessRulesProtected) { exit 1 }
$rules = $acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])
if ($rules.Count -eq 0) { exit 1 }
foreach ($rule in $rules) {
    if ($rule.AccessControlType -eq 'Allow' -and $rule.IdentityReference -ne $sid) { exit 1 }
}
"""
    result = subprocess.run(
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
        env=dict(os.environ, CYPHERCHAT_KEY_PATH=str(Path(path).resolve())),
        capture_output=True, timeout=30,
        creationflags=subprocess.CREATE_NO_WINDOW,
    )
    if result.returncode:
        raise PermissionError(f"{path}: private key requires a protected Windows ACL granting access only to the current user")


def generate_private_key_file(path: str | Path) -> bytes:
    """Create a new private key file (fails if it exists) and return the raw key."""
    raw = x25519.X25519PrivateKey.generate().private_bytes_raw()
    # O_EXCL: never overwrite an existing file. 0600: owner only.
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f:
        # Windows ignores POSIX mode bits. Secure the empty file before writing.
        if os.name == "nt":
            _windows_acl(path, secure=True)
        f.write(raw)
    return raw


def load_private_key_file(path: str | Path) -> bytes:
    """Load a private key, refusing files that other users can read or write."""
    if os.name == "nt":
        _windows_acl(path)
    else:
        mode = stat.S_IMODE(os.stat(path).st_mode)
        if mode & 0o077:
            raise PermissionError(f"{path}: private key file must not be accessible to group/others (chmod 600)")
    raw = Path(path).read_bytes()
    if len(raw) != PRIVATE_KEY_SIZE:
        raise ValueError(f"{path}: not a raw X25519 private key")
    return raw


def public_key_bytes(private_key: bytes) -> bytes:
    return x25519.X25519PrivateKey.from_private_bytes(private_key).public_key().public_bytes_raw()
