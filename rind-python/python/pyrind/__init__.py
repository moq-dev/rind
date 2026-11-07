"""rind's cryptography for Python.

Each rind module is a submodule: `pyrind.aead`, `pyrind.agreement`,
`pyrind.cpu`, `pyrind.digest`, `pyrind.hkdf`, `pyrind.hmac`, `pyrind.kem`,
`pyrind.pbkdf2`, `pyrind.rsa`, and `pyrind.signature`. Every failure raises
a subclass of `pyrind.Error`.

Importing pyrind raises `ImportError` on a CPU missing a feature rind
requires, naming it.
"""

from pyrind._rind import (
    BadSignature,
    DecryptFailed,
    Error,
    Fault,
    KeyRejected,
    RngFailed,
    Unsupported,
    WrongLength,
    aead,
    agreement,
    cpu,
    digest,
    hkdf,
    hmac,
    kem,
    pbkdf2,
    rsa,
    signature,
)

__all__ = [
    "BadSignature",
    "DecryptFailed",
    "Error",
    "Fault",
    "KeyRejected",
    "RngFailed",
    "Unsupported",
    "WrongLength",
    "aead",
    "agreement",
    "cpu",
    "digest",
    "hkdf",
    "hmac",
    "kem",
    "pbkdf2",
    "rsa",
    "signature",
]
