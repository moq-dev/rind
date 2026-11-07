"""Password-based key derivation with PBKDF2."""

from typing import final

from typing_extensions import Buffer

from pyrind.pbkdf2 import legacy as legacy

@final
class Algorithm:
    """A PBKDF2 algorithm."""

PBKDF2_HMAC_SHA256: Algorithm
PBKDF2_HMAC_SHA384: Algorithm
PBKDF2_HMAC_SHA512: Algorithm

@final
class Secret:
    """A password keyed into HMAC once, which derives keys for any salt and iteration count.

    Both calls release the GIL while they run.
    """

    def __new__(cls, algorithm: Algorithm, secret: Buffer) -> Secret:
        """Keys `algorithm` with `secret`, a password of any length."""
    def derive(self, iterations: int, salt: Buffer, length: int) -> bytes:
        """Derives `length` bytes for `salt` with `iterations`."""
    def verify(self, iterations: int, salt: Buffer, previously_derived: Buffer) -> None:
        """Checks in constant time that `previously_derived` is what `derive` returns for `salt` and `iterations`; raises `BadSignature` otherwise."""

__all__ = ["Algorithm", "Secret", "PBKDF2_HMAC_SHA256", "PBKDF2_HMAC_SHA384", "PBKDF2_HMAC_SHA512", "legacy"]
