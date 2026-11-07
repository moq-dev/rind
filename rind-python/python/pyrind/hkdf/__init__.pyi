"""Key derivation with HKDF."""

from typing import final, overload

from typing_extensions import Buffer

from pyrind import aead, hmac
from pyrind.hkdf import legacy as legacy

@final
class Algorithm:
    """An HKDF algorithm."""

HKDF_SHA256: Algorithm
HKDF_SHA384: Algorithm
HKDF_SHA512: Algorithm

@final
class Salt:
    """An HKDF salt, which extracts pseudorandom keys from secrets."""

    def __new__(cls, algorithm: Algorithm, value: Buffer) -> Salt:
        """Makes a salt for `algorithm` from `value`, of any length."""
    def extract(self, secret: Buffer) -> Prk:
        """Extracts a pseudorandom key from `secret`."""

@final
class Prk:
    """A pseudorandom key, which expands into any number of keys."""

    @overload
    def expand(self, info: Buffer, key_type: int) -> bytes: ...
    @overload
    def expand(self, info: Buffer, key_type: aead.Algorithm) -> aead.Key: ...
    @overload
    def expand(self, info: Buffer, key_type: hmac.Algorithm) -> hmac.Key: ...

__all__ = ["Algorithm", "Salt", "Prk", "HKDF_SHA256", "HKDF_SHA384", "HKDF_SHA512", "legacy"]
