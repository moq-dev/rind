"""Message authentication with HMAC."""

from typing import final

from typing_extensions import Buffer

from pyrind.hmac import legacy as legacy

@final
class Algorithm:
    """An HMAC algorithm."""

    @property
    def tag_len(self) -> int:
        """The tag's length in bytes."""

HMAC_SHA256: Algorithm
HMAC_SHA384: Algorithm
HMAC_SHA512: Algorithm

@final
class Key:
    """An HMAC key, whose keyed hash states are computed once."""

    def __new__(cls, algorithm: Algorithm, key: Buffer) -> Key:
        """Makes a key for `algorithm` from `key`, of any length."""

def sign(key: Key, data: Buffer) -> bytes:
    """Returns the tag of `data` under `key`."""

def verify(key: Key, data: Buffer, tag: Buffer) -> None:
    """Checks in constant time that `tag` is the whole tag of `data` under `key`; raises `BadSignature` otherwise, including for a truncated tag."""

@final
class Context:
    """A tag of a message given in pieces, which signs once."""

    def __new__(cls, key: Key) -> Context:
        """Starts a tag under `key`."""
    def update(self, data: Buffer) -> None:
        """Adds `data` to the message."""
    def sign(self) -> bytes:
        """Returns the tag of the message; the context takes no more data."""

__all__ = ["Algorithm", "Key", "Context", "sign", "verify", "HMAC_SHA256", "HMAC_SHA384", "HMAC_SHA512", "legacy"]
