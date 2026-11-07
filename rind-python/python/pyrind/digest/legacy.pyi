"""Hash functions only legacy protocols should use."""

from pyrind.digest import Algorithm

MD5: Algorithm
SHA1: Algorithm

__all__ = ["MD5", "SHA1"]
