"""HKDF algorithms only legacy protocols should use."""

from pyrind.hkdf import Algorithm

HKDF_SHA1: Algorithm

__all__ = ["HKDF_SHA1"]
