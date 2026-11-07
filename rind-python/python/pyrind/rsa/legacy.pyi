"""RSA-OAEP with SHA-1, for protocols that still require it."""

from pyrind.rsa import OaepAlgorithm

OAEP_SHA1: OaepAlgorithm

__all__ = ["OAEP_SHA1"]
