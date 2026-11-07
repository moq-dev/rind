"""Authenticated encryption: AES-GCM and ChaCha20-Poly1305 with the caller's
nonces, and XChaCha20-Poly1305 with random ones."""

from typing import final

from typing_extensions import Buffer

@final
class Algorithm:
    """An AEAD algorithm."""

    @property
    def key_len(self) -> int:
        """The key's length in bytes."""
    @property
    def nonce_len(self) -> int:
        """The nonce's length in bytes."""
    @property
    def tag_len(self) -> int:
        """The tag's length in bytes."""

AES_128_GCM: Algorithm
AES_192_GCM: Algorithm
AES_256_GCM: Algorithm
CHACHA20_POLY1305: Algorithm

@final
class Key:
    """An AEAD key, which seals with the caller's nonces.

    Sealing two messages with one nonce under one key loses confidentiality
    and lets anyone forge messages, so derive nonces from state that never
    repeats, such as a sequence number, or use `RandomizedNonceKey`.
    """

    def __new__(cls, algorithm: Algorithm, key: Buffer) -> Key:
        """Expands `key` for `algorithm`; raises `WrongLength` unless it is `algorithm.key_len` bytes."""
    def seal(self, nonce: Buffer, plaintext: Buffer, *, aad: Buffer) -> bytes:
        """Encrypts `plaintext` under the 12-byte `nonce`, authenticating `aad` with it, and returns the ciphertext with the tag appended."""
    def open(self, nonce: Buffer, ciphertext: Buffer, *, aad: Buffer) -> bytes:
        """Decrypts and verifies `ciphertext`, sealed under `nonce` with `aad`, and returns the plaintext; raises `DecryptFailed` if it does not verify."""

@final
class RandomizedNonceKey:
    """An XChaCha20-Poly1305 key that picks a random 192-bit nonce for every seal, so the caller tracks no nonce state."""

    def __new__(cls, key: Buffer) -> RandomizedNonceKey:
        """Makes a key from 32 bytes of key material; raises `WrongLength` otherwise."""
    def seal(self, plaintext: Buffer, *, aad: Buffer) -> tuple[bytes, bytes]:
        """Encrypts `plaintext` under a fresh random nonce, authenticating `aad` with it, and returns the nonce, which the opener needs, and the ciphertext with the tag appended."""
    def open(self, nonce: Buffer, ciphertext: Buffer, *, aad: Buffer) -> bytes:
        """Decrypts and verifies `ciphertext`, sealed under the 24-byte `nonce` with `aad`, and returns the plaintext; raises `DecryptFailed` if it does not verify."""

__all__ = ["Algorithm", "Key", "RandomizedNonceKey", "AES_128_GCM", "AES_192_GCM", "AES_256_GCM", "CHACHA20_POLY1305"]
