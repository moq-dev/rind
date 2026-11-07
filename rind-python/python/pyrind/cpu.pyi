"""CPU support."""

def has_aes_hardware() -> bool:
    """Whether this CPU runs AES and GHASH in hardware; where it does not, prefer ChaCha20-Poly1305."""

__all__ = ["has_aes_hardware"]
