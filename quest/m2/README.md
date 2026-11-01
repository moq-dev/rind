# m2: later work

## Goal

Work that follows the release MoQ switches to: the speed and armv7 work that
does not block it.

## Required

- [Fuzz the key loaders](/quest/m2/fuzz-keys.md) - arbitrary bytes into every key loader, against aws-lc-rs
- [RSA at every key size as fast as aws-lc-rs](/quest/m2/rsa-sizes.md) - aws-lc's Montgomery routines beyond 1024 and 2048 bits, on x86_64 and aarch64
- [Constant-time RSA key generation](/quest/m2/rsa-keygen-ct.md) - no key-dependent timing in d or Miller-Rabin, on every backend
- [Combined ChaCha20-Poly1305 assembly](/quest/m2/chacha-poly-stitched.md) - aws-lc's interleaved routine, closing the 1.3-1.5x gap
