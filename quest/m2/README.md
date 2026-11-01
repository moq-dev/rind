# m2: later work

## Goal

Work that follows the release MoQ switches to: the speed and armv7 work that
does not block it.

## Required

- [Constant-time RSA key generation](/quest/m2/rsa-keygen-ct.md) - no key-dependent timing in d or Miller-Rabin, on every backend
- [Bench forced paths in release builds](/quest/m2/bench-forced-paths.md) - the slower-path bench rows without debug assertions
- [Combined ChaCha20-Poly1305 assembly](/quest/m2/chacha-poly-stitched.md) - aws-lc's interleaved routine, closing the 1.3-1.5x gap
