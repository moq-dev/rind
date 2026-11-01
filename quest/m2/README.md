# m2: later work

## Goal

Work that follows the release MoQ switches to: re-checking the costs accepted
to get there, and the speed and armv7 work that does not block it.

## Required

- [Re-measure accepted costs](/quest/m2/remeasure.md) - ChaCha20-Poly1305 throughput and RSA key generation timing on rind's first release
- [Fuzz the key loaders](/quest/m2/fuzz-keys.md) - arbitrary bytes into every key loader, against aws-lc-rs
- [RSA at every key size as fast as aws-lc-rs](/quest/m2/rsa-sizes.md) - aws-lc's Montgomery routines beyond 1024 and 2048 bits, on x86_64 and aarch64
