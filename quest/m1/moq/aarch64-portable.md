# [M] aarch64 without the crypto extensions

## Goal

rind runs on aarch64 CPUs that lack the `aes`, `pmull`, and `sha2`
extensions, such as the Raspberry Pi 4, CM4, and Zero 2 W, so MoQ's aarch64
builds keep running on those boards. A 0.1.x release carries it.

## Plan

Decided by the maintainer on 2026-10-31, after moq-cli's switch to rind would
have stopped starting on a Pi 4 running a 64-bit OS. ring and aws-lc-rs pick
a code path per CPU at startup; rind does the same, as its 32-bit `arm` build
already does from `AT_HWCAP2`.

- Only AES, GHASH, SHA-1, and SHA-256 need the extensions; s2n-bignum's
  arithmetic, ChaCha20, Poly1305, SHA-512, and Keccak use only base aarch64
  and NEON. Import aws-lc's aarch64 code for the rest through
  `admin/import-aws-lc`: `vpaes-armv8` (NEON AES), `ghash-neon-armv8`, and
  the `_nohw` SHA-1 and SHA-256 routines.
- Decide once per process from the CPU's features, the same way armv7 does,
  and keep `rind::cpu::check()` refusing only what no path covers (`neon`).
  `has_aes_hardware()` turns false there, so rind-rustls and rind-dimpl
  prefer ChaCha20-Poly1305.
- Test both paths on every aarch64 CI run, by forcing the portable path in
  tests, and cover it in ctgrind and the benchmarks. README's Limitations
  drop the Pi 4 caveat.
- Publish it as a 0.1.x release, which MoQ's moq-cli switch waits on.
