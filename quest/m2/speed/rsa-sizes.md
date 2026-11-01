# [M] RSA at every key size as fast as aws-lc-rs

## Goal

RSA signing and verification at every supported size (2048 to 8192 bits, and
the legacy 1024) run at least as fast as aws-lc-rs on x86_64 and aarch64,
not only at 1024 and 2048 bits.

## Plan

Decided by the maintainer on 2026-11-01, from the x86_64 portable work
(#170). x86_64 runs every Montgomery routine aws-lc's `bn_mul_mont` picks
(#183), squaring by `bn_sqrx8x_internal` with ADX.

- Decided 2026-11-01: rind's copy of aws-lc's `bn_sqr8x_mont` zeroes the two
  scratch words its `mulx` branch reads unwritten, through
  `admin/import-aws-lc`'s `inserts`, a deliberate change recorded in the
  importer and README's Sources row: valgrind sees the read, while results
  and timing do not depend on it.
- aarch64: decided 2026-11-01, adopt aws-lc's `bn_mul_mont` per size only
  where the arm64 bench shows it faster than s2n-bignum's generic routines,
  and only if aarch64 ctgrind passes. The Neoverse-N2 bench (run
  41339865036) measured it twice as fast at 24, 48, and 64 words (RSA-3072
  signing and RSA-3072/4096 verification), so #179 runs it there. Every
  other width but 16 and 32 words (Karatsuba) still runs the generic
  routines and needs its own bench rows before it can switch: odd key sizes,
  and RSA-6144 and RSA-8192 verification (96 and 128 words).
- Cover each new path in ctgrind, the forced-path tests, and the RSA bench
  rows at 3072 and 4096 bits, and record before and after numbers.
