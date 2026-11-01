# [M] RSA at every key size as fast as aws-lc-rs

## Goal

RSA signing and verification at every supported size (2048 to 8192 bits, and
the legacy 1024) run at least as fast as aws-lc-rs on x86_64 and aarch64,
not only at 1024 and 2048 bits.

## Plan

Decided by the maintainer on 2026-11-01, from the x86_64 portable work
(#170). x86_64 now runs every Montgomery routine aws-lc's `bn_mul_mont` picks
(the `mulx` routines with ADX, and `bn_mul_mont_nohw` for widths that are not
a multiple of four words), which brought RSA-3072 to RSA-8192 signing and
verification within about 5% of aws-lc-rs.

- aarch64: the same gap for sizes other than 1024 and 2048 bits, which still
  run s2n-bignum's generic `bignum_montmul`; aws-lc's aarch64 Montgomery
  routines are the candidate. Speed needs aarch64 hardware to measure.
- x86_64: RSA-3072 signing stays about 1.05x aws-lc-rs on the same
  Montgomery routines. aws-lc's exponentiation (`bn_power5`, a 5-bit window
  with the gather inside the multiplication) is the remaining difference.
- Cover each new path in ctgrind, the forced-path tests, and the RSA bench
  rows at 3072 and 4096 bits, and record before and after numbers.
