# [M] RSA at every key size as fast as aws-lc-rs

## Goal

RSA signing and verification at every supported size (2048 to 8192 bits, and
the legacy 1024) run at least as fast as aws-lc-rs on x86_64 and aarch64,
not only at 1024 and 2048 bits.

## Plan

Decided by the maintainer on 2026-11-01, from the x86_64 portable work
(#170). x86_64 now multiplies with aws-lc's `bn_mulx4x_mont` on ADX CPUs and
`bn_mul_mont_nohw` for widths that are not a multiple of four words, and
converts into and out of Montgomery form with the same routines.

- x86_64 with ADX: squaring at sizes other than 1024 and 2048 bits still
  runs `bn_mulx4x_mont`, which leaves RSA-3072 signing and RSA-3072 to 8192
  verification about 1.2-1.4x aws-lc-rs. aws-lc squares with
  `bn_sqr8x_mont`'s `mulx` branch, whose `bn_sqrx8x_internal` loads two
  scratch words it never wrote, so `admin/ctgrind` fails on every result
  unless rind's copy zeroes them.
- aarch64: the same gap for sizes other than 1024 and 2048 bits, which still
  run s2n-bignum's generic `bignum_montmul`; aws-lc's aarch64 Montgomery
  routines are the candidate. Speed needs aarch64 hardware to measure.
- Cover each new path in ctgrind, the forced-path tests, and the RSA bench
  rows at 3072 and 4096 bits, and record before and after numbers.
