# [M] RSA at every key size as fast as aws-lc-rs

## Goal

RSA signing and verification at every supported size (2048 to 8192 bits, and
the legacy 1024) run at least as fast as aws-lc-rs on x86_64 and aarch64,
not only at 1024 and 2048 bits.

## Plan

Decided by the maintainer on 2026-11-01, from the x86_64 portable work
(#170): RSA-3072 signing is still 1.71x aws-lc-rs on ADX CPUs, because
aws-lc's fast Montgomery routines are used only for moduli that are a
multiple of four words at 1024 and 2048 bits.

- x86_64: aws-lc's `mulx` Montgomery routines for the other sizes on ADX
  CPUs, and `bn_mul_mont_nohw` for moduli that are not a multiple of four
  words; fastest source per size wins, measured against aws-lc-rs.
- aarch64: the same gap for sizes other than 1024 and 2048 bits, with
  aws-lc's aarch64 Montgomery routines.
- Cover each new path in ctgrind, the forced-path tests, and the RSA bench
  rows at 3072 and 4096 bits, and record before and after numbers.

## Required

- [x86_64 without AVX2, BMI2, ADX, or AES-NI](/quest/m1/moq/x86-portable.md) - both touch `low`'s Montgomery dispatch
