# [M] x86_64 portability decisions

## Goal

rind runs on any x86_64 CPU with SSSE3, choosing the fastest path the CPU
supports once per process. Two maintainer decisions remain, each decided and,
if taken, landed:

- whether RSA-2048 signing on CPUs with AVX2 but without ADX, as Haswell, runs
  aws-lc's RSAZ exponentiation;
- whether an SSE2-only path covers QEMU's default `qemu64` model, which lacks
  SSSE3, so `rind::cpu::check()` refuses no x86_64 CPU.

## Plan

Decided by the maintainer on 2026-11-01, in m1 so no x86_64 host loses
support when MoQ switches. rind began as graviola, but any source is fine:
the fastest one per path wins, verified only on a tie.

- RSAZ: aws-lc signs with `RSAZ_1024_mod_exp_avx2` (`rsaz-avx2.pl`), 1.6x
  faster than rind's exponentiation over aws-lc's `bn_mul4x_mont` and
  `bn_sqr8x_mont`, which already match aws-lc without AVX2 and for
  verification. RSAZ is its own 5-bit-window exponentiation and constant-time
  gather over a redundant representation, so adopting it replaces rind's
  exponentiation for 1024-bit primes on that path.
- SSE2: every primitive's slowest path is SSSE3 today, the last arm of its
  CPU dispatch: aws-lc's vpaes and SSSE3 GHASH, ChaCha20, SHA-1, and
  SHA-256. An SSE2-only path adds one arm below each, such as aws-lc's
  integer ChaCha20, SHA-1, and SHA-256 routines and a constant-time portable
  AES and GHASH, and drops `ssse3` from `missing_cpu_feature`. A `qemu64`
  guest can instead name a CPU model with SSSE3, such as `-cpu Nehalem`, or
  pass through the host's.
