# [M] x86_64 portability decisions

## Goal

rind runs on any x86_64 CPU, choosing the fastest path the CPU supports once
per process. One maintainer decision remains, decided and, if taken, landed:
whether RSA-2048 signing on CPUs with AVX2 but without ADX, as Haswell, runs
aws-lc's RSAZ exponentiation.

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
