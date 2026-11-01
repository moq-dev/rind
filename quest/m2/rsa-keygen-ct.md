# [M] Constant-time RSA key generation

## Goal

RSA key generation leaks nothing about the key through timing on any
backend, so README drops its "RSA key generation is currently not
side-channel safe" caveat, and ctgrind covers key generation.

## Plan

Decided by the maintainer on 2026-11-01, from the re-measure (#175): ctgrind
flags secret-dependent branches in `invert_vartime(phi)`, which computes `d`,
and in Miller-Rabin on the accepted primes (how often 2 divides `p - 1`, and
an early exit). Timing over 200 keys varies 4.4% (`d`) and 2.4%
(Miller-Rabin) with the key. rind generates RSA-2048 in 36 ms against
aws-lc-rs's 68 ms, so there is room to pay for the fix.

- Compute `d`, `dp`, and `dq` in constant time, as the 32-bit ARM backend's
  `invert_e` already does, on x86_64 and aarch64 too.
- Reduce `d` mod lcm(p-1, q-1), as aws-lc and FIPS 186-5 do, rather than mod
  phi (maintainer, 2026-11-01). Keys rind generated before still load.
- Run Miller-Rabin as aws-lc's `bn_miller_rabin_iteration` does, on every
  backend including 32-bit ARM, which has the same leak.
- Add a ctgrind test that feeds accepted primes in as secret, measure the
  new cost, and keep the differential tests against aws-lc-rs passing.
