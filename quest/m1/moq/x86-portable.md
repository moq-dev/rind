# [M] x86_64 without AVX or AES-NI

## Goal

rind runs on any x86_64 CPU with SSSE3, choosing the fastest path the CPU
supports once per process, so MoQ keeps running on pre-2011 Intel and AMD,
Atom-class Celerons such as the J4125 and N5105, and VMs whose QEMU CPU model
has SSSE3. A 0.1.x release carries it. QEMU's default `qemu64` model lacks
SSSE3; whether an SSE2-only path should cover it is the maintainer's call.

## Plan

Decided by the maintainer on 2026-11-01, in m1 so no x86_64 host loses
support when MoQ switches. rind began as graviola, but any source is fine:
the fastest one per path wins, verified only on a tie, as for aarch64's
portable path.

- Today `rind::cpu::check()` requires `ssse3`, `aes`, `pclmulqdq`, and `avx`.
  ChaCha20, SHA, ML-KEM, and the table selects already run without `avx2`,
  `bmi2`, and `popcnt` behind `low::x86_64::cpu::HaveAvx2`, and bignum, ECC,
  and X25519 without `bmi2` and `adx` behind `low::x86_64::adx_mux`. Keep the
  current kernels as the fast path, and add a path for each missing group:
  - RSA without `adx`: s2n-bignum has no `_alt` Karatsuba or 8n
    reduction, and its generic schoolbook routines sign RSA-2048 2.3x slower
    than aws-lc-rs on the same path (its generic `bignum_montmul` is slower
    still). aws-lc's `bn_mul4x_mont` and `bn_sqr8x_mont` are what aws-lc-rs
    runs there; they compute a whole Montgomery product, so `posint`'s
    multiply-then-reduce split likely moves into `low`;
  - AES-NI and GHASH without `avx`: rind's AES, AES-GCM, and GHASH
    intrinsics are VEX-encoded. aws-lc's SSE `aesni-x86_64` and
    `ghash-x86_64` routines, or the same intrinsics without AVX, whichever is
    faster. SHA already runs aws-lc's SSSE3 and scalar routines without AVX;
  - AES and GHASH without `aes`/`pclmulqdq`: aws-lc's `vpaes-x86_64` and
    `ghash-ssse3` through `admin/import-aws-lc`.
- Decide once per process, the way aarch64 and armv7 do, and make
  `has_aes_hardware()` false without AES-NI so the adapters prefer
  ChaCha20-Poly1305. `check()` then refuses only CPUs below SSSE3.
- Test every path on every x86_64 CI run by forcing each one, as aarch64
  does, and cover each in ctgrind and the benchmarks. README's Limitations
  drop the x86_64 feature list.
