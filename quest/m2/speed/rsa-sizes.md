# [M] RSA at every key size as fast as aws-lc-rs

## Goal

RSA signing and verification at every supported size (2048 to 8192 bits, and
the legacy 1024) run at least as fast as aws-lc-rs on x86_64 and aarch64,
not only at 1024 and 2048 bits.

## Plan

Both architectures run aws-lc's Montgomery multiplication at every width but
s2n-bignum's Karatsuba sizes (16 and 32 words). What remains is x86_64
signing at the other sizes, 3-6% slower than aws-lc-rs although both run the
same Montgomery routines: RSA-3072 at 1.03 (native) to 1.06 (portable) in
nightly run 41353861592, and RSA-2056 at 1.055 in interleaved runs on the
i7-8700, while RSA-6144 and RSA-8192 measure level or faster.

- The gap lies above the multiplication. aws-lc's
  `BN_mod_exp_mont_consttime` takes a 5-bit window through x86_64-mont5's
  `bn_power5` (five squarings and a multiplication fused with a
  constant-time table gather) where the width is a multiple of eight, and a
  6-bit window over `bn_mul_mont` otherwise; rind's `mont_exp` takes a 4-bit
  window. Unmeasured: first time a wider window alone, then `bn_power5`.
- Measure against the RSA bench rows at 2056, 2560, 3072, 4096, 6144, and
  8192 bits, and record before and after numbers. Cover a new path in
  ctgrind and the forced-path tests.
