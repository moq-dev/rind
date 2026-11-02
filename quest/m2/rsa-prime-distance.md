# [S] RSA key generation refuses primes too close together

## Goal

`RsaPrivateKey::generate` in `rind/src/mid/rsa_priv.rs` draws a new q
whenever |p - q| <= 2^(nlen/2 - 100), as FIPS 186-5 A.1.3 step 5.4 and
aws-lc require. The public API does not change.

## Plan

Decided by the maintainer on 2026-11-01: plan it in m2 ✅ / m3 / drop. rind
follows aws-lc's behavior here, and aws-lc's `generate_prime` makes this
check.

- p and q are secret, so compute |p - q| and compare it to the bound in
  constant time. Only the retry itself is visible, and with random primes it
  happens with negligible probability.
- Test the check itself: a unit test feeds the generation loop a q within
  the bound of p and expects it to draw again. Random generation would never
  reach the bound.
- Extend the ctgrind test for key generation if the new comparison is not
  already covered.
