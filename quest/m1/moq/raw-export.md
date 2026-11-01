# [S] Raw private-key export

## Goal

rind exports an ECDSA key pair's private scalar and an Ed25519 key pair's
seed as owned fixed-size types wiped on drop, so moq-auth writes a JWK's `d`
without parsing it back out of PKCS#8 with the `pkcs8` and `sec1` crates.

## Plan

Decided by the maintainer on 2026-10-31, after moq-auth's migration to rind
had to parse PKCS#8 for its JWK fields. This reverses the API audit's
deletion of `seed()` and `to_private_key_be()`, which returned borrowed or
caller-buffer bytes; the new exports follow the audit's encoder shape instead
(an owned type, wiped on drop, like `Pkcs8`).

- Name them by the audit's rule (`to_*` for encoders, names by role); pick the
  names in the PR, for example `EcdsaKeyPair::to_scalar()` and
  `Ed25519KeyPair::to_seed()`, and map ring's and aws-lc-rs's equivalents in
  MIGRATING.md.
- The scalar is big-endian and exactly the curve's length, matching a JWK's
  `d` and SEC1's `privateKey`. Round-trip with the existing raw loaders, and
  cover it in ctgrind so the copy stays constant-time.
- Additive, so it ships in a 0.1.x release.

Once released, moq-auth (moq-dev/moq `rs/moq-auth`) drops its PKCS#8 parsing;
plan that in moq-dev/moq when this lands.
