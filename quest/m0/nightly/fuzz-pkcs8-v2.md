# [XS] The keys fuzzer allows the PKCS#8 v2 refusal

## Goal

Fuzz smoke's `keys` target treats rind refusing ECDSA and RSA PKCS#8 v2 keys,
which aws-lc-rs accepts, as agreement, and still reports any other
difference.

## Plan

- Since 2026-11-01 the fuzzer fails at `fuzz/fuzzer/keys.rs:143`: rind
  returns `KeyRejected(UnsupportedPkcs8Version)` where aws-lc-rs accepts.
  The maintainer chose that refusal in #166, so the fuzzer is wrong, not rind.
- Allow exactly that case: an ECDSA or RSA input whose PKCS#8 version is 2.
  Every other mismatch still fails.
- Keep the crashing input as a corpus seed.
