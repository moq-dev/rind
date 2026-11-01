# [S] Fuzz the key loaders

## Goal

A fuzz target feeds arbitrary bytes to every public key loader (`from_pkcs8`,
`from_sec1`, `from_pkcs1`, SPKI and raw public keys, RSA components) and
checks that none panics and that each accepted key re-encodes to input it
accepts again, with aws-lc-rs accepting and refusing the same inputs.

## Plan

Decided by the maintainer on 2026-10-31: `fuzz/` covers only sha1, sha2,
aead, and kx, while the key parsers take untrusted input from certificates
and files.

- One target per format, or one dispatching on a leading byte, under
  `fuzz/fuzzer/`, so the CI smoke run picks it up.
- Where aws-lc-rs disagrees by design (rind refuses trailing bytes, for
  example), list the case in the target rather than loosening the comparison.
- Seed the corpus from the existing test keys, and fix anything it finds in
  the same PR, each with a regression unit test.
