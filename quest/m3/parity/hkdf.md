# [S] HKDF over every HMAC hash

## Goal

`hkdf` offers `HKDF_SHA384` and `HKDF_SHA512`, and `hkdf::legacy` offers
`HKDF_SHA1`, matching ring's HKDF algorithms on rind's own API.

## Plan

Decided by the maintainer on 2026-10-31, from the adapter survey in
`MIGRATING.md`.

- Each is an `Algorithm` over the matching `hmac` constant, so the work is
  the constants, RFC 5869 and Wycheproof vectors, differential tests against
  aws-lc-rs, and a benchmark row; no new primitive.
- SHA-1 sits in `hkdf::legacy`, as `HMAC_SHA1` does in `hmac::legacy`.
- `expand`'s 255-block limit scales with each hash's output, so check the
  typed-key path stays infallible and the byte-length path refuses past
  `255 * output_len` for each.
