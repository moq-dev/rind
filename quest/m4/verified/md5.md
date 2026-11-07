# [M] MD5 is proven

## Goal

`digest::legacy::MD5` earns the ✓ on every architecture: rind's portable Rust, the only code that computes it, is proven against RFC 1321 through the digest API.

## Plan

- Runs: `low/generic/md5.rs` and `mid/md5.rs`, about 290 lines, over the shared `Blockwise` padding that `proofs/Rind/X86_64/Blockwise.lean` proves, and the digest API's dispatch model in `proofs/Rind/X86_64/DigestDispatch.lean`.
- Route: Aeneas to Lean, with RFC 1321 transliterated beside `Rind/HashSpec.lean` and checked against its test suite, as `HashSpecTest.lean` checks the others.
