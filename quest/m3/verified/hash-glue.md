# [S] The hash and KDF glue's constant-time compares are proven

## Goal

The constant-time compares behind `hmac::verify` and `pbkdf2::Secret::verify` (`ct_compare_bytes` and `ct_compare_16`, inline asm on each target) are proven in HOL Light and enter under [the epic's composition rule](/quest/m3/verified/README.md), discharging the `CtEqual` hypothesis the Lean API theorems take, so `verify` earns ✓ where its block functions are proven.

## Plan

Planned with the maintainer on 2026-11-03 from the audit.

`proofs/` proves the digest API for SHA-1 and SHA-256, the HMAC API over SHA-1, SHA-256, SHA-384, and SHA-512, HKDF, and PBKDF2 (`Rind/X86_64/{DigestApi,HmacApi,Hkdf,Pbkdf2}.lean`). `hmac::verify` and `Secret::verify` take `CtEqual`: `low::generic::ct_equal::ct_equal` returns whether its inputs are equal. That function is opaque in both translations.

- Prove `ct_compare_bytes` and `ct_compare_16` in HOL Light on each target: the result is zero exactly when the inputs are equal, and the routine runs in constant time.
- Restate those proofs as axioms about the Rust wrappers, as `Rind/<Arch>/S2nBignum.lean` does. Then prove `ct_equal` from them in Lean, discharge `CtEqual`, and pin the axioms in `Rind/<Arch>/Axioms.lean`.
- HKDF's `From<Okm>` impls for `aead::Key`, `aead::quic::HeaderProtectionKey`, and `hmac::Key` (`rind/src/high/hkdf.rs`) are unproven: prove each fills its key from `kdf.hkdf_fill`'s bytes. They need no HOL Light and can land first.
- `Rind/X86_64/Sha512.lean` keeps its own SHA-512 padding and buffering lemmas (`sha512_pad_spec`, `sha512_split_tail_spec`, `sha512_complete_blocks_spec`). `Blockwise.lean`'s generic ones could replace them in the same PR, or the work can be dropped.

## Required

- [rind's own HOL Light proofs live in proofs/hol-light](/quest/m4/verified/hol-light.md) - where the HOL Light proofs live and CI checks them

## Related

- [x86_64 SHA-NI SHA-256 block function is proven](/quest/m3/verified/sha256-block.md) - discharges `ShaBlocks` for SHA-256 on that tier
