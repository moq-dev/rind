# [S] Adapter crates' surviving mutants

## Goal

The 103 mutants in the `rind-<consumer>` adapters that no test catches are killed by tests, and their `exclude_re` entries in `.cargo/mutants.toml` are gone. Most are `Debug` and `Display` impls, `PartialEq` on algorithm handles, and accessors no test compares with the upstream crate's: `tag_len`, `block_len`, `chaining_len`, rustls' `encrypted_payload_len`, and QUIC's confidentiality and integrity limits.

## Plan

- Where the upstream crate has the same value, such as ring's or rustls' aws-lc-rs provider's, test against it rather than a literal.
- Run `admin/mutants -p <crate>` on each adapter to confirm none survive.
