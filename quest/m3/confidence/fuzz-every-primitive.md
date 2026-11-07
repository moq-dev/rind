# [L] A differential fuzz target for every primitive

## Goal

Every primitive [TESTING.md](/TESTING.md) lists has a `fuzz/fuzzer/` target that compares rind with aws-lc on fuzzed input, so no "none, planned" link to this quest is left in its Fuzz target column. Today these have none:
- AES-GCM with any IV and tag length (`aead::gcm`), and AES-192 key wrap;
- QUIC header protection, the AES block, AES-CTR, and ChaCha20;
- MD5;
- Ed25519, ECDSA, and RSA signing, and RSA key generation.

## Plan

- Where aws-lc-rs lacks the API, call aws-lc through `aws-lc-sys`, as `xchacha` and `verify` already do: MD5, ChaCha20, AES-192 key wrap, and GCM with an arbitrary IV.
- Signing is randomized for ECDSA and RSA-PSS: check that aws-lc-rs verifies what rind signs from a fuzzed key and message, and compare bytes where the output is deterministic (Ed25519, RSA PKCS#1 v1.5, RFC 6979 ECDSA if rind's nonce is).
- Key generation draws from the system RNG: fuzz the key loaders with generated keys instead, or check that aws-lc-rs loads and agrees with each key rind generates.
- Extend existing targets where the shape fits rather than adding one per primitive; each new target needs a `fuzz/Cargo.toml` `[[bin]]`, and `admin/testing` then asks for its row.
