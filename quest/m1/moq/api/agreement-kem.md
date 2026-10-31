# [S] Agreement and KEM API

## Goal

Key agreement is `agreement::PrivateKey::generate(&X25519)?.agree(peer)?`,
so a public key can no longer disagree with the private key's algorithm.
Every key that has a public half exposes it as `public_key()`, and
`kem::DecapsulationKey::decapsulate` takes the ciphertext as `&[u8]`.

## Plan

The decisions and their alternatives are in the
[epic](/quest/m1/moq/api/README.md).

- Delete `agreement::UnparsedPublicKey`, `agree_ephemeral`, and the
  mismatched-algorithm error. `agree` consumes the key, so it stays single-use.
- `compute_public_key`, `encapsulation_key`, and `key_bytes` become
  `public_key()`, with bytes through `AsRef<[u8]>`.
- `Ciphertext` becomes owned-only, returned by `encapsulate`.
- Update rind-rustls's and rind-dimpl's key exchange in the same PR.
