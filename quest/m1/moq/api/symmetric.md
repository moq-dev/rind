# [M] Symmetric API

## Goal

rind's symmetric modules have one key type per role and no runtime check that
a type could make:

- `aead::Key::new(&alg, key)?`, with `aad: &[u8]` and a typed `Tag`;
- legacy hashes and MACs in `legacy` submodules;
- every algorithm passed as `&'static`;
- HKDF `expand` that cannot fail for typed keys;
- `quic::HeaderProtectionKey::mask` and `constant_time::verify`;
- PBKDF2 `verify` that refuses a stored value shorter than the HMAC output.

## Plan

The decisions and their alternatives are in the
[epic](/quest/m1/moq/api/README.md). Start after PBKDF2 (moq-dev/rind#127)
lands.

- Delete `UnboundKey`, `LessSafeKey`, and `Aad`. `Tag` comes from
  `TryFrom<&[u8]>`, so a wrong-length tag fails before decrypting.
- Move `SHA1_FOR_LEGACY_USE_ONLY` and its HMAC and PBKDF2 kin into `legacy`
  submodules.
- Seal `hkdf::KeyType`, and keep the length check only where an untyped
  length is filled.
- `hmac`, `hkdf`, and `pbkdf2` take `&'static Algorithm`, as every other
  module does.
- Update the adapters' call sites in the same PR.
