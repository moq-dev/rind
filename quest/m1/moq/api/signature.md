# [L] Signature API

## Goal

`rind::signature` has one way to do each job, with misuse caught by types:

- one `PublicKey` and one `VerificationAlgorithm` struct, with no `dyn`;
- constants in `sign` and `verify` submodules, with legacy ones under
  `legacy`;
- loaders and encoders named by format (`from_pkcs1`, `from_sec1`,
  `from_pkcs8`, `to_pkcs8`, `to_spki`);
- an inherent `public_key()` on each key pair;
- encoders and RSA signing return owned, fixed-capacity values.

## Plan

The decisions and their alternatives are in the
[epic](/quest/m1/moq/api/README.md). Start after P-521
(moq-dev/rind#133) lands, so its constants are reshaped too.

- Delete `UnparsedPublicKey`, `ParsedPublicKey`, `RsaPublicKeyComponents::verify`,
  the sealed `VerificationAlgorithm` trait, `EcdsaVerificationAlgorithm`,
  `RsaParameters`, `EdDSAParameters`, the `KeyPair` trait, and its
  `EcdsaPublicKey`, `Ed25519PublicKey`, and `RsaSubjectPublicKey` types.
- `Pkcs8` wipes on drop. Size each owned type for the largest key it holds,
  and keep them on the stack.
- Delete `Ed25519KeyPair::seed` and `EcdsaKeyPair::to_private_key_be`, which
  have no consumer.
- `KeySize` becomes `RsaKeySize`, defined once rather than once per backend.
- Fix a bug found by the audit: an RSA private key whose components disagree
  (p·q ≠ n, or wrong CRT values) loads, and then every signature fails with
  `DecryptFailed`. Refuse it on load with `KeyRejected`, as aws-lc-rs's
  `RSA_check_key` does.
- Update the adapters' call sites in the same PR.
