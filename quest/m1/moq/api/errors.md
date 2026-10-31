# [M] Errors by role

## Goal

`rind::Error` has about six variants, each reached from a distinct kind of
call: `WrongLength`, `KeyRejected` (its reason in Display), `BadSignature`,
`DecryptFailed`, `RngFailed`, and `NotEqual`. A caller asking "was the key
bad?" matches one variant, and no variant means two unrelated things.

## Plan

The decision and its alternatives are in the
[epic](/quest/m1/moq/api/README.md). This runs after the other rind
children, because they remove error sources (buffer sizes and algorithm
mismatches), and the enum should cover what is left.

- Fold `NotUncompressed`, `NotOnCurve`, and key-related `OutOfRange` into
  `KeyRejected`.
- Stop the misleading mappings: RSA's internal fault check must not return
  `DecryptFailed`, and X25519's all-zero secret must not read as
  `NotOnCurve`.
- `Error` derives `Eq` alongside `PartialEq`.

## Required

- [Signature API](/quest/m1/moq/api/signature.md) - removes buffer-size errors
- [Agreement and KEM API](/quest/m1/moq/api/agreement-kem.md) - removes the algorithm-mismatch error
- [Symmetric API](/quest/m1/moq/api/symmetric.md) - removes the tag-length and HKDF errors
