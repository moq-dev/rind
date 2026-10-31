# Public API audit

## Goal

Before rind 0.1.0 ships, every public item in rind and its `rind-*` adapters
has been audited and reshaped. The surface is smaller, misuse fails to
compile rather than failing at runtime, nothing panics on caller input, and
each name says its role. MoQ migrates onto 0.1.0, so breaking changes are
cheapest now.

This epic's own work, once its children land:

- README's Architecture section describes the new design, not aws-lc-rs's
  shape.
- The migration guide, `MIGRATING.md`, maps every aws-lc-rs and ring item
  to its rind name, beside its survey of crates with their own backend. The per-item "deviates from
  aws-lc-rs" doc notes move there as each child lands.

## Plan

Decided with the maintainer on 2026-10-31, in a planning interview over an
inventory of every exported item. These decisions are settled, so don't ask
them again; the chosen option is marked ✅.

**Scope**

- Goal: rind and every adapter, breaking changes allowed, landing before the
  release ✅ / rind only / report only.
- Baseline: rind's own design wins, and an aws-lc-rs name or shape stays only
  when it is as clear and safe ✅ / keep aws-lc-rs's shape / case by case.
  Migrators get the migration guide, and ring users get
  [rind-ring](/quest/m3/parity/rind-ring.md). AGENTS.md's API rule was
  rewritten to match in the PR that planned this epic.
- Release PR moq-dev/rind#5 holds until this epic lands ✅ / release now and
  audit for 0.2. The open parity PRs (P-521, PBKDF2) land first, so the audit
  covers their API too.
- Milestone: m1, ahead of the release ✅ / m0 / m2.
- Every change was settled in the interview, so the children only implement
  it ✅ / a quest runs the audit and brings back each change.

**Shape**, owned by the children below:

- Agreement: `agreement::PrivateKey::generate(&X25519)?.agree(peer)?` ✅ /
  keep ring's `EphemeralPrivateKey`, `UnparsedPublicKey`, `agree_ephemeral`.
- Encoders return owned, fixed-capacity stack types (`Pkcs8` wiped on drop,
  `Spki`, an RSA signature), so no buffer-size error exists ✅ / keep caller
  buffers plus maximum-length constants. rind still does not allocate.
- Verification: one `signature::PublicKey` and one `VerificationAlgorithm`
  struct, with no `dyn`; RSA components convert into a `PublicKey` ✅ / keep
  parsed plus unparsed keys.
- AEAD: one `aead::Key::new(&alg, key)?`, `aad: &[u8]`, and a typed `Tag`
  from `TryFrom<&[u8]>` ✅ / only type the tag.
- Legacy algorithms live in `legacy` submodules (`digest::legacy::SHA1`) ✅ /
  a `_FOR_LEGACY_USE_ONLY` suffix everywhere.
- Signature constants live in `signature::sign` and `signature::verify`, and
  drop the default `_2048_8192` range; a different floor lives under
  `legacy` ✅ / a `_SIGNING` suffix on both / keep the names.
- RSA verification constants are their own `RsaVerificationAlgorithm`, the
  only type `RsaPublicKeyComponents::to_public_key` takes, so a non-RSA
  algorithm there fails to compile; `PublicKey::new` takes either
  (2026-10-31) ✅ / refuse a non-RSA algorithm at run time.
- `verify::legacy::RSA_PKCS1_3072_SHA384` stays (2026-10-31) ✅ / delete it.
- A failed internal consistency check (RSA signing's CRT check, ECDH's
  on-curve shared point) returns a seventh variant, `Error::Fault`
  (2026-10-31) ✅ / the call's own variant / panic.
- Every public error enum is `#[non_exhaustive]`, so a new variant is not
  breaking (2026-10-31) ✅.
- Key formats are named by format, all DER: `from_pkcs1`, `from_sec1`,
  `from_pkcs8`, `to_pkcs8`, `to_spki`. "My public half" is `public_key()`
  everywhere, as an inherent method, so the `KeyPair` trait and its three
  public-key wrapper types go ✅ / keep `_der` suffixes.
- Small renames: `quic::HeaderProtectionKey::mask`, `constant_time::verify`,
  `signature::RsaKeySize` ✅ / keep.
- Errors collapse by role, to about `WrongLength`, `KeyRejected` (with its
  reason in Display), `BadSignature`, `DecryptFailed`, `RngFailed`, and
  `NotEqual`, each from a distinct kind of call ✅ / one opaque error / keep
  the variants and fix only misleading mappings.
- CPU: rind keeps panicking on a missing CPU feature, as an environment
  failure. Adapter entry points that rind invented call `cpu::check()` and
  return its error at setup; statics that upstream requires document calling
  it first ✅ / a capability token on every constructor / leave it.
- HKDF `expand` cannot fail for typed keys, and `KeyType` is sealed. Every
  algorithm is passed as `&'static`. `kem::decapsulate` takes `&[u8]`.
  `Ed25519KeyPair::seed` and `EcdsaKeyPair::to_private_key_be` are deleted
  ✅ / keep those two, returning wiped types.
- PBKDF2 `verify` refuses a stored value shorter than the HMAC output ✅ /
  match ring, which accepts any prefix.
- rind-rustls mirrors rustls's own providers: `kx_group` and `cipher_suite`
  modules, every group a `&dyn` static, `DEFAULT_*` lists in
  `default_provider()`'s order, and `Ticketer` kept ✅ / only
  `default_provider()`.
- rind-rcgen loads and generates P-256, P-384, P-521 (added 2026-10-31,
  after P-521 landed), and Ed25519 keys (RSA load only), exports PKCS#8
  wiped on drop, and maps errors to `rcgen::Error`, so no rind type leaks ✅
  / P-256 only, renamed, with the leak fixed.

The names above are the decided direction, not exact signatures. Each child
may adjust details as it learns, and records any change in its PR.

## Required

- [Adapter API](/quest/m1/moq/api/adapters.md) - rind-rustls mirrors rustls, rind-rcgen broadens, setup-time CPU checks
