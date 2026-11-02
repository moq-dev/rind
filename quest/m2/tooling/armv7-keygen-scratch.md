# [XS] armv7 key generation stops wiping scratch

## Goal

armv7 RSA key generation (`rind/src/mid/arm/rsa_priv/generate.rs`) wipes
only secrets a returned value owns, like the generic backend, per
`AGENTS.md`: per-call scratch is not zeroed on drop.

## Plan

- `Derivation` and `MillerRabinScratch` zero themselves on drop, and so does
  `Prime`. Remove the `Drop` impls of per-call scratch; keep wiping only what
  the returned key owns.
- Compare with the generic backend's `generate.rs` and match it.
- Measure armv7 key generation before and after on the nightly armv7 bench,
  not locally.
