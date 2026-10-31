# ring and aws-lc-rs parity

## Goal

A project on ring or aws-lc-rs can move to rind: rind covers ring's
algorithms with its own API, `rind-ring` offers ring's API for a drop-in
swap, rind-rustls matches aws-lc-rs's rustls provider, and a migration guide
maps each ring and aws-lc-rs item to rind's. aws-lc-rs-only algorithms are
listed and start only when a consumer asks.

This epic's own work, once its children land: in the migration guide,
`MIGRATING.md`, a table from each ring and aws-lc-rs item to rind's equivalent
(or to the quest that adds it, or the reason rind refuses it), and a link to
the guide from the README.

## Plan

Decided by the maintainer on 2026-10-30:

- m3: no named consumer yet beyond anyone who wants to switch.
- rind keeps its own API, designed against misuse rather than shaped after
  aws-lc-rs (maintainer, 2026-10-31, in the
  [API audit](/quest/m1/moq/api/README.md)); the migration guide maps each
  ring and aws-lc-rs item to rind's, and exact name-for-name compatibility
  lives only in `rind-ring`.
- ring's algorithm set first. aws-lc-rs's extras wait for a consumer.
- Out of reach whatever the scope: FIPS validation, and anything that
  exposes C.
- Each new primitive follows `AGENTS.md`: a verified source where one
  exists, Wycheproof vectors, differential tests against aws-lc-rs, ctgrind,
  and a benchmark, on every backend.

## Required

- [HKDF over every HMAC hash](/quest/m3/parity/hkdf.md) - HKDF-SHA384, HKDF-SHA512, and legacy HKDF-SHA1, as ring has
- [rustls provider parity](/quest/m3/parity/rustls.md) - rind-rustls offers what aws-lc-rs's provider does
- [rind-ring](/quest/m3/parity/rind-ring.md) - ring's API on rind, for a drop-in swap
- [aws-lc-rs extras on demand](/quest/m3/parity/aws-lc-extras.md) - waiting on a consumer for each aws-lc-rs-only algorithm
