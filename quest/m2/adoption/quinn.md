# [M] quinn's rustls support works with any provider

## Goal

quinn-proto's rustls support takes any rustls `CryptoProvider`, including
rind-rustls, without pulling ring or aws-lc-rs, in a merged upstream PR closing
[quinn-rs/quinn#2341](https://github.com/quinn-rs/quinn/issues/2341).

## Plan

- Still worth it beside the [ring patch](/MIGRATING.md#rind-ring), which
  already runs quinn 0.11 on rind, though only in a binary that adds a git
  `[patch]`, and with rustls's ring provider over rind-ring rather than
  rind-rustls. Only this change lets a library on quinn (reqwest's HTTP/3,
  hickory, libp2p) offer rind-rustls from crates.io.
- quinn's maintainers want it on main: drop the provider features for an
  explicit provider, as rustls 0.24 requires, after moving the Retry tag onto
  rustls's `PacketKey`
  ([djc and Ralith on quinn-rs/quinn#2671](https://github.com/quinn-rs/quinn/pull/2671#discussion_r3372535699)).
  0.11.x is out: rustls 0.23 cannot build the Retry tag's 16-byte AES-128 key
  through a provider (`AeadKey::with_length` is crate-private), and djc refuses
  RustCrypto dependencies
  ([quinn-rs/quinn#2678](https://github.com/quinn-rs/quinn/pull/2678)).
- [quinn-rs/quinn#2701](https://github.com/quinn-rs/quinn/pull/2701) moves
  main to rustls 0.24 and takes the Retry tag from ctz's WIP branch. What then
  still calls ring or aws-lc-rs directly is the reset key's HMAC and the token
  key's HKDF and AES-256-GCM (`quinn-proto/src/crypto/ring_like.rs`), and the
  `default_provider()` calls behind the provider features.
- The PR, on main once #2701 lands: one explicit `Arc<CryptoProvider>` in
  place of `rustls-ring` and `rustls-aws-lc-rs`; the reset key from the
  provider's HKDF `hmac_sign`, as ctz's commit
  [34cc6531](https://github.com/ctz/quinn/commit/34cc65319a4e767fa953c56077274ae042c53c96)
  does; the token key from the provider's HKDF and an AEAD from its QUIC
  `Algorithm`. A provider lacking a needed suite is a config error. Keep a
  ring or aws-lc-rs default only if the maintainers ask for one.
- The PR is provider-neutral and never names rind
  ([quinn-rs/quinn#2253](https://github.com/quinn-rs/quinn/issues/2253)).
  quinn's AI policy (its `CONTRIBUTING.md`) welcomes AI-written code but wants
  the PR body and comments in the contributor's own words: the agent prepares
  the change and its facts, and the maintainer writes and posts the text.

## Waiting

- quinn-rs/quinn: [#2701](https://github.com/quinn-rs/quinn/pull/2701) merges,
  putting main on rustls 0.24 and the Retry tag on `PacketKey`; check with
  `gh pr view 2701 -R quinn-rs/quinn --json state`.
- Maintainer: say on
  [quinn-rs/quinn#2341](https://github.com/quinn-rs/quinn/issues/2341) that you
  will send the explicit-provider PR once #2701 lands, so nobody duplicates it
  (recommended), or skip it and let the agent start when #2701 merges. quinn's
  AI policy rules out an agent-written comment. Done once the comment is there
  or this item is deleted.
