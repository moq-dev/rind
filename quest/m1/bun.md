# [S] Bun runs its fastest asymmetric crypto on rind

## Goal

A PR to [Bun](https://github.com/oven-sh/bun), with numbers, moves the
operations where rind measures clearly faster than Bun's BoringSSL onto rind,
and Bun merges it: Ed25519 and X25519, and ECDSA and ECDH on P-384 and P-521,
in WebCrypto and node:crypto, with no operation slower than on BoringSSL. SHA-3 in `CryptoHasher`
follows in [its own quest](/quest/m2/adoption/bun-sha3.md).

## Plan

Decided with the maintainer on 2026-11-04: a prototype PR with measurements
✅ / an issue asking first / only new APIs such as `Bun.jwt`. Posting it is
the maintainer's call.

Decided by the maintainer on 2026-11-05: hold the Bun PR until the quests
under Required land, so X25519 and ECDH move in the same PR, the PEM
regression is gone, and the blog post introducing rind is out ✅ / post the
prototype now / open an issue on oven-sh/bun first.

Decided by the maintainer on 2026-11-05, later: the first Bun PR also waits
for rind 0.2.0, released after an API audit, for ECDSA over a precomputed
digest, and for Bun's key parsing on rind, so it lands the whole move at once
on a stable API ✅ / post once the first four prerequisites land.

The prototype is branch `claude/rind-asymmetric` of
[kixelated/bun](https://github.com/kixelated/bun/tree/claude/rind-asymmetric),
and its PR text, with the measurements, is in
[moq-dev/rind#368](https://github.com/moq-dev/rind/pull/368). It pins rind by
git at a main commit until 0.2.0 is on crates.io. Measured on 2026-11-06
against Bun's own BoringSSL build:

- Moved: Ed25519; X25519; ECDSA and ECDH on P-384 and P-521, with any SHA-2
  hash, including node's `createSign`/`createVerify`; and key import and
  export (raw, PKCS#8, SPKI, SEC1, and JWK through the raw forms) for those
  keys. rind parses an encoding only when it writes the same bytes back,
  which is what OpenSSL, BoringSSL, and Node write; any other goes to
  BoringSSL, so Bun imports and exports byte for byte as before. A key rind
  parsed or generated is rind's alone, so the Ed25519 PEM double load is gone.
- P-256 stays on BoringSSL by this quest's rule: end to end, rind generates
  P-256 keys at 0.5x to 0.8x of BoringSSL's (0.83x for the primitive on
  EPYC, Neoverse-N2, and M1), verifies at about 1.0x, and signs only 1.1x to
  1.4x faster. It can join a later Bun PR once rind's P-256 key generation
  leads.

Once Bun merges it, a native `Bun.jwt`
([oven-sh/bun#27727](https://github.com/oven-sh/bun/issues/27727)) on rind is
a natural follow-up.

## Waiting

- Maintainer: once rind 0.2.0 is out and the launch post is up, switch the branch's rind pin to 0.2.0 from crates.io, then post it to oven-sh/bun from `kixelated/bun:claude/rind-asymmetric` with the text in moq-dev/rind#368; no agent may post to oven-sh/bun. Check for an open PR on oven-sh/bun from that branch.
- oven-sh/bun: review and merge the PR; check its state.

## Required

- [rind 0.2.0 is released](/quest/m1/release-0.2.md) - the PR depends on the audited API
- [rind's launch blog post is published](/quest/m1/launch-post.md) - the post the Bun PR links
