# Fastest at every algorithm

## Goal

Every algorithm rind exports, on every path it runs (x86_64's fast path and
its no-ADX, no-AVX2, no-AES-NI, and SSE2 tiers; aarch64 with and without the
crypto extensions; armv7), is at least as fast as the fastest permissively
licensed source usable from Rust, or the gap is recorded with its reason.
README's Algorithms table shows where each stands.

## Plan

Decided with the maintainer on 2026-11-01, in a planning interview. These are
settled; don't ask them again. The chosen option is marked ✅.

- Bar: the fastest of any Rust-usable source (aws-lc-rs, ring, RustCrypto,
  libcrux, graviola, BoringSSL, s2n-bignum, ...) ✅ / the faster of aws-lc-rs
  and ring / aws-lc-rs only.
- Paths: every tier, each against its baselines held to the same CPU
  features ✅ / default paths plus the Pi tier / default fast paths only.
- Structure: an audit that measures everything and recommends one quest per
  gap, which the maintainer plans from its report ✅ / an epic per algorithm
  family / one big quest.
- Milestone: m2 ✅ / m1.
- Licenses: permissive only (Apache-2.0, ISC, MIT, BSD, CC0); copyleft code
  such as the Linux kernel's assembly is out ✅ / permissive, plus asking
  per case.
- Hardware: the nightly bench's GitHub x86_64 and arm64 runners (armv7 in
  32-bit mode on arm64, x86_64 tiers forced), plus interleaved runs on the
  maintainer's i7-8700; real Pi 4 and older x86 hardware stay unmeasured and
  noted ✅ / also rented cloud instances.
- The existing speed quests join this epic ✅ / stay separate.
- Nightly baselines: aws-lc-rs and ring, so regressions show; other sources
  are measured once by the audit ✅ / every source nightly / aws-lc-rs only.
- Verification breaks ties only: a verified source wins when it is within
  measurement noise, about 2%, of the fastest ✅ / within 5% / never. This
  refines `AGENTS.md`'s fastest-source rule.
- Scope: every exported primitive, plus rind-rustls full and resumed
  handshakes and bulk transfer against aws-lc-rs's and ring's providers ✅ /
  primitives only / also every adapter.
- Symmetric sizes: 32 B, 1200 B, 1350 B, and 16 KB, plus 64 B and 8 KB for
  hashes; a gap at any size counts ✅ / a full power-of-two sweep.
- Scoreboard: README's Algorithms table gains each path's ratio to the
  fastest baseline, refreshed by the audit and each gap quest; the nightly
  job's summary keeps the live numbers ✅ / nightly summary only / a separate
  BENCHMARKS.md.

## Required

- [AGENTS.md states the 2% tie rule](/quest/m2/speed/agents-rule.md) - the fastest-source rule says a verified source wins only within about 2%
- [Audit every algorithm's speed](/quest/m2/speed/audit.md) - measure every algorithm on every path against every source, and recommend a quest per gap
- [RSA at every key size as fast as aws-lc-rs](/quest/m2/speed/rsa-sizes.md) - aws-lc's Montgomery routines beyond 1024 and 2048 bits, on x86_64 and aarch64
