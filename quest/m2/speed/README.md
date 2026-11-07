# Fastest at every algorithm

## Goal

Every algorithm rind exports, on every path it runs (x86_64's fast path and
its no-IFMA, no-ADX, no-AVX2, no-AES-NI, and SSE2 tiers; aarch64 with and
without the crypto extensions; armv7), is at least as fast as the fastest
permissively licensed source usable from Rust, or the gap is recorded with its
reason.
BENCHMARKS.md's CPU tiers show where each stands, and its Known gaps, from
`benchmarks/gaps.toml`, each gap's quest or reason.

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
- Verification breaks ties: a verified source wins unless another is more
  than about 10% faster ✅ (maintainer, 2026-11-02: raised from about 2% to
  prefer verified code over chasing benchmark noise) / within 2% / never.
- Scope: every exported primitive, plus rind-rustls full and resumed
  handshakes and bulk transfer against aws-lc-rs's and ring's providers ✅ /
  primitives only / also every adapter.
- Symmetric sizes: 32 B, 1200 B, 1350 B, and 16 KB, plus 64 B and 8 KB for
  hashes; a gap at any size counts ✅ / a full power-of-two sweep.
- Scoreboard: BENCHMARKS.md's CPU tiers, which `admin/bench-report nightly`
  and `render` regenerate from the nightly bench, show each path's ratio to
  the fastest baseline; the nightly job's summary keeps the live numbers ✅
  (maintainer, 2026-11-03, while planning the benchmark report:
  moved from the Algorithms table, now in `ALGORITHMS.md`, which keeps only the sources) /
  the Algorithms table / nightly summary only.

An RSA change's A/B on GitHub's runners reads `bench.yml`'s `no-ifma` row:
a runner may draw a CPU with AVX-512 IFMA, whose dual RSAZ the row denies, so
both runs time the path of CPUs without it. The plain x86_64 row times the
dual RSAZ only when the runner has IFMA.

## Required

- [AES-192-GCM on aarch64 is level with aws-lc-rs for large messages](/quest/m2/speed/aes192-gcm-aarch64.md) - s2n-bignum's stitched kernels skip 192-bit keys
- [Wiping keys on drop is opt-in](/quest/m2/speed/wipe-feature.md) - a `wipe` feature; the default build skips it
