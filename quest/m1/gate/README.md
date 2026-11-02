# Lean merge gate

## Goal

`just ci` spends its time only on high-signal checks, and compiles every
backend before merge, not only x86_64. The audit measured about 45-50 s with
a warm build cache and about 155 s cold (88% compiling), on an i7-8700.

## Plan

Decided with the maintainer on 2026-11-01, from the merge-gate and CI audit. Settled; don't ask again. The chosen option is marked ✅.

- Milestone: m1 ✅ / m0 / m2.
- Compile aarch64 and armv7 in the gate ✅ / armv7 only / leave both to
  nightly.
- Run tests with nextest ✅ / skip it to avoid another tool.
- Forced x86_64 CPU tiers: leave them to nightly and the post-merge Check ✅
  / add a path-scoped forced-tier run to the gate.
- Every other gate step stays: fmt, clippy (the only per-PR proof that the
  benches and fuzz targets compile), the unit and crosscheck suites,
  Wycheproof, CAVP, the ring and adapter tests, doc tests, deny, and the
  path-scoped lints.

## Required

- [Drop the redundant RSA key generation tests](/quest/m1/gate/rsa-keygen-tests.md) - the gate stops spending 6-7 CPU-seconds on keygen tests that repeat others
