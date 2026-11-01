# [S] Bench forced paths in release builds

## Goal

`bench.yml`'s rows for the slower paths (no AES hardware, no AVX2, no ADX,
SSE2, aarch64 without the crypto extension) time a release build without
debug assertions, so they stop overstating rind against aws-lc-rs.

## Plan

Decided by the maintainer on 2026-11-01, from the re-measure (#175): the
`RIND_CPU_DISABLE_*` switches work only with debug assertions on, and those
builds also run per-block `debug_assert!`s that cost about 30% (ChaCha20-
Poly1305 at 1200 B reads 1.81x instead of 1.32x).

- Find a way to force a path in a release bench without adding a production
  knob, for example a bench-only build cfg or feature that only rind-bench
  enables, and say why it cannot leak into a published build.
- Re-run the forced rows, and correct any README or quest numbers that came
  from the inflated ones.
