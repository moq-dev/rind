# [S] admin/structure reports only real layering edges

## Goal

`admin/structure` passes nightly, and every edge it reports is a real
`low`/`mid`/`high` layering violation.

## Plan

- It reports mid-to-high edges such as
  `mid::sha{1,2}::*Context::finish{,_block} -> high::digest::Digest`, yet
  `mid/sha*.rs` never names `Digest`.
- First pin `cargo-modules` to the version that last passed and rerun. If
  the edges vanish, the newer release is a false positive: keep the pin and
  report it upstream.
- If the edges are real (for example through a trait impl in `high`), fix
  the layering at its source.
