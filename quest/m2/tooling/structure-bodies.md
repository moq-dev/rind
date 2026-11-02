# [XS] admin/structure sees function bodies

## Goal

`admin/structure` fails when non-test code under `rind/src/mid` (or `low`)
names a higher layer anywhere, including inside a function body, which
cargo-modules does not see.

## Plan

- #197 showed a `size_of::<crate::high::digest::Digest>()` inside a `mid`
  function body went unreported: cargo-modules reads only signatures and
  `use` items.
- Add a text check beside the cargo-modules pass: `crate::high` (and
  `crate::mid` from `low`) in non-test code, plus any `super::` path that
  climbs into a higher layer. Keep test modules exempt, as the graph check
  does.
- Prove it with a planted violation, then remove it.
