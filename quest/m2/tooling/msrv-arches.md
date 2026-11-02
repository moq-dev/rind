# [XS] MSRV covers aarch64 and armv7

## Goal

The nightly MSRV job checks rind's library for aarch64 and armv7 on the
declared `rust-version` (1.90), not only x86_64, so a backend's `naked_asm!`
or intrinsic that needs a newer compiler fails nightly.

## Plan

Decided with the maintainer on 2026-11-02: cross-check in the existing msrv
row ✅ / a native arm64 row.

- In `lints.yml`'s `msrv` job, add `cargo check -p rind --lib --locked
  --target aarch64-unknown-linux-gnu` and the `armv7-unknown-linux-gnueabihf`
  equivalent, run through `nix develop .#msrv`.
- Give `devShells.msrv` those two targets' std. No C toolchain is needed for
  `check`.
- If either fails on 1.90, fix it the way #199 fixed x86_64, or justify a
  higher floor.
