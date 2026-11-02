# [XS] Lints use the flake's toolchain

## Goal

The nightly lints workflow fails only on code: its rows run the same pinned
toolchain as the gate, it no longer repeats the gate's x86_64 clippy and
fmt, and the Cranelift job is deleted.

## Plan

- Stable rustfmt 1.99.1 reformats `rind/src/low/x86_64/rsaz.rs:296`, which the
  pinned 1.98.1 accepts. That has failed runs 41135771706, 41242669857, and
  41354204872.
- Delete the x86_64 clippy and fmt row: `just ci` runs both on every merge.
- Run the aarch64 clippy row and the MSRV row through `nix develop`. Pin
  `cargo-modules` too, as `admin/structure`'s input.
- Keep the nightly rustfmt row with `.rustfmt.unstable.toml`: it checks
  the unstable style options.
- Delete the Cranelift workflow. It has failed since 2026-10-31 with "asm!
  and global_asm! sym operands are not yet supported", and the maintainer
  chose deletion over leaving it red.
