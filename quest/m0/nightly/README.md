# Nightly passes on main

## Goal

Every scheduled workflow on `main` passes, so a red nightly means a new break.
Since 2026-10-30 the quality lints, fuzz smoke, and Cranelift workflows have
been red, each for its own reason.

## Plan

Decided with the maintainer on 2026-11-01, from the merge-gate and CI audit. Settled; don't ask again. The chosen option is marked ✅.

- Milestone: m0 ✅ / m1 / m2.
- Cranelift: delete the job ✅ / keep it red until Cranelift supports
  `asm!` sym operands.

## Required

- [Lints use the flake's toolchain](/quest/m0/nightly/lints-toolchain.md) - nightly lints fail on code, not on a new stable rustfmt; the gate's duplicate row and the Cranelift job go
- [MSRV builds again](/quest/m0/nightly/msrv.md) - rind builds on its declared rust-version 1.89
