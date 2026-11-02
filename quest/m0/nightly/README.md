# [XS] Nightly passes on main

## Goal

Every scheduled workflow on `main` passes, so a red nightly means a new break.
Since 2026-10-30 the quality lints, fuzz smoke, and Cranelift workflows have
been red, each for its own reason.

## Plan

Decided with the maintainer on 2026-11-01, from the merge-gate and CI audit. Settled; don't ask again. The chosen option is marked ✅.

- Milestone: m0 ✅ / m1 / m2.
- Cranelift: delete the job ✅ / keep it red until Cranelift supports
  `asm!` sym operands.
