# [S] The nightly aarch64 build row runs natively

## Goal

`build.yml`'s aarch64 row tests aarch64 once, on the native
`ubuntu-24.04-arm` runner, instead of cross-compiling under qemu for 76
minutes.

## Plan

Decided with the maintainer on 2026-11-01, from the merge-gate and CI audit:
m2 ✅ / m1 / m3.

- Fix the bug: the "Artificial CPU feature tests (x86_64)" step checks
  `runner.arch == 'X64'`, which is true on the x86 runner that
  cross-compiles. So it reruns six x86-only tiers under aarch64 qemu, about
  35 minutes each night. Skip it for cross targets.
- Move the row to `ubuntu-24.04-arm` and drop the cross toolchain.
