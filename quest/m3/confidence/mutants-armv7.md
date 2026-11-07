# [M] Mutation testing on armv7

## Goal

`admin/mutants` runs on armv7, covering the code only 32-bit ARM compiles: `low/arm`, `mid/arm`, `low/generic/order.rs`, and the paths armv7 takes through the generic arithmetic. Each mutant there that no test catches is killed by a test or recorded with its reason, and `mutants.yml` covers armv7 too.

## Plan

- `admin/mutants` has no armv7 case, so it skips `low/arm` and `mid/arm` on every host. Cross-build for `armv7-unknown-linux-gnueabihf` and run each test binary under qemu-arm's `max` CPU through the target runner, as `admin/ct-qemu` does from `nix develop .#ct-qemu`. Its rows deny the crypto extension, like the x86_64 and aarch64 rows do.
- Combine its `mutants.out` with the other architectures' runs through `admin/mutants --survivors`.
