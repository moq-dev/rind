# [M] rind on armv6

## Goal

rind and rind-rustls build for arm-unknown-linux-gnueabi, arm-unknown-linux-gnueabihf and arm-linux-androideabi, and CI runs the test suite (Wycheproof, differential, rind-rustls handshakes) under qemu on each.

## Plan

ring 0.17 and aws-lc-rs both test these targets in CI. They have `target_arch = "arm"`, so they compile rind's `arm` backend, whose aws-lc and OpenSSL assembly and `AT_HWCAP` checks were only tested on armv7. Check that each routine assembles and runs on ARMv6 (no NEON, no Thumb-2), and that the NEON and crypto-extension paths stay behind their runtime checks. If a routine can't, have `rind/build.rs` send these targets to the [portable backend](/ARCHITECTURE.md) instead, since it would be their only backend, not a fallback. A missing CPU feature still fails with an error naming it. Add the targets to [PLATFORMS.md](/PLATFORMS.md) and the release checks in the same PR.
