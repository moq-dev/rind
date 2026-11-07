# [S] rind on loongarch64

## Goal

rind and rind-rustls build for loongarch64-unknown-linux-gnu on the [portable backend](/ARCHITECTURE.md), and CI runs the test suite (Wycheproof, differential, rind-rustls handshakes) under qemu on each.

## Plan

Little-endian. ring 0.17 and aws-lc-rs only compile it in CI, so running the tests here goes beyond both. Check that qemu and valgrind (for ctgrind) support it in the Nix shell. A missing CPU feature still fails with an error naming it; the portable backend needs none. Add the targets to [PLATFORMS.md](/PLATFORMS.md) and the release checks in the same PR.
