# [S] rind on MIPS

## Goal

rind and rind-rustls build for mips(el)-unknown-linux-gnu and mips64(el)-unknown-linux-gnuabi64, which are tier 3 in Rust on the [portable backend](/ARCHITECTURE.md), and CI runs the test suite (Wycheproof, differential, rind-rustls handshakes) under qemu on each.

## Plan

As of 2026-11-06, aws-lc-rs tests MIPS only on nightly, and ring dropped it after 0.17. Delete this quest instead if neither ring 0.17 nor aws-lc-rs still builds for MIPS, or if no stable toolchain builds it. Big-endian variants need the byte-order checks. A missing CPU feature still fails with an error naming it; the portable backend needs none. Add the targets to [PLATFORMS.md](/PLATFORMS.md) and the release checks in the same PR.
