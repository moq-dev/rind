# rind builds on every target ring or aws-lc-rs supports

## Goal

rind and rind-rustls build and run on every architecture that ring 0.17 or aws-lc-rs supports, wasm excepted, so a library can depend on rind alone without dropping targets its users build. Architectures with no assembly in rind get one portable Rust backend. Each one's CI runs the tests under qemu.

Non-goals: wasm (browsers bring their own TLS, and every consumer that needed wasm was already left out), and speed work on the new architectures, which waits for a consumer.

## Plan

Decided with the maintainer on 2026-11-06, in moq-dev/web-transport's planning interview ([moq-dev/web-transport#478](https://github.com/moq-dev/web-transport/pull/478)) (✅ chosen):

- Goal: ✅ ring ∪ aws-lc-rs, minus wasm / only web-transport's CI targets / skip wasm32 only.
- Backend: ✅ a portable fallback generalized from armv7's libcrux path / per-arch assembly.
- Placement: ✅ m2 adoption / m1 / m3 parity.
- Split: ✅ epic, one child per architecture family / one [XL] quest.
- Consumer: moq-dev/web-transport goes rind-only now on its x86_64/aarch64/armv7 release targets. Its library users on other architectures are the reason for this epic.

The union of ring 0.17's and aws-lc-rs's CI and build scripts, listed on 2026-11-06, adds armv6, which both test. It drops i586, which ring refuses for lacking SSE2 and aws-lc-rs doesn't test. riscv32 and sparc64 are compile-only in both, as loongarch64 is, so they wait for a consumer. aarch64_be and armeb, which ring compiles and aws-lc refuses, compile the portable backend, untested.

"Exactly one backend compiles per architecture" still holds: the portable backend is each new architecture's only backend, not a fallback for a missing CPU feature. Big-endian targets (s390x, powerpc64, mips) need every byte-order assumption checked.

The epic's own work, once every child has merged:

- Rewrite [MIGRATE.md](/MIGRATE.md)'s rule that a library keeps its old backend as the default: a library whose targets rind covers may go rind-only.
- Update [PLATFORMS.md](/PLATFORMS.md) and the README's Limitations.

## Required

- [32-bit x86](/quest/m2/adoption/targets/x86.md) - i686 on Linux, Windows and Android
- [armv6](/quest/m2/adoption/targets/armv6.md) - arm-unknown-linux-gnueabi(hf) and arm-linux-androideabi
- [riscv64](/quest/m2/adoption/targets/riscv64.md) - riscv64gc Linux
- [PowerPC](/quest/m2/adoption/targets/powerpc.md) - powerpc64le, powerpc64 and powerpc Linux
- [s390x](/quest/m2/adoption/targets/s390x.md) - s390x Linux
- [loongarch64](/quest/m2/adoption/targets/loongarch64.md) - loongarch64 Linux
- [MIPS](/quest/m2/adoption/targets/mips.md) - mips and mips64 Linux, if ring or aws-lc-rs still supports them
