# m2: later work

## Goal

Work that follows the release MoQ switches to: the speed and armv7 work that
does not block it.

## Required

- [Fastest at every algorithm](/quest/m2/speed/README.md) - every algorithm on every path as fast as any permissive source
- [Constant-time in armv7 debug builds too](/quest/m2/debug-ct.md) - armv7 debug ctgrind passes, finishing the sweep the nightly jobs do not cover
- [The nightly aarch64 build row runs natively](/quest/m2/ci-aarch64-native.md) - one native aarch64 run instead of 76 minutes of qemu, which also reran six x86 tiers
- [x86-cpu runs one CPU model per dispatch path](/quest/m2/ci-x86-cpu-trim.md) - the same path coverage in about 40 minutes instead of 90
