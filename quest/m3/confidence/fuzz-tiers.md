# [M] Fuzz the tiers GitHub's runners cannot reach

## Goal

Every fuzz target's corpus runs on every dispatch tier, not only those `sh/fuzz-replay.sh` reaches by denying features on GitHub's x86_64 and arm64 runners:
- x86_64's AVX-512, VAES, SHA extension, and SHA512 instruction paths, which a runner has or lacks from run to run, and the SHA512 instructions, which none has;
- armv7's three tiers: the crypto extension, NEON alone, and neither.

## Plan

- x86_64: replay each corpus under Intel SDE models that select those paths, as `x86-cpu.yml` names them (Diamond Rapids selects every one). SDE and AddressSanitizer may not share an address space; if not, replay a build without a sanitizer (`cargo fuzz build -s none`), since the replay checks results against aws-lc-rs, not memory safety.
- armv7: libfuzzer-sys builds libFuzzer itself, so a cross build without a sanitizer should run under qemu-user with `QEMU_CPU` and `RIND_CPU_DISABLE_neon`, as `sh/armv7.sh` runs the tests. aws-lc-rs must build for armv7 too, as it does for the tests.
- Replay, don't fuzz: the corpus the x86_64 jobs save is the input, as `fuzz.yml`'s aarch64 replay does.
