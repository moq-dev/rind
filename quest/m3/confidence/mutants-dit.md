# [S] Mutation testing of DIT

## Goal

The code that detects and sets data-independent timing (DIT) runs under `admin/mutants` on cores that have it: `rind::cpu::Dit`, aarch64's `enter_cpu_state` and `leave_cpu_state`, the Linux and Windows detection in `low/aarch64/cpu.rs`, and `dit::maybe_enable`. Each mutant there that no test catches is killed by a test or recorded with its reason, and the `exclude_re` entries in `.cargo/mutants.toml` that point here are gone.

## Plan

- GitHub's Cobalt arm64 runners hide DIT, and the x86_64 hosts have none. GitHub's macOS arm64 runners are Apple M-series, which have it, and its `windows-11-arm` runners reach the Windows probe. `admin/mutants` knows only Linux target triples, so teach it Darwin's and Windows'.
- Mutate only the files above there. Combine the results with the Linux runs through `admin/mutants --survivors`.
