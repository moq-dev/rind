# [S] Constant-time in armv7 debug builds too

## Goal

`admin/ctgrind` passes on armv7 debug builds as well as release builds, so no
armv7 secret path relies on release optimizations to stay constant-time.

## Plan

#189 made rind's own secret arithmetic wrap and the x86_64 and aarch64 debug
ctgrind jobs pass. armv7 has no debug job (#111 dropped it for wall time),
so its debug suites ran from a throwaway branch, `tmp/debug-ct-sweep3`,
whose `ctgrind.yml` drops `--release` from the armv7 jobs and adds
`--no-fail-fast`; run 41349429240 is the latest. Its reports so far were
dependencies' debug checks (curve25519-dalek, subtle, and libcrux-ml-kem),
turned off in the workspace dev profile as fiat-crypto's were.

- Read that run, fix what remains the same way for dependencies or by
  wrapping arithmetic in rind's code, and rerun until all three suites pass.
- Whether armv7 debug becomes a nightly job is the maintainer's call; it
  took hours per suite when it last ran.
