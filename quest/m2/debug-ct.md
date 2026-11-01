# [S] Constant-time in armv7 debug builds too

## Goal

`admin/ctgrind` passes on armv7 debug builds as well as release builds, so no
armv7 secret path relies on release optimizations to stay constant-time.

## Plan

Decided by the maintainer on 2026-11-01: this is m2 work, and armv7 gets no
debug nightly job (#111 dropped it for wall time).

#189 made rind's own secret arithmetic wrap and the x86_64 and aarch64 debug
ctgrind jobs pass. armv7's debug suites run from a throwaway branch,
`tmp/debug-ct-sweep3`, whose `ctgrind.yml` drops `--release` from the armv7
jobs and adds `--no-fail-fast`. Earlier runs reported only dependencies'
debug checks (curve25519-dalek, subtle, and libcrux-ml-kem), now turned off
in the workspace dev profile as fiat-crypto's were. Run 41349429240, with
those settings, passed the adapters suite with no errors; its unit and
Wycheproof suites were still running when this moved.

- Read run 41349429240's unit and Wycheproof results, fix what they report
  the same way for dependencies or by wrapping arithmetic in rind's code,
  and rerun until all three suites pass.
- Delete `tmp/debug-ct-sweep3` once its run has been read; recreate a
  throwaway branch for any rerun.
