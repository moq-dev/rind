# [XS] Clippy aarch64 and armv7 in the gate

## Goal

`just ci` runs `cargo clippy -p rind --lib` for aarch64 and armv7 whenever
rind's source changes, so a compile break on either backend fails before
merge.

## Plan

- Measured cost: about 8 s and 18 CPU-s each cold, about 1 s warm.
- Add the two targets to the default dev shell's toolchain, and scope the
  step like the gate's other rind steps in `sh/dispatch.sh`.
