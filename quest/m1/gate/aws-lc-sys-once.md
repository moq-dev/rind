# [S] Build aws-lc-sys once per gate

## Goal

A cold `just ci` runs aws-lc-sys's C build once, not once for clippy and
again for the test build, saving about 30-36 CPU-seconds.

## Plan

- Both builds use the same features (`prebuilt-nasm`), yet the build script
  runs twice (36 and 30 CPU-s). Find out why: check versus build profile,
  environment differences, or the build script's own rerun conditions.
- Fix it at the source and measure cold before and after.
