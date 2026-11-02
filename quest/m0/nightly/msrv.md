# [XS] MSRV builds again

## Goal

The nightly MSRV row builds rind on its declared `rust-version`, 1.89.

## Plan

- It fails with E0133 at `rind/src/low/x86_64/cpu.rs:352`: `__cpuid` is
  safe on newer toolchains but needs `unsafe` on 1.89.
- Fix it without leaving a lint on current stable, for example an
  `unsafe` block with `#[allow(unused_unsafe)]` and a comment naming 1.89.
  Alternatively, raise `rust-version` if a newer floor is justified.
