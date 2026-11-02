# [S] rind-cpuid reports every feature the dispatch reads

## Goal

`rind-cpuid` reports every CPU feature `rind/src/low/x86_64/cpu.rs` reads,
including SSE4.1, POPCNT, and AVX-512 VBMI/VBMI2, and the `admin/x86-cpus`
SDE scans are refreshed, so `x86-cpu.yml`'s model grouping (#205) can be
rebuilt from the repository alone.

## Plan

Decided with the maintainer on 2026-11-02: report and refresh the scans ✅ /
also derive the grouping with a script.

- #205 took SSE4.1 and VBMI/VBMI2 from Intel's specs because the saved scans
  lack them.
- Add the missing features to `rind-cpuid`, rerun the scans under SDE for
  every model in `x86-cpu.yml`'s comments, and check each step's grouping
  comment against them.
