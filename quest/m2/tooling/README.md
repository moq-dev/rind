# CI and tooling follow-ups

## Goal

The gaps found while landing the merge-gate and nightly fixes on 2026-11-02
are closed: the MSRV check covers every backend, the layering check sees
function bodies, and the dev shells carry only what each job needs.

## Plan

Decided with the maintainer on 2026-11-02, planning follow-ups from
[moq-dev/rind#196](https://github.com/moq-dev/rind/pull/196),
[#197](https://github.com/moq-dev/rind/pull/197),
[#199](https://github.com/moq-dev/rind/pull/199),
[#204](https://github.com/moq-dev/rind/pull/204), and
[#205](https://github.com/moq-dev/rind/pull/205). Settled; don't ask again.

- Milestone: m2 ✅ / m1 / m0.
- Dropped: workflow `permissions` blocks (the repository's default token is
  already read-only), a fixed-input key generation bench, nextest outside the
  gate, and removing the `__cpuid` workaround at 1.94 (its comment says so).

## Required

- [MSRV covers aarch64 and armv7](/quest/m2/tooling/msrv-arches.md) - the nightly MSRV row also checks the other two backends on 1.90
- [admin/structure sees function bodies](/quest/m2/tooling/structure-bodies.md) - a `mid` function body naming `high` fails the layering check
- [admin/structure without graphviz](/quest/m2/tooling/structure-awk.md) - the default dev shell drops graphviz
- [A ctgrind dev shell](/quest/m2/tooling/ctgrind-shell.md) - `admin/ctgrind` runs locally without setting `LIBCLANG_PATH`
- [armv7 key generation stops wiping scratch](/quest/m2/tooling/armv7-keygen-scratch.md) - per-call scratch drops its zeroing, as `AGENTS.md` says
- [rind-cpuid reports every feature the dispatch reads](/quest/m2/tooling/cpuid-features.md) - the x86-cpu grouping rebuilds from the repo alone
