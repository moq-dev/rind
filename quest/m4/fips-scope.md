# [M] Scope FIPS 140-3 validation

## Goal

A report gives the maintainer what FIPS 140-3 validation of rind would take,
so they can decide whether to pursue it: the module boundary, the changes
(power-on self-tests, an approved-mode API, the DRBG and entropy source,
zeroization, the service indicator), a lab, the cost, and the timeline, with
aws-lc's validated module as the reference.

## Plan

Planned by the maintainer on 2026-11-04 in m4. This quest only scopes;
the validation itself is planned from its report. Note which consumers want
it (Bun's FIPS request, [oven-sh/bun#4869](https://github.com/oven-sh/bun/issues/4869),
and Deno's and Node's FIPS builds are the precedent) and whether a FIPS build
can stay a separate crate so rind's default build pays nothing.
Zeroization starts from rind's opt-in `wipe` feature; say what FIPS adds to
it, such as wiping copies inside a call.
