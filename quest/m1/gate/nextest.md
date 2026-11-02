# [S] Run the gate's tests with nextest

## Goal

The gate runs its test binaries in parallel with `cargo nextest run`, and doc
tests separately with `cargo test --doc`. That saves about 3.5 s warm on an
i7-8700, more on a host with more cores.

## Plan

- Add `cargo-nextest` to the dev shell and swap it in in `sh/dispatch.sh`.
- With `CI_STRICT`, the pebble test must still fail when pebble is missing.
- Measure the gate before and after.
