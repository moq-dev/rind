# m0: immediate priorities

## Goal

The work that cannot wait: security advisories against rind or its
dependencies, a failing `main`, and anything that breaks MoQ on a published
rind release, and hosted CI that blocks every PR. Otherwise empty while
nothing is urgent.

## Required

- [Constant-time in debug builds too](/quest/m0/debug-ct.md) - debug ctgrind passes, so the nightly jobs stop failing
