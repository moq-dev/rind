# m0: immediate priorities

## Goal

The work that cannot wait: security advisories against rind or its
dependencies, a failing `main`, and anything that breaks MoQ on a published
rind release, and hosted CI that blocks every PR. Otherwise empty while
nothing is urgent.

## Required

- [Retire the crates.io registry token](/quest/m0/confine-release-credentials.md) -
  delete the long-lived crates.io token once a release publishes through
  trusted publishing
