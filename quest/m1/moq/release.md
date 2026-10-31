# [S] Release

## Goal

rind and every publishable `rind-*` adapter are on crates.io through
release-plz. `rind-instant-acme` publishes later, through
[Publish rind-instant-acme](/quest/m1/moq/instant-acme-publish.md), once
instant-acme 0.9 is released.

## Plan

The maintainer reset the numbering: every published crate starts at 0.1.0
rather than continuing graviola's, so the first release publishes `rind` 0.1.0
over the 0.0.0 placeholder.

The release workflow authenticates as moq's GitHub App (`moq-bot`) with the
`APP_CLIENT_ID`, `APP_PRIVATE_KEY`, and `CARGO_REGISTRY_TOKEN` secrets, all
configured. The token can publish new crates, so release-plz creates each
`rind-*` adapter on its first release.

Decided 2026-10-30 (maintainer): the first release does not wait on
upstream releases. Publishing still waits for the maintainer's go-ahead on
the release PR.

## Required

- [Public API audit](/quest/m1/moq/api/README.md) - the breaking API changes land before 0.1.0
