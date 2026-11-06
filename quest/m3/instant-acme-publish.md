# [XS] Publish rind-instant-acme

## Goal

`rind-instant-acme` depends on instant-acme 0.9 from crates.io instead of a
git revision, and is published.

## Plan

The adapter landed on a pinned instant-acme git revision before the release
(maintainer, 2026-10-30). Point the dependency and dev-dependency at the
release, drop `publish = false`, the README's unpublished note, and the
`deny.toml` git allowance, and adapt to any provider change since the pinned
revision.
Trusted publishing cannot create a crate, so its first version goes out by
hand, as `CONTRIBUTING.md`'s Releases section describes; this is the
maintainer's step.

## Required

- [instant-acme 0.9 is released](/quest/m3/instant-acme-release.md) - the release this switches to
