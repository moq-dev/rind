# [XS] Retire the crates.io registry token

## Goal

After the first release that publishes through crates.io trusted publishing,
no long-lived crates.io token can publish rind.

## Plan

- This waits on the maintainer: the release job no longer reads
  `CARGO_REGISTRY_TOKEN`, but the secret stays until a real release proves
  the OIDC path. Check the release job's log for release-plz retrieving a
  trusted publishing token and every changed crate publishing.
- Then delete the `CARGO_REGISTRY_TOKEN` secret and revoke that token on
  crates.io.
- Recommended: turn on each published crate's crates.io setting that requires
  trusted publishing, so a leaked API token cannot publish it.
- Delete this quest once the token is gone.
