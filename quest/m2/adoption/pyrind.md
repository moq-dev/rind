# [XS] pyrind on PyPI

## Goal

`pip install pyrind` installs rind for Python, with rind's own API: AEADs,
hashes, HMAC, HKDF, PBKDF2, X25519, Ed25519, ECDSA and ECDH, RSA, and ML-KEM,
from wheels for every platform rind supports. A small-message AEAD or HMAC
call costs a fraction of pyca/cryptography's.

## Plan

[rind-python](/rind-python/README.md) builds the package, with its numbers
against pyca/cryptography in its README. release-plz versions it from git
tags (`git_only`), so the next release PR carries rind-python 0.1.0; when
that PR lands, release-plz tags `rind-python-v0.1.0`, and `release.yml`
builds the wheels with `python.yml` and publishes them by PyPI trusted
publishing from the `publish` environment. A failed publish retries on the
next push to `main` that runs the release job.

## Waiting

- Maintainer: on PyPI, add a pending trusted publisher for the project
  `pyrind` (owner `moq-dev`, repository `rind`, workflow `release.yml`,
  environment `publish`) before merging the release PR that carries
  rind-python 0.1.0, then merge it. An agent cannot create the PyPI account
  or publisher. Check: `pip install pyrind==0.1.0` installs, and
  `python -c "import pyrind"` runs.
