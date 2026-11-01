# [M] JWT signing as fast as aws-lc-rs

## Goal

rind-jsonwebtoken signs and verifies each algorithm moq-auth uses (HS256,
ES256, ES384, EdDSA, RS256) at least as fast as jsonwebtoken's aws-lc-rs
backend, measured per token on a quiet host, so moq-auth's switch to rind
costs no per-token time.

## Plan

Decided by the maintainer on 2026-10-31, from moq-auth's migration bench
(medians on a loaded 4-core host, so rough): HS256 sign 4.5 µs on rind
against 2.0 µs, HS256 verify 9.4 against 4.6, EdDSA sign 38 against 20,
EdDSA verify 61 against 47, ES256 sign 73 against 52, RS256 verify 41
against 29. ES256 verify and RS256 sign were already faster on rind.

- jsonwebtoken loads the key on every call, so measure that load apart from
  the operation first; a guess, unverified, is that each `from_pkcs8`
  re-derives the public key. Fix the cause in rind or rind-jsonwebtoken,
  whichever owns it.
- Add the per-token comparison to rind-bench so a regression shows up, and
  record before and after numbers in the PR.
- If a gap is in a primitive rather than the adapter (for example Ed25519
  signing), fix it in rind on every backend, per AGENTS.md's performance
  rules.
