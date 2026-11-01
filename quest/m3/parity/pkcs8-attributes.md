# [S] PKCS#8 keys with attributes

## Goal

rind's ECDSA and RSA `from_pkcs8` load a PKCS#8 document that carries the
optional `attributes` field, as ring and aws-lc-rs do, so rind-ring loads
those keys too and its README drops the caveat.

## Plan

Decided by the maintainer on 2026-10-31, from rind-ring's differences from
ring.

- Skip the attributes rather than interpret them, as aws-lc-rs does. Ed25519
  already parses them in rind-ring; reuse that shape in rind's parser so every
  key type accepts the same documents.
- Refuse anything else malformed exactly as before: test an attributes field
  that is truncated, the wrong tag, or trailing garbage, and run the PKCS#8
  fuzz target if one covers the parser.
- Differential test against aws-lc-rs on keys with and without attributes,
  and update rind-ring's README and tests, and MIGRATING.md if it mentions
  the limit.
