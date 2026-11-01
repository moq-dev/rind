# [S] HS256 as fast as aws-lc-rs on x86_64 without SHA-NI

## Goal

rind-jsonwebtoken signs and verifies HS256 at least as fast per token as
jsonwebtoken's aws-lc-rs backend on x86_64 CPUs without the SHA extensions
(Intel before Ice Lake), so moq-auth's switch to rind costs no per-token
time there either. ES256, ES384, EdDSA, and RS256 already match or beat it;
`rind-bench`'s `jsonwebtoken` bench measures all five.

## Plan

Measured on an i7-8700 (no SHA-NI) on 2026-10-31: HS256 costs about 3% more
per token on rind, and the gap is SHA-256's compression. rind's own AVX2
routine runs about 3.5% slower per block than aws-lc's
`sha256_block_data_order_avx`, which aws-lc picks on Intel without SHA-NI;
the HMAC and adapter overhead around it already matches.

- Pick the fastest SHA-256 source for this path per AGENTS.md, for example
  importing aws-lc's AVX routine with `admin/import-aws-lc` as SHA-512's was,
  and check every message size and both vendors against aws-lc-rs.
- Hosts with SHA-NI, and every other backend, are out of scope unless a
  measurement there shows a gap.
