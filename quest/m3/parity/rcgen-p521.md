# [XS] P-521 in rind-rcgen

## Goal

rind-rcgen generates and loads ECDSA P-521 keys, as the API audit decided
(maintainer, 2026-10-31). This waits on rcgen: its
`PKCS_ECDSA_P521_*` algorithms exist only with its `aws_lc_rs` feature, and a
`SigningKey` cannot name an algorithm rcgen does not export. It is ready once a
released rcgen exports them with `default-features = false`; ask in
[rustls/rcgen#460](https://github.com/rustls/rcgen/issues/460).

## Plan

Map `PKCS_ECDSA_P521_SHA256`, `_SHA384`, and `_SHA512` in rind-rcgen's
algorithm table, cover them in its tests, and drop the P-521 caveat from
MIGRATING.md. Adding an algorithm is not a breaking change, so the
maintainer moved this out of the API audit on 2026-10-31 rather than hold
rind 0.1.0 on rcgen.
