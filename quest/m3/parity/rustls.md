# [S] rustls provider parity

## Goal

rind-rustls offers the rest of aws-lc-rs's rustls provider: the MLKEM1024 key-exchange group, and the ML-DSA-44, ML-DSA-65, and ML-DSA-87 signature schemes, both signing and verifying.

## Plan

- Waits on rind having ML-KEM-1024 and ML-DSA, which
  [aws-lc-rs extras](/quest/m3/parity/aws-lc-extras.md) holds until a consumer
  asks; rind-rustls already offers everything else aws-lc-rs's provider does.
- `aws_lc_rs_parity` in `rind-rustls/src/lib.rs` lists these as the only gaps;
  drop each exclusion as it lands.
