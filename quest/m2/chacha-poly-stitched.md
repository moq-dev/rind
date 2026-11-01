# [M] Combined ChaCha20-Poly1305 assembly

## Goal

ChaCha20-Poly1305 seals and opens at least as fast as aws-lc-rs at QUIC
packet sizes on x86_64 and aarch64, using aws-lc's combined ChaCha20 and
Poly1305 assembly where it measures faster.

## Plan

Decided by the maintainer on 2026-11-01, from the re-measure (#175): with
AVX2, rind takes 1.33-1.44x aws-lc-rs's time from 32 B to 16 KB, because
aws-lc runs one routine that interleaves ChaCha20 with Poly1305
(`chacha20_poly1305_x86_64` with AVX2 and SSE4.1 variants, and
`chacha20_poly1305_armv8`). Without AVX2, Poly1305 alone is also 4-7%
behind from 2 KB.

- Import those routines with `admin/import-aws-lc`, choosing per process as
  the other x86_64 and aarch64 paths do, and keep rind's current code where
  it measures faster (fastest source wins, verified only on a tie).
- Cover each path in the forced-path tests, ctgrind, and the bench rows at
  32, 1200, 1350 bytes and 16 KB, measured in release builds.
- Record the source and license in README's Sources table and LICENSE.
