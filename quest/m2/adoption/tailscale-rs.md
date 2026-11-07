# [M] tailscale-rs's tunnel runs on rind

## Goal

A PR to [tailscale-rs](https://github.com/tailscale/tailscale-rs), with
numbers, moves its WireGuard data plane (ChaCha20-Poly1305 on every packet)
from RustCrypto's chacha20poly1305 0.10 onto rind.

## Plan

Decided with the maintainer on 2026-11-04, in a planning interview.

- It is young, in preview, and security-critical: open an issue asking
  whether they want a backend change before preparing a large PR. Its
  CONTRIBUTING.md also asks outsiders to file an issue before any PR, and to
  say how AI was used and how the change was verified.

Found on 2026-11-07 ([#471](https://github.com/moq-dev/rind/pull/471) holds
the issue draft, the patch, and the numbers):

- Only the session cipher can move. The handshake's HKDF is HMAC-BLAKE2s, and
  its cookies and DERP and disco boxes need BLAKE2s, XChaCha20-Poly1305, and
  XSalsa20-Poly1305, which rind lacks.
  [tailscale/tailscale-rs#87](https://github.com/tailscale/tailscale-rs/issues/87)
  dropped aws-lc-rs for the handshake for the same reason. It noted that the
  session cipher alone could still move.
- aws-lc-rs is already in tailscale-rs's default tree through rustls, so it
  is the zero-dependency alternative. rind matches it here, since both run
  aws-lc's assembly, and both are about 3x faster than chacha20poly1305 0.10.
- rind 0.2.1's armv7 backend pulls libcrux's `cfg(hax)` dependencies into the
  lockfile, so tailscale-rs's `cargo deny` (all features, all targets) flags
  RUSTSEC-2026-0173 until they ignore it, as rind's own `deny.toml` does.
- The patch has not been built for their `x86_64-pc-windows-gnu` CI target,
  which rind does not test.

## Waiting

- Maintainer: post the issue drafted in
  [#471](https://github.com/moq-dev/rind/pull/471) to tailscale/tailscale-rs,
  or drop the quest. Posting outside moq-dev is the maintainer's call. It is
  done once the issue's URL is recorded here.
