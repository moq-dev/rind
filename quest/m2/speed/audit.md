# [L] Audit every algorithm's speed

## Goal

A report, in the PR and README's Algorithms table, of every exported
algorithm on every path at the epic's sizes, timed against aws-lc-rs, ring,
and every other permissively licensed source usable from Rust, naming the
fastest source for each cell and recommending one quest per gap, described
fully enough for `/quest-plan`.

## Plan

The decisions are in the [epic](/quest/m2/speed/README.md).

- Fill the bench matrix first: every algorithm (SHA-1, SHA-2, SHA-512/256,
  HMAC, HKDF, PBKDF2, AES-GCM, AES-CTR, QUIC header protection,
  ChaCha20-Poly1305, XChaCha20-Poly1305, X25519, ECDH and ECDSA on P-256,
  P-384, and P-521, Ed25519, RSA sign, verify, and key generation, ML-KEM-768)
  on every path, with ring added as a nightly baseline beside aws-lc-rs.
  Forced tiers time release builds with `--cfg rind_cpu_disable`, as
  `bench.yml` does.
- Add rind-rustls handshake (full and resumed, per key exchange group and
  signature scheme) and bulk-transfer benches against aws-lc-rs's and ring's
  rustls providers.
- Measure the other candidate sources once, in a scratch harness outside
  the published crates: RustCrypto, libcrux, upstream graviola, BoringSSL
  through bindings, and any newer release of an imported source. Note each
  source's license and verification.
- Known leads to confirm or drop: HMAC and HKDF on one-block inputs, armv7
  P-521 verification (1.05x), ChaCha20-Poly1305 without AVX2 (1.22-1.27x
  from 1200 B against aws-lc's SSE4.1 combined routine, #181), SHA-256 fed
  1-byte updates without SHA-NI (1.10-1.17x, #181), RSA-2048 signing without
  AVX2 (1.11x, #181), and ES256 and EdDSA per-token cost in moq-auth's bench.
- Land the bench rows, ring baseline, handshake benches, and README table;
  create no quests, but list each recommended gap quest with its numbers.
