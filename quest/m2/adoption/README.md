# Adoption beyond MoQ

## Goal

Popular projects that gain from rind's pure-Rust build or its ECC speed, and
whose crypto is less security-critical, can choose rind: through upstream
feature or provider-hook PRs, `rind-*` adapters, and rind packages for other
languages, with whatever rind itself lacks for them planned here too.

## Plan

Decided with the maintainer on 2026-11-04, in a planning interview. Settled;
don't ask again (✅ is the chosen option):

- Milestone: m2 ✅ / m3.
- Targets: graviola-precedent features (llrt, rusty-s3), rind-str0m,
  provider-neutral hooks (quinn, opendal, librespot), rustls's provider list
  and 0.24, Bun, Python, and Dart ✅. Node, React Native, Go, Java, .NET,
  Swift, Zig, and C libraries are out: they need OpenSSL's breadth or FIPS,
  which [m4](/quest/m4/README.md) holds, and rind wins there only on
  asymmetric ECC.
- opendal needs no quest: it already ships
  `http-transport-reqwest-rustls-no-provider`
  ([apache/opendal#7582](https://github.com/apache/opendal/pull/7582)), which
  the [migration prompt](/MIGRATE.md) can turn on.
- Big names on RustCrypto are marketing wins, since rind is several times
  faster ([BENCHMARKS.md](/BENCHMARKS.md)'s `nixos2`, an i7-8700: RSA-2048
  verify about 4.7x, P-256 sign and ECDH about 5x, ChaCha20-Poly1305 per
  packet about 3x, AES-GCM about 2x): Deno,
  Servo, Lemmy, tailscale-rs, snow's users, and Apache Iggy ✅. Deno is in
  for the marketing win though the maintainer considers it deprecated, and
  nothing is added to rind only for it. Considered and left out: RustFS
  (already links aws-lc-rs), YARA-X, age, Turso, rustic (needs a raw
  Poly1305 API), Kanidm (forbids AI-written code), Arti (security bar), and
  Bitwarden and Matrix (need wasm).
- No rind-graviola ✅: build it only if big crates use graviola directly.
  None does; every notable graviola user (llrt, rusty-s3, wtx, oxish) picks it
  with an optional feature, and `[patch]` cannot swap in a crate of another
  name, so a `rind` feature beside theirs is the path.
- Upstream PRs, issues, and discussions are outward-facing: each quest
  prepares the change and its text, then asks the maintainer before posting
  ✅ / starting the quest authorizes it. Posts carry the AI marker.
- Core-stack maintainers decline young providers by name
  ([quinn-rs/quinn#2253](https://github.com/quinn-rs/quinn/issues/2253),
  [transact-rs/sqlx#4408](https://github.com/transact-rs/sqlx/issues/4408)),
  so PRs to them are provider-neutral and stand on their own merits.
- Other-language packages live in this workspace as `rind-<consumer>` crates
  released by its CI ✅ / separate repositories; each language gets rind's own
  API and a second package with the popular library's interface ✅.
- rind-rustls's `default_provider()` keeps aws-lc-rs's algorithm list,
  P-521 included ✅ / drop P-521 as ring does (decided 2026-11-05 on
  [#375](https://github.com/moq-dev/rind/pull/375), which has the sizes): it
  is already smaller than aws-lc-rs's provider.
- Whatever these consumers need from rind itself is planned now: the
  WebCrypto set (AES-192, MD5, RSA-OAEP key labels and SPKI export, AES key
  wrap with padding, all landed) and platform coverage. RSA-2048 signing, which JWT's RS256 needs, is level with the
  fastest library on x86_64 in [BENCHMARKS.md](/BENCHMARKS.md).

## Required

- [rustls lists rind-rustls](/quest/m2/adoption/rustls-providers.md) - an entry in rustls's third-party provider list
- [rusty-s3 offers rind](/quest/m2/adoption/rusty-s3.md) - a `rind` feature beside its `graviola` one
- [quinn's rustls support works with any provider](/quest/m2/adoption/quinn.md) - quinn-proto stops forcing ring or aws-lc-rs
- [Bun's CryptoHasher takes SHA-3 from rind](/quest/m2/adoption/bun-sha3.md) - SHA-3 in Bun on rind, after the m1 Bun PR
- [pyrind on PyPI](/quest/m2/adoption/pyrind.md) - rind for Python with its own API
- [Lemmy's federation signs and verifies with rind](/quest/m2/adoption/lemmy.md) - activitypub-federation-rust's HTTP signatures off the `rsa` crate
- [rind-snow](/quest/m2/adoption/rind-snow.md) - snow's `CryptoResolver` on rind, for rathole and other Noise users
- [tailscale-rs's tunnel runs on rind](/quest/m2/adoption/tailscale-rs.md) - WireGuard's per-packet ChaCha20-Poly1305 on rind
- [llrt offers rind](/quest/m2/adoption/llrt.md) - `crypto-rind` and `tls-rind` features in AWS's Lambda runtime
- [Deno's WebCrypto and node:crypto run on rind](/quest/m2/adoption/deno.md) - Deno's RustCrypto paths moved to rind
- [Servo's WebCrypto runs on rind](/quest/m2/adoption/servo.md) - Servo's RustCrypto WebCrypto moved to rind
- [pyca-compatible pyrind](/quest/m2/adoption/pyrind-cryptography.md) - pyca's `hazmat` names on pyrind
- [Talk to pyca about rind](/quest/m2/adoption/pyca.md) - a discussion with pyca/cryptography's maintainers
- [rind for Dart and Flutter](/quest/m2/adoption/rind-dart.md) - the `rind` package on pub.dev
- [rind as a Dart `cryptography` backend](/quest/m2/adoption/rind-dart-cryptography.md) - the `cryptography` package's interface on rind
- [Apache Iggy encrypts streams with rind](/quest/m2/adoption/iggy.md) - its AES-256-GCM message encryption on rind
- [librespot builds rustls without ring](/quest/m2/adoption/librespot.md) - users pick their rustls provider
- [rind-rustls supports rustls 0.24](/quest/m2/adoption/rind-rustls-0.24.md) - a release on 0.24 soon after it ships
- [rustls 0.24 is released](/quest/m2/adoption/rustls-0.24-release.md) - waiting on the release
- [rind replaces ring and aws-lc-rs throughout a binary's tree](/quest/m2/adoption/aws-lc-rs/README.md) - rind-aws-lc-rs, and git-only `ring` and `aws-lc-rs` patch shims
- [rind on every ring or aws-lc-rs target](/quest/m2/adoption/targets/README.md) - a portable backend for every architecture except wasm, so libraries can go rind-only
