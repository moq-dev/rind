# Migrating from ring and aws-lc-rs

This guide will map each ring and aws-lc-rs item to rind's.
So far it maps `signature`, errors, and the adapter crates, and surveys the
crates that pick a crypto backend for you.

## signature

ring's names match aws-lc-rs's here, except where noted.

| aws-lc-rs | rind |
|---|---|
| `UnparsedPublicKey::new(alg, bytes).verify(m, s)` | `PublicKey::new(alg, bytes)?.verify(m, s)` |
| `ParsedPublicKey::new(alg, bytes)`, `verify_sig` | `PublicKey::new(alg, bytes)`, `verify` |
| `RsaPublicKeyComponents::verify(alg, m, s)` | `components.to_public_key(alg)?.verify(m, s)` |
| `VerificationAlgorithm` trait, `EcdsaVerificationAlgorithm`, `EdDSAParameters` | `VerificationAlgorithm` |
| `RsaParameters` | `RsaVerificationAlgorithm`, which `PublicKey::new` also takes |
| `EcdsaSigningAlgorithm`, `RsaEncoding`/`RsaSignatureEncoding` | `EcdsaSigningAlgorithm`, `RsaSigningAlgorithm` |
| `ECDSA_P256_SHA256_ASN1_SIGNING` and the other `_SIGNING` | `sign::ECDSA_P256_SHA256_ASN1` |
| `ECDSA_P256_SHA256_ASN1`, `ED25519` | `verify::ECDSA_P256_SHA256_ASN1`, `verify::ED25519` |
| `RSA_PKCS1_SHA256`, `RSA_PSS_SHA256` | `sign::RSA_PKCS1_SHA256`, `sign::RSA_PSS_SHA256` |
| `RSA_PKCS1_2048_8192_SHA256`, `RSA_PSS_2048_8192_SHA256` | `verify::RSA_PKCS1_SHA256`, `verify::RSA_PSS_SHA256` |
| `RSA_PKCS1_3072_8192_SHA384` | `verify::legacy::RSA_PKCS1_3072_SHA384` |
| `RSA_PKCS1_1024_8192_SHA256_FOR_LEGACY_USE_ONLY` (also SHA-1, SHA-512) | `verify::legacy::RSA_PKCS1_1024_SHA256` |
| `RSA_PKCS1_2048_8192_SHA1_FOR_LEGACY_USE_ONLY` | `verify::legacy::RSA_PKCS1_SHA1` |
| `KeyPair::public_key()` | inherent `public_key()`, a `PublicKey`; `RsaKeyPair::public_key(&sign::X)` |
| `EcdsaKeyPair::from_private_key_der` | `from_sec1`, which refuses PKCS#8 |
| `RsaKeyPair::from_der` | `from_pkcs1` |
| `Ed25519KeyPair::from_pkcs8_maybe_unchecked` | `from_pkcs8`, which takes v1 and v2 |
| `to_pkcs8()`, `public_key().as_der()`, each an allocated `Document` | `to_pkcs8()`, `to_spki()`, each of fixed capacity; `Pkcs8` is wiped on drop |
| `EcdsaKeyPair::sign(rng, m)`, `RsaKeyPair::sign(alg, rng, m, &mut sig)` | `sign(m)`, `sign(alg, m)`, which take no random source and return a `Signature` |
| `rsa::KeySize` | `RsaKeySize` |
| `Ed25519KeyPair::seed()`, `private_key().as_be_bytes()`, `public_modulus_len()` | none |

`PublicKey::new` refuses a compressed ECDSA point, which aws-lc-rs takes.

## error

aws-lc-rs's `error::Unspecified` and `error::KeyRejected` become one
`rind::Error`, whose variant depends on the kind of call. ring's names match.
`Error` is `#[non_exhaustive]`, so a `match` on it needs a wildcard arm.

| aws-lc-rs | rind |
|---|---|
| `KeyRejected`, from loading a key pair | `Error::KeyRejected` |
| `Unspecified`, from a peer's or public key that is malformed, off the curve, or the wrong length | `Error::KeyRejected`, from `PublicKey::new`, `agree`, or `EncapsulationKey::new` |
| `KeyRejected::description_()` | `KeyRejected`'s `Display` |
| `Unspecified`, from `verify`, `hmac::verify`, or `pbkdf2::verify` | `Error::BadSignature` |
| `Unspecified`, from `open_in_place` | `Error::DecryptFailed` |
| `Unspecified`, from a symmetric key, nonce, tag, or output of the wrong length | `Error::WrongLength` |
| `Unspecified`, from `SystemRandom::fill` or `generate` | `Error::RngFailed` |
| `Unspecified`, from `constant_time::verify_slices_are_equal` | `Error::NotEqual` |
| `Unspecified`, from RSA signing or ECDH when an internal check fails | `Error::Fault` |

## Adapter crates

Each `rind-*` crate stands in for a crate's aws-lc-rs or ring backend. rind
panics on a CPU missing a feature it requires, so every adapter entry point
that is a function refuses one with `rind::cpu::MissingFeature` instead. A
static that the upstream crate requires, such as `DEFAULT_PROVIDER`, cannot,
so call `rind::cpu::check()` before using it.

### rind-rustls

rind-rustls mirrors the layout of rustls's own providers.

| rustls `crypto::aws_lc_rs` | rind-rustls |
|---|---|
| `default_provider()` | `default_provider()?` |
| `DEFAULT_CIPHER_SUITES`, `ALL_CIPHER_SUITES` | the same, preferring AES-128-GCM to AES-256-GCM; `default_provider()` puts ChaCha20-Poly1305 first where rind runs AES without CPU instructions |
| `DEFAULT_KX_GROUPS`, `ALL_KX_GROUPS` | the same: X25519MLKEM768, X25519, P-256, then P-384 |
| `cipher_suite::*` | the same nine suites |
| `kx_group::X25519`, `SECP256R1`, `SECP384R1`, `X25519MLKEM768` | the same |
| `kx_group::SECP256R1MLKEM768`, `MLKEM768`, `MLKEM1024` | none |
| `Ticketer::new()` | the same, which also refuses a CPU missing a feature |
| `sign::any_supported_type` and the other `sign` loaders, `hpke` | none; load keys through the provider's `key_provider` |

rind-rustls signs with RSA, ECDSA P-256 and P-384, and Ed25519 keys; ECDSA
P-521 neither signs nor verifies.

### rind-rcgen

`rind_rcgen::KeyPair` replaces `rcgen::KeyPair` for ECDSA P-256 and P-384,
Ed25519, and RSA with PKCS#1 v1.5. It cannot sign with P-521: rcgen names
those algorithms only with its `aws_lc_rs` feature.

| rcgen | rind-rcgen |
|---|---|
| `KeyPair::generate()` | `KeyPair::generate(&PKCS_ECDSA_P256_SHA256)` |
| `KeyPair::generate_for(alg)` | `KeyPair::generate(alg)`; RSA fails with `KeyGenerationUnavailable` |
| `KeyPair::from_pkcs8_der_and_sign_algo(der, alg)` | `KeyPair::from_pkcs8(alg, der)` |
| `KeyPair::from_der_and_sign_algo`, `from_pem`, `TryFrom` | none; convert the key to PKCS#8 and pass its algorithm |
| `serialize_der()`, `serialized_der()`, `PrivatePkcs8KeyDer::from(&key)` | `to_pkcs8()`, wiped on drop |
| `Error::RingKeyRejected`, `RingUnspecified` | the same variants, with rind's reason for a refused key |

### rind-dimpl, rind-object-store, rind-jsonwebtoken, and rind-instant-acme

| aws-lc-rs backend | rind |
|---|---|
| dimpl's `crypto::aws_lc_rs::default_provider()` | `rind_dimpl::default_provider()?` |
| object_store's `aws`, `azure`, and `gcp` features | the `*-base` features, with `with_crypto_provider(rind_object_store::default_provider()?)` |
| jsonwebtoken's `crypto::aws_lc::DEFAULT_PROVIDER` | `rind_jsonwebtoken::DEFAULT_PROVIDER`, after `rind::cpu::check()?` |
| instant-acme's built-in provider | `Account::builder(http, &rind_instant_acme::DEFAULT_PROVIDER)`, after `rind::cpu::check()?` |

## Crates with their own crypto backend

Surveyed on 2026-10-31 against each crate's latest release, by reading its
features and source; none were built. A migrated graph should give no output
from `cargo tree -e normal,build -i ring` or `-i aws-lc-sys`.

"Install" means calling `rind_rustls::default_provider()?.install_default()`
before the crate builds its TLS config. Crates that read rustls's process
default panic without one, and a few (jsonrpsee, pingora, tauri on mobile)
install ring's if nothing is installed first.

- **rind-rustls**: TLS runs through rustls. Pick the listed features and
  install or pass rind-rustls's provider.
- **rind-x**: an existing adapter crate covers it.
- **Pure Rust**: its default build, or the listed features, use neither.
- **Adapter**: a new `rind-*` crate could cover it through a public hook.
  [Adapters](#adapters) says which are worth building.
- **Unsupported**: ring or aws-lc-rs is hard-wired. The cell names the
  alternative or the upstream change that would fix it.

### TLS and HTTP

| Crate | What ties it | On rind |
|---|---|---|
| rustls 0.23 | `ring` and `aws_lc_rs` features pick a provider | **rind-rustls**: `default-features = false`, `std`, `tls12` |
| rustls-webpki 0.103 | `ring` and `aws-lc-rs` fill `ALL_VERIFICATION_ALGS` | **rind-rustls**: no features; direct callers pass the provider's `signature_verification_algorithms.all` |
| rustls-platform-verifier 0.7 | none | **rind-rustls**: `Verifier::new(provider)` |
| tokio-rustls 0.26, futures-rustls 0.26 | default `aws_lc_rs` | **rind-rustls**: `default-features = false`, `logging`, `tls12` |
| hyper-rustls 0.27 | default `aws-lc-rs` | **rind-rustls**: `default-features = false` and a `with_provider_and_*` builder; `with_native_roots()` and its siblings need ring or aws-lc-rs |
| reqwest 0.13 | default `rustls` is aws-lc-rs | **rind-rustls**: `rustls-no-provider`, install. `http3` always enables aws-lc-rs |
| ureq 3 | default `rustls` is ring | **rind-rustls**: `rustls-no-provider` (marked unstable) and a roots feature |
| axum-server 0.8 | `tls-rustls` is aws-lc-rs | **rind-rustls**: `tls-rustls-no-provider`, install |
| actix-web 4, actix-tls 3 | none | **rind-rustls**: `rustls-0_23`, with a config built on rind-rustls |
| tonic 0.14 | `tls-ring`, `tls-aws-lc` | **rind-rustls**: `tls-native-roots` or `tls-webpki-roots` alone (a server-only build needs `_tls-any`), install |
| tungstenite 0.30, tokio-tungstenite 0.30 | none | **rind-rustls**: a `rustls-tls-*-roots` feature, install |
| tokio-websockets 0.13 | handshake SHA-1 from ring, aws-lc-rs, or OpenSSL | **rind-rustls**: `sha1_smol` and `rustls-bring-your-own-connector` |
| lettre 0.11 | `rustls-tls` is ring | **rind-rustls**: `rustls-no-provider`, install |
| kube 4 | default `rustls-tls` with `ring` | **rind-rustls**: `client` and `rustls-tls`, install. `oidc` and `oauth` need ring |
| async-nats 0.51 | default `ring`; `crypto` hashes with it | **rind-rustls**: without `ring`, `crypto`, or `object-store`, install |
| mysql_async 0.37 | `default-rustls` is aws-lc-rs | **rind-rustls**: `default-rustls-no-provider`, install |
| tokio-postgres-rustls 0.14 | optional, off by default | **rind-rustls**: default features |
| bollard 0.21 | `ssl` is ring | **rind-rustls**: `ssl_providerless`, install |
| ldap3 0.12 | `tls-rustls-*`; `gssapi` and `ntlm` call ring | **rind-rustls**: `tls-rustls` and `rustls-provider`, install; not `gssapi` or `ntlm` |
| metrics-exporter-prometheus 0.18 | `push-gateway` is aws-lc-rs | **rind-rustls**: `push-gateway-no-tls-provider`, install |
| tauri 2 | mobile `rustls-tls` installs ring | **rind-rustls**: desktop needs nothing; mobile skips `rustls-tls`; tauri-plugin-http goes through reqwest 0.12's `rustls-tls-native-roots-no-provider` |
| AWS SDK: aws-config 1, aws-smithy-http-client 1 | `default-https-client` is aws-lc-rs; the legacy `rustls` default is ring | **rind-rustls** only under `--cfg aws_sdk_unstable`, through `CryptoMode::Custom`; otherwise Adapter. Request signing (aws-sigv4) is pure Rust |
| poem 3 | `rustls` calls aws-lc-rs; `acme*` calls ring | Adapter: a TLS `Acceptor` over tokio-rustls |
| sqlx 0.9 | `tls-rustls-*` hard-code ring's or aws-lc-rs's provider | Unsupported: needs a no-provider feature upstream |
| mongodb 3 | hard-codes the provider | Unsupported: needs a no-provider feature upstream |
| fred 10 | rustls only behind `enable-rustls` (aws-lc-rs) or `enable-rustls-ring` | Unsupported: needs a no-provider feature upstream |
| rskafka 0.6 | `transport-tls` enables ring | Unsupported: `tls_config` takes a rind-rustls config, but ring stays linked |
| jsonrpsee 0.26 | `tls` enables and installs ring | Unsupported over TLS |
| pingora 0.9 | pingora-rustls depends on ring | Unsupported |
| tiny_http 0.12 | `ssl-rustls` is rustls 0.20 | Unsupported over TLS |
| webpki 0.22, sct 0.7 | ring, unconditionally | Unsupported: legacy; move to rustls 0.23 and rustls-webpki |

### QUIC, WebRTC, and peer-to-peer

| Crate | What ties it | On rind |
|---|---|---|
| quinn 0.11, quinn-proto 0.11, h3-quinn | `rustls` is an alias for `rustls-ring`; the Retry tag, reset key, and token key call ring or aws-lc-rs | Unsupported: use noq, or ask quinn for a provider-only `rustls` feature |
| noq 1.4 | default `ring` | **rind-rustls**: `rustls` without `ring`, plus the caller's `HmacKey` and `HandshakeTokenKey` on rind's HMAC, HKDF, and AES-256-GCM |
| iroh 1.4 | default `tls-ring` picks the provider | **rind-rustls**: `default-features = false`, `Endpoint::builder().crypto_provider(..)`. iroh-relay's `server` enables ring |
| wtransport 0.7 | needs `ring` or `aws-lc-rs`, and quinn's defaults | Unsupported |
| s2n-quic 1 | s2n-quic-crypto always links aws-lc-rs | Unsupported |
| quiche 0.30 | BoringSSL | Unsupported: C |
| dimpl 0.9 | default aws-lc-rs | **rind-dimpl** |
| str0m | default aws-lc-rs; its provider interface is unreleased | Adapter: rind-str0m covered it and was removed for lack of a consumer |
| webrtc 0.21 (rtc 0.21) | default `crypto-ring`, or `crypto-aws-lc-rs` | Unsupported: `RTCCryptoProvider` could carry an adapter, but none is planned without a consumer |
| webrtc-dtls 0.12, stun 0.17, turn 0.17 | ring, unconditionally | Unsupported: move to webrtc 0.21 |
| libp2p-tls 0.7, libp2p-quic 0.14, libp2p-noise 0.47 | aws-lc-rs and ring, unconditionally | Unsupported: needs a provider hook upstream |
| snow 0.10 | opt-in `ring-resolver` | **Pure Rust** by default. Adapter through `CryptoResolver`, once rind loads static X25519 keys |
| boringtun 0.7 | ring's ChaCha20-Poly1305 and constant-time comparison | Unsupported |

### DNS

| Crate | What ties it | On rind |
|---|---|---|
| hickory-proto, hickory-net, hickory-resolver 0.26 | TLS, HTTPS, and QUIC need a `*-ring` or `*-aws-lc-rs` feature; DNSSEC validation calls them internally | Unsupported: `with_tls_config` takes a rind-rustls config, but ring stays linked. Plain DNS is unaffected. rind has every primitive DNSSEC needs |
| domain 0.12 | DNSSEC and TSIG need ring or OpenSSL | Unsupported: its backend is a closed enum |

### Certificates, ACME, and tokens

| Crate | What ties it | On rind |
|---|---|---|
| rcgen 0.14 | default `ring`, or `aws_lc_rs`, gates `KeyPair` | **rind-rcgen**: ECDSA P-256 and P-384, Ed25519, and loaded RSA keys. Without rcgen's `crypto` feature, set the serial number and `key_identifier_method` yourself, or the subject key identifier is empty |
| instant-acme | 0.8 calls aws-lc-rs or ring; the unreleased 0.9 takes a `CryptoProvider` | **rind-instant-acme** on 0.9. `Order::finalize` needs ring or aws-lc-rs; call `finalize_csr` with a CSR from rcgen on rind-rcgen |
| rustls-acme 0.15, tokio-rustls-acme 0.9 | account keys and CSRs call ring or aws-lc-rs | Unsupported: use instant-acme on rind-instant-acme |
| x509-parser 0.18 | `verify` is ring, `verify-aws` aws-lc-rs | Unsupported: verify `tbs_certificate` with `rind::signature` instead |
| x509-certificate 0.25, cryptographic-message-syntax 0.28 | ring types in their public API | Unsupported |
| sigstore 0.14, tough 0.24 | aws-lc-rs, unconditionally | Unsupported |
| jsonwebtoken 11 | optional `aws_lc_rs` | **rind-jsonwebtoken**, every algorithm. `rust_crypto` is the pure-Rust alternative |
| jwtk 0.5 | default `aws-lc` for RSA verification and JWK conversion | Adapter, for caller-held keys only |
| biscuit 0.8, rusty_paseto 0.10, paseto 2 | ring, unconditionally | Unsupported |
| passkey 0.6 (passkey-crypto) | optional `aws-lc-rs` | **Pure Rust** by default |
| tame-oauth 0.10 | `jwt` is ring | Unsupported |
| gcp_auth 0.12 | default `ring` for TLS and service-account signing | **rind-rustls** without `ring` or `aws-lc-rs`; service-account keys need a signing hook upstream |
| google-cloud-auth 1 | defaults are aws-lc-rs | **rind-rustls**: `default-features = false`, install; signing loads keys through the installed provider. `idtoken` also installs rind-jsonwebtoken |
| yup-oauth2 12 | default `ring` for TLS and service-account signing | **rind-rustls** for user flows, through `with_client` and hyper-rustls; service accounts need a signing hook upstream |
| matrix-sdk-crypto 0.19 | opt-in `rust-x509-verifier-impl` | **Pure Rust** without it |

### Storage, databases, and other

| Crate | What ties it | On rind |
|---|---|---|
| object_store 0.14 | `aws`, `gcp`, `azure` and `http` enable aws-lc-rs | **rind-object-store**, with the `*-base` features; HTTPS through reqwest on rind-rustls |
| parquet 60 | `encryption` calls ring | Unsupported |
| russh 0.65 | default `aws-lc-rs`, or `ring`, for its AES-GCM and ChaCha20-Poly1305 transport | Unsupported: its cipher trait is private |
| scram 0.6 | ring, unconditionally | Unsupported |
| ethereum_hashing 0.8 | default `ring` for SHA-256 | **Pure Rust** on x86_64; other targets need ring |

## Adapters

No new adapter is planned (maintainer, 2026-10-31):

- **quinn**: its rustls integration cannot be built without ring or
  aws-lc-rs, so an adapter would carry its own port of quinn's
  `crypto::rustls` session. noq, quinn's fork, already runs on rind-rustls.
- **webrtc**: `rtc_crypto::RTCCryptoProvider` covers all of its crypto, and
  rind lacks only MD5 (for TURN's long-term credentials) and the AES-CCM and
  AES-CBC DTLS suites, but no consumer asks for it.

Nor are these worth a crate:

- **AWS SDK**: the adapter would be a whole HTTP client; stabilizing
  `CryptoMode::Custom` upstream needs none.
- **snow**: its default backend is already pure Rust, and rind cannot yet
  load a static X25519 key or hash with BLAKE2.
- **poem** and **jwtk**: each is a few lines of the caller's code over
  tokio-rustls or rind's signatures.
