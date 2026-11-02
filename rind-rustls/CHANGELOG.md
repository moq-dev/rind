# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.6](https://github.com/moq-dev/rind/compare/rind-rustls-v0.1.5...rind-rustls-v0.1.6) - 2026-11-02

### Other

- updated the following local packages: rind

## [0.1.5](https://github.com/moq-dev/rind/compare/rind-rustls-v0.1.4...rind-rustls-v0.1.5) - 2026-11-01

### Other

- updated the following local packages: rind

## [0.1.4](https://github.com/moq-dev/rind/compare/rind-rustls-v0.1.3...rind-rustls-v0.1.4) - 2026-11-01

### Other

- updated the following local packages: rind

## [0.1.3](https://github.com/moq-dev/rind/compare/rind-rustls-v0.1.2...rind-rustls-v0.1.3) - 2026-11-01

### Other

- updated the following local packages: rind

## [0.1.2](https://github.com/moq-dev/rind/compare/rind-rustls-v0.1.1...rind-rustls-v0.1.2) - 2026-11-01

### Added

- *(x86_64)* AES and GHASH without AVX or AES-NI ([#172](https://github.com/moq-dev/rind/pull/172))

## [0.1.1](https://github.com/moq-dev/rind/compare/rind-rustls-v0.1.0...rind-rustls-v0.1.1) - 2026-11-01

### Added

- *(aarch64)* run on CPUs without the crypto extension ([#157](https://github.com/moq-dev/rind/pull/157))
- *(rustls)* SECP256R1MLKEM768, MLKEM768, secp521r1, and ECDSA P-521, as aws-lc-rs's provider ([#150](https://github.com/moq-dev/rind/pull/150))

### Fixed

- *(rustls)* declare the oldest rustls rind-rustls builds and tests with ([#152](https://github.com/moq-dev/rind/pull/152))

## [0.1.0](https://github.com/moq-dev/rind/releases/tag/rind-rustls-v0.1.0) - 2026-10-31

### Added

- [**breaking**] adapters mirror their upstreams and refuse unsupported CPUs at setup ([#143](https://github.com/moq-dev/rind/pull/143))
- [**breaking**] errors by role, and RSA components take only an RSA algorithm ([#142](https://github.com/moq-dev/rind/pull/142))
- *(signature)* [**breaking**] one PublicKey, sign and verify constants, owned encodings, RSA key checks ([#140](https://github.com/moq-dev/rind/pull/140))
- [**breaking**] aead::Key, typed tags, legacy submodules, infallible HKDF expand ([#139](https://github.com/moq-dev/rind/pull/139))
- *(agreement,kem)* [**breaking**] PrivateKey::agree, public_key(), slice ciphertexts ([#137](https://github.com/moq-dev/rind/pull/137))
- *(aead)* QUIC header-protection keys ([#132](https://github.com/moq-dev/rind/pull/132))
- [**breaking**] rind::rand, deviation docs, and the aws-lc-rs API surface audit ([#94](https://github.com/moq-dev/rind/pull/94))
- *(rustls)* prefer ChaCha20-Poly1305 without AES hardware ([#92](https://github.com/moq-dev/rind/pull/92))
- [**breaking**] signature key pairs bound to algorithm constants ([#89](https://github.com/moq-dev/rind/pull/89))
- *(hmac)* [**breaking**] reusable HMAC keys bound to an algorithm constant ([#83](https://github.com/moq-dev/rind/pull/83))
- [**breaking**] agreement and kem modules with algorithm constants ([#79](https://github.com/moq-dev/rind/pull/79))
- *(aead)* [**breaking**] AEAD and cipher keys bound to an algorithm constant ([#75](https://github.com/moq-dev/rind/pull/75))
- [**breaking**] digest constants replace the Hash trait ([#77](https://github.com/moq-dev/rind/pull/77))
- *(aead)* [**breaking**] AesGcm::new refuses a bad key length ([#43](https://github.com/moq-dev/rind/pull/43))
- [**breaking**] AEADs refuse over-long messages ([#34](https://github.com/moq-dev/rind/pull/34))
- P-384 on armv7 over fiat-crypto's arithmetic ([#23](https://github.com/moq-dev/rind/pull/23))
- raw AES, AES-CTR, and ChaCha20 on armv7 ([#21](https://github.com/moq-dev/rind/pull/21))
- *(rustls)* QUIC packet and header protection keys ([#15](https://github.com/moq-dev/rind/pull/15))
- build armv7 on a libcrux backend ([#8](https://github.com/moq-dev/rind/pull/8))
- [**breaking**] bootstrap rind from graviola ([#1](https://github.com/moq-dev/rind/pull/1))

### Fixed

- *(rustls)* refuse oversized TLS 1.2 ChaCha20-Poly1305 records ([#135](https://github.com/moq-dev/rind/pull/135))

### Other

- attribute every algorithm's source and license ([#88](https://github.com/moq-dev/rind/pull/88))
- follow the move to moq-dev/rind ([#50](https://github.com/moq-dev/rind/pull/50))
- one workspace rust-version ([#33](https://github.com/moq-dev/rind/pull/33))
- ctgrind the adapter crates' secret paths ([#19](https://github.com/moq-dev/rind/pull/19))
- start rind at 0.1.0 and enable releases ([#2](https://github.com/moq-dev/rind/pull/2))
