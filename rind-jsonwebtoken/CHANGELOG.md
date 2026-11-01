# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.4](https://github.com/moq-dev/rind/compare/rind-jsonwebtoken-v0.1.3...rind-jsonwebtoken-v0.1.4) - 2026-11-01

### Other

- updated the following local packages: rind

## [0.1.3](https://github.com/moq-dev/rind/compare/rind-jsonwebtoken-v0.1.2...rind-jsonwebtoken-v0.1.3) - 2026-11-01

### Other

- updated the following local packages: rind

## [0.1.2](https://github.com/moq-dev/rind/compare/rind-jsonwebtoken-v0.1.1...rind-jsonwebtoken-v0.1.2) - 2026-11-01

### Other

- updated the following local packages: rind

## [0.1.1](https://github.com/moq-dev/rind/compare/rind-jsonwebtoken-v0.1.0...rind-jsonwebtoken-v0.1.1) - 2026-11-01

### Other

- updated the following local packages: rind

## [0.1.0](https://github.com/moq-dev/rind/releases/tag/rind-jsonwebtoken-v0.1.0) - 2026-10-31

### Added

- [**breaking**] adapters mirror their upstreams and refuse unsupported CPUs at setup ([#143](https://github.com/moq-dev/rind/pull/143))
- [**breaking**] errors by role, and RSA components take only an RSA algorithm ([#142](https://github.com/moq-dev/rind/pull/142))
- *(signature)* [**breaking**] one PublicKey, sign and verify constants, owned encodings, RSA key checks ([#140](https://github.com/moq-dev/rind/pull/140))
- [**breaking**] aead::Key, typed tags, legacy submodules, infallible HKDF expand ([#139](https://github.com/moq-dev/rind/pull/139))
- *(signature)* legacy RSA verification and keys from components ([#130](https://github.com/moq-dev/rind/pull/130))
- [**breaking**] signature key pairs bound to algorithm constants ([#89](https://github.com/moq-dev/rind/pull/89))
- *(hmac)* [**breaking**] reusable HMAC keys bound to an algorithm constant ([#83](https://github.com/moq-dev/rind/pull/83))
- [**breaking**] agreement and kem modules with algorithm constants ([#79](https://github.com/moq-dev/rind/pull/79))
- [**breaking**] digest constants replace the Hash trait ([#77](https://github.com/moq-dev/rind/pull/77))
- P-384 on armv7 over fiat-crypto's arithmetic ([#23](https://github.com/moq-dev/rind/pull/23))
- build armv7 on a libcrux backend ([#8](https://github.com/moq-dev/rind/pull/8))
- *(jsonwebtoken)* add rind-jsonwebtoken ([#9](https://github.com/moq-dev/rind/pull/9))

### Other

- attribute every algorithm's source and license ([#88](https://github.com/moq-dev/rind/pull/88))
- follow the move to moq-dev/rind ([#50](https://github.com/moq-dev/rind/pull/50))
- one workspace rust-version ([#33](https://github.com/moq-dev/rind/pull/33))
- ctgrind the adapter crates' secret paths ([#19](https://github.com/moq-dev/rind/pull/19))
