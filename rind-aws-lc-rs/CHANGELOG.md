# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0.3](https://github.com/kixel-ai/rind/compare/rind-aws-lc-rs-v1.0.2...rind-aws-lc-rs-v1.0.3) - 2026-11-14

### Added

- *(fips)* [**breaking**] the rind-fips module, and HKDF's extract and expand and CBC's padded encrypt return Result ([#704](https://github.com/kixel-ai/rind/pull/704))
- *(agreement)* [**breaking**] keys keep their public key and algorithm ([#529](https://github.com/kixel-ai/rind/pull/529))
- *(cipher)* [**breaking**] AES-CBC encryption takes a typed CbcIv ([#530](https://github.com/kixel-ai/rind/pull/530))

### Fixed

- *(aws-lc-rs)* keep an RSA key outside an algorithm's range and fail at verify ([#751](https://github.com/kixel-ai/rind/pull/751))
- *(aws-lc-rs)* run aws-lc-rs's own tests, and zero a refused TLS seal's output ([#679](https://github.com/kixel-ai/rind/pull/679))
- repair nightly checks and ARM AES key wiping ([#513](https://github.com/kixel-ai/rind/pull/513))
- *(aws-lc-rs)* offer exactly aws-lc-rs 1.x's API ([#522](https://github.com/kixel-ai/rind/pull/522))

### Other

- diff each adapter's API against its upstream's ([#698](https://github.com/kixel-ai/rind/pull/698))
- release and queue from the kixel-ai org ([#711](https://github.com/kixel-ai/rind/pull/711))
- ML-DSA-44, ML-DSA-65, and ML-DSA-87 ([#610](https://github.com/kixel-ai/rind/pull/610))
- fail on key-derived heap scratch freed unwiped ([#581](https://github.com/kixel-ai/rind/pull/581))

## [1.0.2](https://github.com/kixel-ai/rind/compare/rind-aws-lc-rs-v1.0.1...rind-aws-lc-rs-v1.0.2) - 2026-11-08

### Other

- updated the following local packages: rind

## [1.0.1](https://github.com/kixel-ai/rind/compare/rind-aws-lc-rs-v1.0.0...rind-aws-lc-rs-v1.0.1) - 2026-11-08

### Other

- updated the following local packages: rind

## [1.0.0](https://github.com/kixel-ai/rind/releases/tag/rind-aws-lc-rs-v1.0.0) - 2026-11-07

### Added

- *(aws-lc-rs)* rind-aws-lc-rs offers aws-lc-rs 1.x's API backed by rind ([#465](https://github.com/kixel-ai/rind/pull/465))
