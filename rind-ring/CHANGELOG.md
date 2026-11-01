# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0](https://github.com/moq-dev/rind/compare/rind-ring-v0.1.1...rind-ring-v0.2.0) - 2026-11-01

### Fixed

- [**breaking**] fuzz the key loaders, take compressed key pair points, refuse ECDSA and RSA PKCS#8 v2 ([#166](https://github.com/moq-dev/rind/pull/166))

## [0.1.1](https://github.com/moq-dev/rind/compare/rind-ring-v0.1.0...rind-ring-v0.1.1) - 2026-11-01

### Other

- updated the following local packages: rind

## [0.1.0](https://github.com/moq-dev/rind/releases/tag/rind-ring-v0.1.0) - 2026-11-01

### Added

- accept 33-bit RSA public exponents ([#161](https://github.com/moq-dev/rind/pull/161))
- load PKCS#8 keys carrying attributes ([#160](https://github.com/moq-dev/rind/pull/160))
- *(ring)* add rind-ring, ring 0.17's API on rind ([#151](https://github.com/moq-dev/rind/pull/151))

### Fixed

- *(ring)* [**breaking**] pbkdf2::derive returns () and panics as ring's does ([#154](https://github.com/moq-dev/rind/pull/154))
