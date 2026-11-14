# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.3](https://github.com/kixel-ai/rind/compare/rind-python-v0.1.2...rind-python-v0.1.3) - 2026-11-14

### Added

- *(fips)* [**breaking**] the rind-fips module, and HKDF's extract and expand and CBC's padded encrypt return Result ([#704](https://github.com/kixel-ai/rind/pull/704))
- *(release)* publish pyrind-cryptography to PyPI ([#618](https://github.com/kixel-ai/rind/pull/618))
- *(python)* pyrind-cryptography, pyca's hazmat API on pyrind ([#553](https://github.com/kixel-ai/rind/pull/553))
- *(agreement)* [**breaking**] keys keep their public key and algorithm ([#529](https://github.com/kixel-ai/rind/pull/529))

### Fixed

- *(release)* release pyrind as 0.1.3, which pyrind-cryptography needs ([#688](https://github.com/kixel-ai/rind/pull/688))

### Other

- release and queue from the kixel-ai org ([#711](https://github.com/kixel-ai/rind/pull/711))
- *(dart,python)* say the bindings do not wipe ([#549](https://github.com/kixel-ai/rind/pull/549))

## [0.1.2](https://github.com/kixel-ai/rind/compare/rind-python-v0.1.1...rind-python-v0.1.2) - 2026-11-08

### Other

- *(python)* test musl and armv7 wheels ([#496](https://github.com/kixel-ai/rind/pull/496))

## [0.1.1](https://github.com/kixel-ai/rind/compare/rind-python-v0.1.0...rind-python-v0.1.1) - 2026-11-08

### Other

- updated the following local packages: rind

## [0.1.0](https://github.com/kixel-ai/rind/releases/tag/rind-python-v0.1.0) - 2026-11-07

### Added

- *(python)* pyrind, rind's API for Python ([#459](https://github.com/kixel-ai/rind/pull/459))
