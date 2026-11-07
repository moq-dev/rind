# [S] rind for Dart and Flutter

## Goal

The `rind` package on pub.dev brings rind to Dart and Flutter through FFI,
with rind's own API, built by Dart's native-asset hooks for Android (aarch64,
armv7, x86_64), iOS, macOS, Linux, and Windows, where pure-Dart crypto
(pointycastle, `cryptography`'s Dart backend) is up to 100x slower.

## Plan

Decided with the maintainer on 2026-11-04, in a planning interview:

- Two packages, as rind and rind-ring are: this one with rind's own API, and
  [a `cryptography` backend](/quest/m2/adoption/rind-dart-cryptography.md) on
  top ✅ / one package.
- It lives in this workspace as a `rind-dart` crate with its Dart package,
  released by this repository's CI ✅ / a separate repository.

The package is in `rind-dart/`: its build hook compiles the crate with cargo,
and `.github/workflows/dart-release.yml` publishes it when a
`rind-dart-v<version>` tag is pushed, staged by `sh/dart-package.sh` against
rind from crates.io. What remains is the first release and a phone's
benchmark numbers in its README.

## Waiting

- Maintainer: publish 0.1.0 by hand, since pub.dev turns on automated
  publishing only for a package that exists and an agent holds no pub.dev
  account: run `sh/dart-package.sh <dir>`, then `dart pub publish` in `<dir>`.
  Then, on the package's admin page, enable publishing from GitHub Actions for
  `moq-dev/rind` with tag pattern `rind-dart-v{{version}}` and required
  environment `pub.dev`, and create that environment in the repository,
  deployable only from `rind-dart-v*` tags. Check that
  https://pub.dev/packages/rind lists 0.1.0.
- Maintainer: run `benchmark/compare.dart`'s `main` in a release-mode Flutter
  app on an Android armv7 or aarch64 phone, where rind's lead is largest, and
  add its numbers to `rind-dart/README.md`; an agent has no phone to run it
  on, and the emulator's numbers would not represent one.
