// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

/// rind's cryptography for Dart and Flutter, through FFI to the pure-Rust
/// rind library.
///
/// Algorithms only legacy protocols should use are in
/// `package:rind/legacy.dart`.
library;

export 'src/bindings.dart'
    hide
        digestMd5,
        digestSha1,
        hkdfSha1,
        hmacSha1,
        oaepSha1,
        pbkdf2HmacSha1,
        rsaPkcs1Min1024Sha1,
        rsaPkcs1Min1024Sha256,
        rsaPkcs1Min1024Sha512,
        rsaPkcs1Min3072Sha384,
        rsaPkcs1Sha1;
