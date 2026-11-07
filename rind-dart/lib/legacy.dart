// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

/// Algorithms only legacy protocols and formats should use: SHA-1 and MD5,
/// and RSA moduli below 2048 bits for verification.
library;

export 'src/bindings.dart'
    show
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
