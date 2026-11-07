//! Cryptographic hash functions.
//!
//! aws-lc-rs's SHA-224 is not offered: rind lacks it. Nor is
//! `Digest::import_less_safe`: rind signs and verifies only digests it
//! computed.

use core::fmt;

/// A hash function, chosen by one of this module's constants.
pub struct Algorithm {
    /// The length of a digest, in bytes.
    pub output_len: usize,

    /// The length of the hash's internal state, in bytes, which aws-lc-rs
    /// keeps only for ring compatibility.
    #[deprecated(
        since = "1.1.0",
        note = "Unused by aws-lc-rs; retained for ring compatibility. Use `output_len()` to size an HMAC key."
    )]
    pub chaining_len: usize,

    /// The length of a block the hash compresses at a time, in bytes.
    pub block_len: usize,

    pub(crate) id: AlgorithmId,
}

#[allow(non_camel_case_types)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AlgorithmId {
    SHA1,
    SHA256,
    SHA384,
    SHA512,
    SHA512_256,
    SHA3_256,
    SHA3_384,
    SHA3_512,
}

impl Algorithm {
    /// The length of a digest, in bytes.
    pub fn output_len(&self) -> usize {
        self.output_len
    }

    /// The length of the hash's internal state, in bytes.
    #[deprecated(
        since = "1.1.0",
        note = "Unused by aws-lc-rs; retained for ring compatibility. Use `output_len()` to size an HMAC key."
    )]
    pub fn chaining_len(&self) -> usize {
        #[allow(deprecated)]
        self.chaining_len
    }

    /// The length of a block the hash compresses at a time, in bytes.
    pub fn block_len(&self) -> usize {
        self.block_len
    }

    pub(crate) fn rind(&self) -> &'static rind::digest::Algorithm {
        match self.id {
            AlgorithmId::SHA1 => &rind::digest::legacy::SHA1,
            AlgorithmId::SHA256 => &rind::digest::SHA256,
            AlgorithmId::SHA384 => &rind::digest::SHA384,
            AlgorithmId::SHA512 => &rind::digest::SHA512,
            AlgorithmId::SHA512_256 => &rind::digest::SHA512_256,
            AlgorithmId::SHA3_256 => &rind::digest::SHA3_256,
            AlgorithmId::SHA3_384 => &rind::digest::SHA3_384,
            AlgorithmId::SHA3_512 => &rind::digest::SHA3_512,
        }
    }
}

impl fmt::Debug for Algorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.id.fmt(f)
    }
}

impl PartialEq for Algorithm {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}

impl Eq for Algorithm {}

macro_rules! algorithm {
    ($name:ident, $id:ident, $output_len:expr, $chaining_len:expr, $block_len:expr, $doc:expr) => {
        #[doc = $doc]
        #[allow(deprecated)]
        pub const $name: Algorithm = Algorithm {
            output_len: $output_len,
            chaining_len: $chaining_len,
            block_len: $block_len,
            id: AlgorithmId::$id,
        };
    };
}

algorithm!(
    SHA1_FOR_LEGACY_USE_ONLY,
    SHA1,
    SHA1_OUTPUT_LEN,
    SHA1_OUTPUT_LEN,
    64,
    "SHA-1, for legacy protocols only: its collision resistance is broken."
);
algorithm!(
    SHA256,
    SHA256,
    SHA256_OUTPUT_LEN,
    SHA256_OUTPUT_LEN,
    64,
    "SHA-256."
);
algorithm!(
    SHA384,
    SHA384,
    SHA384_OUTPUT_LEN,
    SHA512_OUTPUT_LEN,
    128,
    "SHA-384."
);
algorithm!(
    SHA512,
    SHA512,
    SHA512_OUTPUT_LEN,
    SHA512_OUTPUT_LEN,
    128,
    "SHA-512."
);
algorithm!(
    SHA512_256,
    SHA512_256,
    SHA512_256_OUTPUT_LEN,
    SHA512_OUTPUT_LEN,
    128,
    "SHA-512/256."
);
algorithm!(SHA3_256, SHA3_256, 32, 32, 136, "SHA3-256.");
algorithm!(SHA3_384, SHA3_384, 48, 48, 104, "SHA3-384.");
algorithm!(SHA3_512, SHA3_512, 64, 64, 72, "SHA3-512.");

/// The largest block length of any algorithm, in bytes.
pub const MAX_BLOCK_LEN: usize = 128;

/// The largest digest length of any algorithm, in bytes.
pub const MAX_OUTPUT_LEN: usize = 64;

/// The largest internal state of any algorithm, in bytes.
pub const MAX_CHAINING_LEN: usize = MAX_OUTPUT_LEN;

/// The length of a SHA-1 digest, in bytes.
pub const SHA1_OUTPUT_LEN: usize = 20;

/// The length of a SHA-256 digest, in bytes.
pub const SHA256_OUTPUT_LEN: usize = 32;

/// The length of a SHA-384 digest, in bytes.
pub const SHA384_OUTPUT_LEN: usize = 48;

/// The length of a SHA-512 digest, in bytes.
pub const SHA512_OUTPUT_LEN: usize = 64;

/// The length of a SHA-512/256 digest, in bytes.
pub const SHA512_256_OUTPUT_LEN: usize = 32;

/// Hashes `data` in one go.
pub fn digest(algorithm: &'static Algorithm, data: &[u8]) -> Digest {
    let mut ctx = Context::new(algorithm);
    ctx.update(data);
    ctx.finish()
}

/// An in-progress hash computation; a clone forks it.
#[derive(Clone)]
pub struct Context {
    inner: rind::digest::Context,
    algorithm: &'static Algorithm,
}

impl Context {
    /// Starts hashing with `algorithm`.
    pub fn new(algorithm: &'static Algorithm) -> Self {
        Self {
            inner: rind::digest::Context::new(algorithm.rind()),
            algorithm,
        }
    }

    /// Adds `data` to the message.
    pub fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    /// Returns the digest of the message.
    pub fn finish(mut self) -> Digest {
        Digest {
            inner: self.inner.finish(),
            algorithm: self.algorithm,
        }
    }

    /// The algorithm this context hashes with.
    pub fn algorithm(&self) -> &'static Algorithm {
        self.algorithm
    }
}

/// The output of a hash function.
#[derive(Clone, Copy)]
pub struct Digest {
    inner: rind::digest::Digest,
    algorithm: &'static Algorithm,
}

impl Digest {
    /// The algorithm that made this digest.
    pub fn algorithm(&self) -> &'static Algorithm {
        self.algorithm
    }

    pub(crate) fn rind(&self) -> &rind::digest::Digest {
        &self.inner
    }
}

impl AsRef<[u8]> for Digest {
    fn as_ref(&self) -> &[u8] {
        self.inner.as_ref()
    }
}

impl fmt::Debug for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}:", self.algorithm)?;
        crate::write_hex(f, self.as_ref())
    }
}
