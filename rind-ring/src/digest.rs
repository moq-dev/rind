//! Cryptographic hash functions.

use core::fmt;

/// A hash function, chosen by one of this module's statics.
pub struct Algorithm {
    rind: &'static rind::digest::Algorithm,
    id: AlgorithmId,
    block_len: usize,
    chaining_len: usize,
}

#[allow(non_camel_case_types)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AlgorithmId {
    SHA1,
    SHA256,
    SHA384,
    SHA512,
    SHA512_256,
}

impl Algorithm {
    /// The length of a block the hash compresses at a time, in bytes.
    pub fn block_len(&self) -> usize {
        self.block_len
    }

    /// The length of the hash's internal state, in bytes.
    pub fn chaining_len(&self) -> usize {
        self.chaining_len
    }

    /// The length of a digest, in bytes.
    pub fn output_len(&self) -> usize {
        self.rind.output_len()
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

/// SHA-1, for legacy protocols only: its collision resistance is broken.
pub static SHA1_FOR_LEGACY_USE_ONLY: Algorithm = Algorithm {
    rind: &rind::digest::legacy::SHA1,
    id: AlgorithmId::SHA1,
    block_len: 64,
    chaining_len: SHA1_OUTPUT_LEN,
};

/// SHA-256.
pub static SHA256: Algorithm = Algorithm {
    rind: &rind::digest::SHA256,
    id: AlgorithmId::SHA256,
    block_len: 64,
    chaining_len: SHA256_OUTPUT_LEN,
};

/// SHA-384.
pub static SHA384: Algorithm = Algorithm {
    rind: &rind::digest::SHA384,
    id: AlgorithmId::SHA384,
    block_len: 128,
    chaining_len: SHA512_OUTPUT_LEN,
};

/// SHA-512.
pub static SHA512: Algorithm = Algorithm {
    rind: &rind::digest::SHA512,
    id: AlgorithmId::SHA512,
    block_len: 128,
    chaining_len: SHA512_OUTPUT_LEN,
};

/// SHA-512/256.
pub static SHA512_256: Algorithm = Algorithm {
    rind: &rind::digest::SHA512_256,
    id: AlgorithmId::SHA512_256,
    block_len: 128,
    chaining_len: SHA512_OUTPUT_LEN,
};

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
            inner: rind::digest::Context::new(algorithm.rind),
            algorithm,
        }
    }

    /// Adds `data` to the message.
    pub fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    /// Returns the digest of the message.
    pub fn finish(self) -> Digest {
        Digest::new(self.algorithm, self.inner.finish().as_ref())
    }

    /// The algorithm this context hashes with.
    pub fn algorithm(&self) -> &'static Algorithm {
        self.algorithm
    }
}

/// The output of a hash function.
#[derive(Clone, Copy)]
pub struct Digest {
    value: [u8; MAX_OUTPUT_LEN],
    algorithm: &'static Algorithm,
}

impl Digest {
    /// Copies `value`, which rind made `algorithm`'s output length.
    pub(crate) fn new(algorithm: &'static Algorithm, value: &[u8]) -> Self {
        let mut digest = Self {
            value: [0; MAX_OUTPUT_LEN],
            algorithm,
        };
        digest.value[..value.len()].copy_from_slice(value);
        digest
    }

    /// The algorithm that made this digest.
    pub fn algorithm(&self) -> &'static Algorithm {
        self.algorithm
    }
}

impl AsRef<[u8]> for Digest {
    fn as_ref(&self) -> &[u8] {
        &self.value[..self.algorithm.output_len()]
    }
}

impl fmt::Debug for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}:", self.algorithm)?;
        crate::write_hex(f, self.as_ref())
    }
}
