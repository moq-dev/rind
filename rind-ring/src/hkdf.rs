//! Key derivation with HKDF (RFC 5869), over any [`hmac`] algorithm.

use crate::{error, hmac};

/// An HKDF algorithm, chosen by one of this module's statics.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Algorithm(hmac::Algorithm);

impl Algorithm {
    /// The HMAC algorithm this HKDF is built on.
    pub fn hmac_algorithm(&self) -> hmac::Algorithm {
        self.0
    }
}

/// HKDF-SHA1, for legacy protocols only.
pub static HKDF_SHA1_FOR_LEGACY_USE_ONLY: Algorithm =
    Algorithm(hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY);

/// HKDF-SHA256.
pub static HKDF_SHA256: Algorithm = Algorithm(hmac::HMAC_SHA256);

/// HKDF-SHA384.
pub static HKDF_SHA384: Algorithm = Algorithm(hmac::HMAC_SHA384);

/// HKDF-SHA512.
pub static HKDF_SHA512: Algorithm = Algorithm(hmac::HMAC_SHA512);

/// An HKDF key, such as a [`Salt`] or [`Prk`], is as long as the hash's output.
impl KeyType for Algorithm {
    fn len(&self) -> usize {
        self.0.digest_algorithm().output_len()
    }
}

/// A salt, keyed once and reused for every secret it extracts from.
#[derive(Debug)]
pub struct Salt(hmac::Key);

impl Salt {
    /// Keys `algorithm` with `value`; an empty `value` is RFC 5869's absent salt.
    pub fn new(algorithm: Algorithm, value: &[u8]) -> Self {
        Self(hmac::Key::new(algorithm.0, value))
    }

    /// Extracts a pseudorandom key from `secret` (HKDF-Extract).
    pub fn extract(&self, secret: &[u8]) -> Prk {
        let prk = hmac::sign(&self.0, secret);
        Prk(hmac::Key::new(self.0.algorithm(), prk.as_ref()))
    }

    /// The algorithm this salt was made for.
    pub fn algorithm(&self) -> Algorithm {
        Algorithm(self.0.algorithm())
    }
}

impl From<Okm<'_, Algorithm>> for Salt {
    fn from(okm: Okm<'_, Algorithm>) -> Self {
        Self(hmac::Key::from(okm.into_hmac()))
    }
}

/// The length of what an [`Okm`] becomes.
pub trait KeyType {
    /// The length, in bytes.
    fn len(&self) -> usize;
}

/// A pseudorandom key, from which [`Prk::expand`] derives any number of keys.
#[derive(Clone, Debug)]
pub struct Prk(hmac::Key);

impl Prk {
    /// Takes `value` as the pseudorandom key itself, skipping HKDF-Extract.
    pub fn new_less_safe(algorithm: Algorithm, value: &[u8]) -> Self {
        Self(hmac::Key::new(algorithm.0, value))
    }

    /// Derives key material for the concatenation of `info` (HKDF-Expand),
    /// failing if `len` is over 255 hash outputs.
    pub fn expand<'a, L: KeyType>(
        &'a self,
        info: &'a [&'a [u8]],
        len: L,
    ) -> Result<Okm<'a, L>, error::Unspecified> {
        let len_cached = len.len();
        if len_cached > 255 * self.hash_len() {
            return Err(error::Unspecified);
        }
        Ok(Okm {
            prk: self,
            info,
            len,
            len_cached,
        })
    }

    fn hash_len(&self) -> usize {
        self.0.algorithm().digest_algorithm().output_len()
    }

    // Fills `out`, which `expand` has checked is at most 255 hash outputs,
    // the most HKDF-Expand's one-byte block counter numbers.
    fn expand_into(&self, info: &[&[u8]], out: &mut [u8]) {
        let mut previous: Option<hmac::Tag> = None;
        for (counter, chunk) in (1..=255u8).zip(out.chunks_mut(self.hash_len())) {
            let mut ctx = hmac::Context::with_key(&self.0);
            if let Some(previous) = &previous {
                ctx.update(previous.as_ref());
            }
            for info in info {
                ctx.update(info);
            }
            ctx.update(&[counter]);
            let block = ctx.sign();
            chunk.copy_from_slice(&block.as_ref()[..chunk.len()]);
            previous = Some(block);
        }
    }
}

impl From<Okm<'_, Algorithm>> for Prk {
    fn from(okm: Okm<'_, Algorithm>) -> Self {
        Self(hmac::Key::from(okm.into_hmac()))
    }
}

/// Key material from [`Prk::expand`], as long as `L` says, for [`Okm::fill`] or a key's `From`.
#[derive(Debug)]
pub struct Okm<'a, L: KeyType> {
    prk: &'a Prk,
    info: &'a [&'a [u8]],
    len: L,
    len_cached: usize,
}

impl<L: KeyType> Okm<'_, L> {
    /// What this key material becomes.
    pub fn len(&self) -> &L {
        &self.len
    }

    /// Fills `out`, failing unless it is exactly the length `L` says.
    pub fn fill(self, out: &mut [u8]) -> Result<(), error::Unspecified> {
        if out.len() != self.len_cached {
            return Err(error::Unspecified);
        }
        self.prk.expand_into(self.info, out);
        Ok(())
    }

    /// Fills `out`, which the caller made exactly the length `L` says.
    pub(crate) fn fill_exact(self, out: &mut [u8]) {
        debug_assert_eq!(out.len(), self.len_cached);
        self.prk.expand_into(self.info, out);
    }
}

impl<'a> Okm<'a, Algorithm> {
    fn into_hmac(self) -> Okm<'a, hmac::Algorithm> {
        Okm {
            prk: self.prk,
            info: self.info,
            len: self.len.0,
            len_cached: self.len_cached,
        }
    }
}
