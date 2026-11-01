// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

//! ML-KEM-768 as standardised by FIPS-203: rind's own on CPUs with AVX2,
//! over s2n-bignum's AVX2 routines, and libcrux's portable Rust on the rest,
//! chosen once per process.
//!
//! Without AVX2, libcrux measured faster than rind's FIPS 203 code over
//! portable ports of mlkem-native's routines: its Keccak is the cheaper, and
//! Keccak dominates both.

use crate::error::Error;
use crate::low;

#[path = "../mlkem768.rs"]
mod avx2;
#[path = "../generic/mlkem768.rs"]
mod portable;

#[cfg(test)]
pub(crate) use avx2::Message;
pub(crate) use avx2::{Ciphertext, SharedSecret};

/// An ML-KEM-768 decapsulation key.
//
// `repr(u8)` puts `Avx2` at tag zero, and its key is plain bytes, so
// all-bits-zero is a valid value and `Drop` can wipe the tag and any unused
// tail along with the key. The variants differ in size, and boxing would
// allocate for every key to save space only on CPUs without AVX2.
#[allow(clippy::large_enum_variant)]
#[repr(u8)]
pub(crate) enum DecapKey {
    Avx2(avx2::DecapKey),
    Portable(portable::DecapKey),
}

impl DecapKey {
    /// Generate a random [`DecapKey`] (which contains the corresponding [`EncapKey`]).
    ///
    /// This fails only if random material generation fails.
    pub(crate) fn generate() -> Result<Self, Error> {
        Ok(match low::HaveAvx2::check() {
            Some(_) => Self::Avx2(avx2::DecapKey::generate()?),
            None => Self::Portable(portable::DecapKey::generate()?),
        })
    }

    /// Decapsulate ciphertext `c`, yielding a [`SharedSecret`].
    pub(crate) fn decaps(&self, c: &Ciphertext) -> SharedSecret {
        match self {
            Self::Avx2(key) => key.decaps(c),
            Self::Portable(key) => {
                SharedSecret(*key.decaps(&portable::Ciphertext::from(*c.as_ref())).as_ref())
            }
        }
    }

    /// Return the corresponding [`EncapKey`].
    pub(crate) fn encapsulation_key(&self) -> EncapKey {
        match self {
            Self::Avx2(key) => EncapKey::Avx2(key.encapsulation_key()),
            Self::Portable(key) => EncapKey::Portable(key.encapsulation_key()),
        }
    }

    /// Encode the key as bytes.
    ///
    /// This is used for testing.
    #[cfg(test)]
    pub(crate) fn as_bytes(&self) -> [u8; 2400] {
        match self {
            Self::Avx2(key) => key.as_bytes(),
            Self::Portable(key) => key.as_bytes(),
        }
    }

    #[cfg(test)]
    pub(crate) fn keygen_internal(seed: &[u8; 64]) -> Self {
        match low::HaveAvx2::check() {
            Some(_) => Self::Avx2(avx2::DecapKey::keygen_internal(seed)),
            None => Self::Portable(portable::DecapKey::keygen_internal(seed)),
        }
    }
}

impl Drop for DecapKey {
    fn drop(&mut self) {
        // Wipes the discriminant and the space a smaller variant leaves unused,
        // not only the variant's own key.
        low::zeroise_value(self);
    }
}

impl low::Zeroable for DecapKey {}

/// An ML-KEM-768 encapsulation key.
#[allow(clippy::large_enum_variant)]
#[derive(Clone)]
pub(crate) enum EncapKey {
    Avx2(avx2::EncapKey),
    Portable(portable::EncapKey),
}

impl EncapKey {
    /// Create a new [`EncapKey`] from bytes.
    pub(crate) fn from_bytes(input: &[u8; 1184]) -> Result<Self, Error> {
        Ok(match low::HaveAvx2::check() {
            Some(_) => Self::Avx2(avx2::EncapKey::from_bytes(input)?),
            None => Self::Portable(portable::EncapKey::from_bytes(input)?),
        })
    }

    /// Encapsulate a random shared secret, returning the shared secret and a ciphertext.
    ///
    /// The ciphertext can be returned to the holder of the [`DecapKey`] who can then
    /// derive the same [`SharedSecret`].
    pub(crate) fn encaps(&self) -> Result<(SharedSecret, Ciphertext), Error> {
        match self {
            Self::Avx2(key) => key.encaps(),
            Self::Portable(key) => key.encaps().map(from_portable),
        }
    }

    /// Encode the [`EncapKey`] as bytes.
    pub(crate) fn as_bytes(&self) -> [u8; 1184] {
        match self {
            Self::Avx2(key) => key.as_bytes(),
            Self::Portable(key) => key.as_bytes(),
        }
    }

    #[cfg(test)]
    pub(crate) fn encaps_internal(&self, m: Message) -> (SharedSecret, Ciphertext) {
        match self {
            Self::Avx2(key) => key.encaps_internal(m),
            Self::Portable(key) => from_portable(key.encaps_internal(portable::Message(m.0))),
        }
    }
}

fn from_portable((k, c): (portable::SharedSecret, portable::Ciphertext)) -> (SharedSecret, Ciphertext) {
    (SharedSecret(*k.as_ref()), Ciphertext::from(*c.as_ref()))
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    // AVX2, where present, hides libcrux from every other test, so the two
    // are checked against each other directly: keys, encapsulation, and
    // decapsulation of a valid and a rejected ciphertext.
    #[test]
    fn portable_matches_avx2() {
        if low::HaveAvx2::check().is_none() {
            return;
        }
        for i in 0..4u8 {
            let seed = core::array::from_fn(|j| (j as u8).wrapping_mul(31) ^ i);
            let want = avx2::DecapKey::keygen_internal(&seed);
            let got = portable::DecapKey::keygen_internal(&seed);
            assert_eq!(got.as_bytes(), want.as_bytes(), "decapsulation key {i}");
            let (want_ek, got_ek) = (want.encapsulation_key(), got.encapsulation_key());
            assert_eq!(got_ek.as_bytes(), want_ek.as_bytes(), "encapsulation key {i}");

            let m = [i ^ 0x5a; 32];
            let (want_k, want_c) = want_ek.encaps_internal(Message(m));
            let (got_k, got_c) = got_ek.encaps_internal(portable::Message(m));
            assert_eq!(got_k.as_ref(), want_k.as_ref(), "encapsulated secret {i}");
            assert_eq!(got_c.as_ref(), want_c.as_ref(), "ciphertext {i}");

            for flip in [false, true] {
                let mut c = *want_c.as_ref();
                c[usize::from(i) * 100] ^= u8::from(flip);
                let want_k = want.decaps(&Ciphertext::from(c));
                let got_k = got.decaps(&portable::Ciphertext::from(c));
                assert_eq!(got_k.as_ref(), want_k.as_ref(), "decapsulated {i}, flipped {flip}");
            }
        }
    }
}
