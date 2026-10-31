// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

//! PBKDF2 (Password-Based Key Derivation Function 2), following aws-lc-rs's `pbkdf2`.
//!
//! PBKDF2 is standardized in [RFC 8018](https://datatracker.ietf.org/doc/html/rfc8018#section-5.2).

use core::num::NonZeroU32;

use super::hash::Hash;
use super::hmac::{self, Hmac, Keyed};
use crate::Error;
use crate::low::{ct, ct_equal};

/// A PBKDF2 algorithm, chosen by one of this module's constants.
#[derive(Clone, Copy, Debug)]
pub struct Algorithm(hmac::Algorithm);

/// PBKDF2-HMAC-SHA1, for legacy formats only.
///
/// PBKDF2 does not rely on SHA-1's broken collision resistance, and formats
/// such as WPA2 and older PKCS#12 files still require it.
pub static PBKDF2_HMAC_SHA1: Algorithm = Algorithm(hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY);

/// PBKDF2-HMAC-SHA256.
pub static PBKDF2_HMAC_SHA256: Algorithm = Algorithm(hmac::HMAC_SHA256);

/// PBKDF2-HMAC-SHA384.
pub static PBKDF2_HMAC_SHA384: Algorithm = Algorithm(hmac::HMAC_SHA384);

/// PBKDF2-HMAC-SHA512.
pub static PBKDF2_HMAC_SHA512: Algorithm = Algorithm(hmac::HMAC_SHA512);

/// A secret, such as a password, keyed once for every salt it derives with; wiped on drop.
///
/// aws-lc-rs's `derive` and `verify` instead take the algorithm, iteration
/// count, salt, secret, and output as five arguments; rind keeps calls to
/// three, as [`crate::hkdf::Salt`] does.
pub struct Secret(hmac::Key);

impl Secret {
    /// Keys `algorithm` with `secret`, which may be any length.
    pub fn new(algorithm: Algorithm, secret: &[u8]) -> Self {
        Self(hmac::Key::new(algorithm.0, secret))
    }

    /// Fills `out` with the key derived from `salt` over `iterations` rounds.
    ///
    /// Fails with [`Error::WrongLength`], leaving `out` unchanged, if `out`
    /// is empty or longer than PBKDF2 allows, rather than panicking as
    /// aws-lc-rs does.
    pub fn derive(&self, iterations: NonZeroU32, salt: &[u8], out: &mut [u8]) -> Result<(), Error> {
        self.check_len(out.len())?;
        self.blocks(iterations, salt, out.len(), |offset, block| {
            out[offset..offset + block.len()].copy_from_slice(block);
        });
        Ok(())
    }

    /// Checks in constant time that `previously_derived` is what [`Secret::derive`] makes for `salt` and `iterations`.
    ///
    /// The key derived is as long as `previously_derived`. Fails with
    /// [`Error::WrongLength`] if that is empty or longer than PBKDF2 allows,
    /// and with [`Error::BadSignature`] if the keys differ.
    pub fn verify(
        &self,
        iterations: NonZeroU32,
        salt: &[u8],
        previously_derived: &[u8],
    ) -> Result<(), Error> {
        self.check_len(previously_derived.len())?;
        // Block by block, so verifying needs no buffer as long as the key.
        let mut equal = true;
        self.blocks(
            iterations,
            salt,
            previously_derived.len(),
            |offset, block| {
                equal &= ct_equal(block, &previously_derived[offset..offset + block.len()]);
            },
        );
        match ct::into_public(equal) {
            true => Ok(()),
            false => Err(Error::BadSignature),
        }
    }

    // RFC 8018 numbers blocks with a 32-bit counter starting at 1.
    fn check_len(&self, len: usize) -> Result<(), Error> {
        let blocks = len.div_ceil(self.0.algorithm().tag_len());
        match blocks == 0 || blocks > u32::MAX as usize {
            true => Err(Error::WrongLength),
            false => Ok(()),
        }
    }

    // Computes each block of a `len`-byte key in turn, handing `sink` its
    // offset and the bytes of it that fall within `len`.
    fn blocks(
        &self,
        iterations: NonZeroU32,
        salt: &[u8],
        len: usize,
        sink: impl FnMut(usize, &[u8]),
    ) {
        fn blocks<H: Hash>(
            hmac: &Hmac<H>,
            iterations: NonZeroU32,
            salt: &[u8],
            len: usize,
            mut sink: impl FnMut(usize, &[u8]),
        ) {
            let mut salted = hmac.clone();
            salted.update(salt);

            let hash_len = H::zeroed_output().as_ref().len();
            for (index, offset) in (1..=u32::MAX).zip((0..len).step_by(hash_len)) {
                let mut ctx = salted.clone();
                ctx.update(index.to_be_bytes());
                let mut u = ctx.finish();
                let mut t = u.clone();
                for _ in 1..iterations.get() {
                    u = hmac.sign_block(u.as_ref());
                    for (t, u) in t.as_mut().iter_mut().zip(u.as_ref()) {
                        *t ^= u;
                    }
                }
                sink(offset, &t.as_ref()[..hash_len.min(len - offset)]);
            }
        }

        match &self.0.0 {
            Keyed::Sha1(hmac) => blocks(hmac, iterations, salt, len, sink),
            Keyed::Sha256(hmac) => blocks(hmac, iterations, salt, len, sink),
            Keyed::Sha384(hmac) => blocks(hmac, iterations, salt, len, sink),
            Keyed::Sha512(hmac) => blocks(hmac, iterations, salt, len, sink),
        }
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    const ONE: NonZeroU32 = NonZeroU32::MIN;

    #[test]
    fn lengths() {
        let secret = Secret::new(PBKDF2_HMAC_SHA256, b"password");
        assert_eq!(
            secret.derive(ONE, b"salt", &mut []),
            Err(Error::WrongLength)
        );
        assert_eq!(secret.verify(ONE, b"salt", &[]), Err(Error::WrongLength));
    }

    #[test]
    fn verify_checks_every_byte() {
        // Two whole SHA-256 blocks and a partial third, so a flip in any
        // block, including the partial one, must be caught.
        let iterations = NonZeroU32::new(3).unwrap();
        let secret = Secret::new(PBKDF2_HMAC_SHA256, b"password");
        let mut key = [0u8; 70];
        secret.derive(iterations, b"salt", &mut key).unwrap();
        assert_eq!(secret.verify(iterations, b"salt", &key), Ok(()));

        for i in 0..key.len() {
            let mut wrong = key;
            wrong[i] ^= 1;
            assert_eq!(
                secret.verify(iterations, b"salt", &wrong),
                Err(Error::BadSignature)
            );
        }
        let other = NonZeroU32::new(4).unwrap();
        assert_eq!(
            secret.verify(other, b"salt", &key),
            Err(Error::BadSignature)
        );
        assert_eq!(
            secret.verify(iterations, b"pepper", &key),
            Err(Error::BadSignature)
        );

        // The stored key's length is the derived one's, so its prefix verifies too.
        assert_eq!(secret.verify(iterations, b"salt", &key[..33]), Ok(()));
    }

    #[test]
    fn secret_password() {
        // Under `admin/ctgrind`, nothing may branch on or index by the
        // password or anything derived from it, until the derived key or
        // verify's answer is declassified. Passwords longer than a block are
        // hashed first.
        let iterations = NonZeroU32::new(3).unwrap();
        for algorithm in [
            PBKDF2_HMAC_SHA1,
            PBKDF2_HMAC_SHA256,
            PBKDF2_HMAC_SHA384,
            PBKDF2_HMAC_SHA512,
        ] {
            for password_len in [16, 200] {
                let password = vec![0x5a; password_len];
                let mut wanted = [0u8; 100];
                Secret::new(algorithm, &password)
                    .derive(iterations, b"salt", &mut wanted)
                    .unwrap();

                ct::secret_slice(&password);
                let secret = Secret::new(algorithm, &password);
                let mut got = [0u8; 100];
                secret.derive(iterations, b"salt", &mut got).unwrap();
                ct::public_slice(&got);
                assert_eq!(got, wanted);
                assert_eq!(secret.verify(iterations, b"salt", &wanted), Ok(()));
            }
        }
    }
}
