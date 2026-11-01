// Written for Graviola by Joe Birr-Pixton, 2024.
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0
#![doc = include_str!("../README.md")]
#![allow(
    clippy::new_without_default,
    clippy::result_unit_err,
    clippy::too_many_arguments
)]
#![forbid(unused_must_use)]
#![warn(
    clippy::alloc_instead_of_core,
    clippy::let_underscore_must_use,
    clippy::ptr_as_ptr,
    clippy::ptr_cast_constness,
    clippy::std_instead_of_core,
    clippy::undocumented_unsafe_blocks,
    clippy::upper_case_acronyms,
    clippy::use_self,
    elided_lifetimes_in_paths,
    missing_docs,
    trivial_numeric_casts,
    unreachable_pub,
    unused_import_braces,
    unused_extern_crates,
    unused_qualifications
)]
#![cfg_attr(coverage_nightly, feature(coverage_attribute))]

/// Low level operations.
///
/// `unsafe` is allowed only here.
///
/// Examples: elliptic curve field operations,
/// bignum arithmetic.
mod low;

/// Mid-level APIs.
///
/// Examples: elliptic curve group operations.
mod mid;

/// High-level APIs.
///
/// Examples: key encodings, high-level constructions.
mod high;

/// Errors.  Common to all layers.
mod error;

/// Test infrastructure.
#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod test;

// vvv Public API
pub use error::{Error, KeyRejected};

/// Non-API documentation
#[cfg(doc)]
pub mod doc {
    pub use super::low::inline_assembly_safety;
}

/// Ephemeral key agreement: X25519, and ECDH on P-256, P-384, and P-521.
///
/// ```
/// use rind::agreement::*;
///
/// let alice = PrivateKey::generate(&X25519).unwrap();
/// let bob = PrivateKey::generate(&X25519).unwrap();
///
/// let alice_pub = alice.public_key();
/// let bob_pub = bob.public_key();
///
/// let alice_secret = alice
///     .agree(bob_pub.as_ref())
///     .expect("bob gave an invalid public key");
/// let bob_secret = bob
///     .agree(alice_pub.as_ref())
///     .expect("alice gave an invalid public key");
///
/// assert_eq!(alice_secret.as_ref(), bob_secret.as_ref());
/// ```
pub mod agreement {
    pub use crate::high::agreement::{
        Algorithm, ECDH_P256, ECDH_P384, ECDH_P521, PrivateKey, PublicKey, SharedSecret, X25519,
    };
}

/// Key encapsulation: ML-KEM-768.
///
/// ```
/// # fn main() -> Result<(), rind::Error> {
/// use rind::kem::*;
///
/// // The recipient generates a key pair, and sends the encapsulation key to
/// // the sender.
/// let decapsulation_key = DecapsulationKey::generate(&ML_KEM_768)?;
/// let encapsulation_key = decapsulation_key.public_key();
///
/// // The sender parses the encapsulation key, encapsulates a fresh secret,
/// // and sends the ciphertext back to the recipient.
/// let peer_key = EncapsulationKey::new(&ML_KEM_768, encapsulation_key.as_ref())?;
/// let (ciphertext, sender_secret) = peer_key.encapsulate()?;
///
/// // The recipient decapsulates the ciphertext, recovering the same secret.
/// let recipient_secret = decapsulation_key.decapsulate(ciphertext.as_ref())?;
///
/// assert_eq!(sender_secret.as_ref(), recipient_secret.as_ref());
/// # Ok(())
/// # }
/// ```
pub mod kem {
    pub use crate::high::kem::{
        Algorithm, Ciphertext, DecapsulationKey, EncapsulationKey, ML_KEM_768, SharedSecret,
    };
}

/// Public key signatures: ECDSA on P-256, P-384, and P-521, RSA, and Ed25519.
///
/// A key pair signs with a [`signature::sign`] algorithm, and a peer's
/// public key is parsed for a [`signature::verify`] algorithm:
///
/// ```
/// # fn main() -> Result<(), rind::Error> {
/// use rind::signature::{EcdsaKeyPair, PublicKey, sign, verify};
///
/// let key_pair = EcdsaKeyPair::generate(&sign::ECDSA_P256_SHA256_ASN1)?;
/// let signature = key_pair.sign(b"hello")?;
///
/// let encoded = key_pair.public_key();
/// let public_key = PublicKey::new(&verify::ECDSA_P256_SHA256_ASN1, encoded.as_ref())?;
/// public_key.verify(b"hello", signature.as_ref())?;
/// # Ok(())
/// # }
/// ```
pub mod signature {
    pub use crate::high::signature::{
        EcdsaKeyPair, EcdsaScalar, EcdsaSigningAlgorithm, Ed25519KeyPair, Ed25519Seed, Pkcs8,
        PublicKey, RsaKeyPair, RsaKeySize, RsaPublicKeyComponents, RsaSigningAlgorithm,
        RsaVerificationAlgorithm, Signature, Spki, VerificationAlgorithm,
    };

    /// Algorithms a key pair signs with.
    ///
    /// Each signs as the [`verify`] algorithm of the same name verifies.
    pub mod sign {
        pub use crate::high::signature::sign::{
            ECDSA_P256_SHA256_ASN1, ECDSA_P256_SHA256_FIXED, ECDSA_P384_SHA384_ASN1,
            ECDSA_P384_SHA384_FIXED, ECDSA_P521_SHA512_ASN1, ECDSA_P521_SHA512_FIXED,
            RSA_PKCS1_SHA256, RSA_PKCS1_SHA384, RSA_PKCS1_SHA512, RSA_PSS_SHA256, RSA_PSS_SHA384,
            RSA_PSS_SHA512,
        };
    }

    /// Algorithms a public key verifies with.
    ///
    /// RSA algorithms accept moduli of 2048 to 8192 bits.
    pub mod verify {
        pub use crate::high::signature::verify::{
            ECDSA_P256_SHA256_ASN1, ECDSA_P256_SHA256_FIXED, ECDSA_P256_SHA384_ASN1,
            ECDSA_P256_SHA512_ASN1, ECDSA_P384_SHA256_ASN1, ECDSA_P384_SHA384_ASN1,
            ECDSA_P384_SHA384_FIXED, ECDSA_P384_SHA512_ASN1, ECDSA_P521_SHA256_ASN1,
            ECDSA_P521_SHA384_ASN1, ECDSA_P521_SHA512_ASN1, ECDSA_P521_SHA512_FIXED, ED25519,
            RSA_PKCS1_SHA256, RSA_PKCS1_SHA384, RSA_PKCS1_SHA512, RSA_PSS_SHA256, RSA_PSS_SHA384,
            RSA_PSS_SHA512,
        };

        /// RSA algorithms with another modulus floor, or SHA-1, for old keys
        /// and signatures.
        pub mod legacy {
            pub use crate::high::signature::verify::legacy::{
                RSA_PKCS1_1024_SHA1, RSA_PKCS1_1024_SHA256, RSA_PKCS1_1024_SHA512,
                RSA_PKCS1_3072_SHA384, RSA_PKCS1_SHA1,
            };
        }
    }
}

/// Cryptographic hash functions.
///
/// ```
/// use rind::digest;
///
/// let mut ctx = digest::Context::new(&digest::SHA256);
/// ctx.update(b"hello, ");
/// ctx.update(b"world");
/// assert_eq!(
///     ctx.finish().as_ref(),
///     digest::digest(&digest::SHA256, b"hello, world").as_ref(),
/// );
/// ```
pub mod digest {
    pub use super::high::digest::{
        Algorithm, Context, Digest, SHA256, SHA384, SHA512, SHA512_256, digest,
    };

    /// Hash functions only legacy protocols should use.
    pub mod legacy {
        pub use crate::high::digest::SHA1;
    }
}

/// Message authentication with HMAC.
///
/// A [`hmac::Key`] precomputes its keyed hash states once; each message then
/// signs through a [`hmac::Context`] started from it, or the one-shot
/// [`hmac::sign`] and [`hmac::verify`].
///
/// ```
/// use rind::hmac;
///
/// let key = hmac::Key::new(&hmac::HMAC_SHA256, b"secret");
///
/// let mut ctx = hmac::Context::with_key(&key);
/// ctx.update(b"hello, ");
/// ctx.update(b"world");
/// let tag = ctx.sign();
///
/// hmac::verify(&key, b"hello, world", tag.as_ref()).unwrap();
/// ```
pub mod hmac {
    pub use super::high::hmac::{
        Algorithm, Context, HMAC_SHA256, HMAC_SHA384, HMAC_SHA512, Key, Tag, sign, verify,
    };

    /// HMAC algorithms only legacy protocols should use.
    pub mod legacy {
        pub use crate::high::hmac::HMAC_SHA1;
    }
}

/// Constant-time comparison, for checking a secret such as a MAC or token.
///
/// ```
/// use rind::constant_time;
///
/// constant_time::verify(b"expected", b"expected").unwrap();
/// assert_eq!(constant_time::verify(b"expected", b"presented"), Err(rind::Error::WrongLength));
/// assert_eq!(constant_time::verify(b"expected", b"Expected"), Err(rind::Error::NotEqual));
/// ```
pub mod constant_time {
    pub use crate::high::constant_time::verify;
}

/// Key derivation with HKDF.
///
/// A [`hkdf::Salt`] extracts a [`hkdf::Prk`] from a secret, which then expands
/// into any number of keys, each exactly as long as what it becomes.
///
/// ```
/// use rind::{aead, hkdf, hmac};
///
/// let prk = hkdf::Salt::new(&hkdf::HKDF_SHA256, b"salt").extract(b"input key material");
///
/// let aead_key = aead::Key::from(prk.expand(&[b"aead"], &aead::AES_256_GCM));
/// let hmac_key = hmac::Key::from(prk.expand(&[b"hmac"], &hmac::HMAC_SHA256));
///
/// let info: [&[u8]; 2] = [b"label", b"context"];
/// let mut bytes = [0u8; 16];
/// prk.expand(&info, bytes.len()).fill(&mut bytes).unwrap();
/// ```
pub mod hkdf {
    pub use super::high::hkdf::{
        Algorithm, HKDF_SHA256, HKDF_SHA384, HKDF_SHA512, KeyType, Okm, Prk, Salt,
    };

    /// HKDF algorithms only legacy protocols should use.
    pub mod legacy {
        pub use crate::high::hkdf::HKDF_SHA1;
    }
}

/// Password-based key derivation with PBKDF2.
///
/// A [`pbkdf2::Secret`] keys HMAC with a password once, then derives a key
/// for a salt and iteration count, or checks one derived before. This
/// example takes the iteration count OWASP suggests for SHA-256, so it is
/// not run as a test.
///
/// ```no_run
/// use std::num::NonZeroU32;
/// use rind::pbkdf2;
///
/// let iterations = NonZeroU32::new(600_000).unwrap();
/// let secret = pbkdf2::Secret::new(&pbkdf2::PBKDF2_HMAC_SHA256, b"password");
///
/// let mut stored = [0u8; 32];
/// secret.derive(iterations, b"per-user salt", &mut stored).unwrap();
///
/// secret.verify(iterations, b"per-user salt", &stored).unwrap();
/// ```
pub mod pbkdf2 {
    pub use super::high::pbkdf2::{
        Algorithm, PBKDF2_HMAC_SHA256, PBKDF2_HMAC_SHA384, PBKDF2_HMAC_SHA512, Secret,
    };

    /// PBKDF2 algorithms only legacy formats should use.
    pub mod legacy {
        pub use crate::high::pbkdf2::PBKDF2_HMAC_SHA1;
    }
}

/// Authenticated encryption.
///
/// An [`aead::Key`] is built from an algorithm constant and key bytes, and
/// seals with the caller's nonces, which must never repeat under one key. An
/// [`aead::RandomizedNonceKey`] picks its own.
///
/// ```
/// use rind::aead::*;
///
/// let key = Key::new(&AES_128_GCM, &[0x42; 16]).unwrap();
///
/// let mut in_out = b"hello".to_vec();
/// let nonce = || Nonce::assume_unique_for_key([0; 12]);
/// key.seal_in_place_append_tag(nonce(), b"header", &mut in_out)
///     .unwrap();
///
/// let plaintext = key.open_in_place(nonce(), b"header", &mut in_out).unwrap();
/// assert_eq!(plaintext, b"hello");
/// ```
pub mod aead;

/// Unauthenticated ciphers, for protocols that specify one alongside their own integrity protection.
///
/// Prefer [`aead`] unless a protocol requires one of these.
pub mod cipher;

/// CPU support.
///
/// Every operation panics on a CPU missing a feature rind requires. Check at
/// startup to refuse cleanly instead:
///
/// ```
/// if let Err(missing) = rind::cpu::check() {
///     eprintln!("{missing}");
///     std::process::exit(1);
/// }
/// ```
pub mod cpu {
    pub use crate::low::cpu::{MissingFeature, check, has_aes_hardware};
}

/// Random bytes from the system's secure random source.
///
/// No rind API takes a random source, so [`rand::fill`] is all a caller
/// needs.
///
/// ```
/// let mut nonce = [0u8; 16];
/// rind::rand::fill(&mut nonce).unwrap();
/// ```
pub mod rand {
    /// Fills the entirety of `out` with random bytes.
    pub fn fill(out: &mut [u8]) -> Result<(), super::Error> {
        use crate::mid::rng::{RandomSource, SystemRandom};
        SystemRandom.fill(out)
    }
}
