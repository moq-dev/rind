//! <h1 align="center">rind-rustls</h1>
//! <img width="40%" align="right" src="https://raw.githubusercontent.com/moq-dev/rind/main/admin/picture.png">
//!
//! This crate provides an integration between [rustls](https://github.com/rustls/rustls) and [rind](https://github.com/moq-dev/rind/), a fork of [Graviola](https://github.com/ctz/graviola/).
//!
//! Use it like:
//!
//! ```rust
//! # fn main() -> Result<(), rind::cpu::MissingFeature> {
//! rind_rustls::default_provider()?.install_default().unwrap();
//! # Ok(())
//! # }
//! ```
//!
//! And then use rustls as normal.
//!
//! rind panics on a CPU missing a feature it requires, so [`default_provider`]
//! and [`Ticketer::new`] check first and return an error instead. To build a
//! provider from this crate's statics, call [`rind::cpu::check`] first.

use rustls::SupportedCipherSuite;
use rustls::crypto::{CryptoProvider, SupportedKxGroup};

mod aead;
mod hash;
mod hmac;
mod quic;
mod sign;
mod verify;

/// Every cipher suite this crate supports.
///
/// Call [`rind::cpu::check`] before using these directly.
pub mod cipher_suite;

/// Every key exchange group this crate supports.
///
/// Call [`rind::cpu::check`] before using these directly.
pub mod kx_group;

mod ticketer;
pub use ticketer::Ticketer;

/// Returns a rustls [`CryptoProvider`] using cryptography from rind, or the
/// CPU feature rind requires that this CPU lacks.
///
/// This provides the same algorithms as the rustls *ring*-based
/// provider, which are interoperable and safe defaults for modern TLS,
/// plus X25519MLKEM768.
/// It prefers ChaCha20-Poly1305 where rind runs AES without CPU instructions.
pub fn default_provider() -> Result<CryptoProvider, rind::cpu::MissingFeature> {
    rind::cpu::check()?;
    let cipher_suites = if rind::cpu::has_aes_hardware() {
        DEFAULT_CIPHER_SUITES
    } else {
        CHACHA20_FIRST
    };
    Ok(CryptoProvider {
        cipher_suites: cipher_suites.to_vec(),
        kx_groups: DEFAULT_KX_GROUPS.to_vec(),
        signature_verification_algorithms: verify::ALGORITHMS,
        secure_random: &RngProvider,
        key_provider: &sign::Provider,
    })
}

/// The cipher suites [`default_provider`] offers, in its order where rind runs
/// AES on CPU instructions; elsewhere it puts ChaCha20-Poly1305 first.
pub static DEFAULT_CIPHER_SUITES: &[SupportedCipherSuite] = ALL_CIPHER_SUITES;

/// Every cipher suite this crate supports, in preference order.
pub static ALL_CIPHER_SUITES: &[SupportedCipherSuite] = &[
    cipher_suite::TLS13_AES_128_GCM_SHA256,
    cipher_suite::TLS13_AES_256_GCM_SHA384,
    cipher_suite::TLS13_CHACHA20_POLY1305_SHA256,
    cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
    cipher_suite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
    cipher_suite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    cipher_suite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
    cipher_suite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
];

/// [`DEFAULT_CIPHER_SUITES`] with ChaCha20-Poly1305 first, which outruns AES
/// without AES instructions.
static CHACHA20_FIRST: &[SupportedCipherSuite] = &[
    cipher_suite::TLS13_CHACHA20_POLY1305_SHA256,
    cipher_suite::TLS13_AES_128_GCM_SHA256,
    cipher_suite::TLS13_AES_256_GCM_SHA384,
    cipher_suite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
    cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
    cipher_suite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
    cipher_suite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    cipher_suite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
];

/// The key exchange groups [`default_provider`] offers, in its order.
pub static DEFAULT_KX_GROUPS: &[&dyn SupportedKxGroup] = ALL_KX_GROUPS;

/// Every key exchange group this crate supports, in preference order.
pub static ALL_KX_GROUPS: &[&dyn SupportedKxGroup] = &[
    kx_group::X25519MLKEM768,
    kx_group::X25519,
    kx_group::SECP256R1,
    kx_group::SECP384R1,
];

#[derive(Debug)]
struct RngProvider;

impl rustls::crypto::SecureRandom for RngProvider {
    fn fill(&self, bytes: &mut [u8]) -> Result<(), rustls::crypto::GetRandomFailed> {
        rind::rand::fill(bytes).map_err(|_| rustls::crypto::GetRandomFailed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefers_chacha20_without_aes_hardware() {
        // CI runs armv7 on a CPU model with the crypto extension and one
        // without, and names which, so both orders are checked.
        match std::env::var_os("RIND_TEST_ARM_CRYPTO_EXT") {
            Some(expected) => assert_eq!(rind::cpu::has_aes_hardware(), expected == "1"),
            None if cfg!(not(target_arch = "arm")) => assert!(rind::cpu::has_aes_hardware()),
            None => {}
        }

        let expected = if rind::cpu::has_aes_hardware() {
            DEFAULT_CIPHER_SUITES
        } else {
            CHACHA20_FIRST
        };
        assert_eq!(default_provider().unwrap().cipher_suites, expected);
    }

    #[test]
    fn chacha20_first_reorders_every_suite() {
        let mut all = DEFAULT_CIPHER_SUITES.to_vec();
        let mut chacha20_first = CHACHA20_FIRST.to_vec();
        for suites in [&mut all, &mut chacha20_first] {
            suites.sort_by_key(|suite| u16::from(suite.suite()));
        }
        assert_eq!(all, chacha20_first);
    }
}
