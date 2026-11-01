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
/// This offers the same cipher suites and key exchange groups as the rustls
/// aws-lc-rs provider's defaults, and verifies and signs the same signature
/// schemes, short of ML-DSA.
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
pub static DEFAULT_KX_GROUPS: &[&dyn SupportedKxGroup] = &[
    kx_group::X25519MLKEM768,
    kx_group::X25519,
    kx_group::SECP256R1,
    kx_group::SECP384R1,
];

/// Every key exchange group this crate supports, in preference order.
pub static ALL_KX_GROUPS: &[&dyn SupportedKxGroup] = &[
    kx_group::X25519MLKEM768,
    kx_group::SECP256R1MLKEM768,
    kx_group::X25519,
    kx_group::SECP256R1,
    kx_group::SECP384R1,
    kx_group::SECP521R1,
    kx_group::MLKEM768,
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
        // without, and aarch64 with it and with it denied, and names which,
        // so both orders are checked.
        match std::env::var_os("RIND_TEST_ARM_CRYPTO_EXT") {
            Some(expected) => assert_eq!(rind::cpu::has_aes_hardware(), expected == "1"),
            None if cfg!(target_arch = "x86_64") => assert!(rind::cpu::has_aes_hardware()),
            None => {}
        }

        let expected = if rind::cpu::has_aes_hardware() {
            DEFAULT_CIPHER_SUITES
        } else {
            CHACHA20_FIRST
        };
        assert_eq!(default_provider().unwrap().cipher_suites, expected);
    }

    // rustls's aws-lc-rs provider offers ML-KEM-1024 and ML-DSA, which rind
    // lacks; everything else it offers, this crate offers too.
    #[test]
    fn aws_lc_rs_parity() {
        use rustls::crypto::aws_lc_rs;
        use rustls::pki_types::{SignatureVerificationAlgorithm, alg_id};
        use rustls::{NamedGroup, SignatureScheme};

        fn sorted<T: Ord>(items: impl IntoIterator<Item = T>) -> Vec<T> {
            let mut items = items.into_iter().collect::<Vec<_>>();
            items.sort();
            items
        }
        let suites = |suites: &[SupportedCipherSuite]| {
            sorted(suites.iter().map(|suite| u16::from(suite.suite())))
        };
        let groups = |groups: &[&dyn SupportedKxGroup]| {
            sorted(groups.iter().map(|group| u16::from(group.name())))
        };
        // Each algorithm's key and signature identifiers.
        let ids = |algs: &[&dyn SignatureVerificationAlgorithm]| {
            sorted(algs.iter().map(|alg| {
                let (key, sig) = (alg.public_key_alg_id(), alg.signature_alg_id());
                (key.as_ref().to_vec(), sig.as_ref().to_vec())
            }))
        };

        assert_eq!(
            suites(DEFAULT_CIPHER_SUITES),
            suites(aws_lc_rs::DEFAULT_CIPHER_SUITES)
        );
        assert_eq!(
            suites(ALL_CIPHER_SUITES),
            suites(aws_lc_rs::ALL_CIPHER_SUITES)
        );

        assert_eq!(
            groups(DEFAULT_KX_GROUPS),
            groups(aws_lc_rs::DEFAULT_KX_GROUPS)
        );
        // aws-lc-rs's provider leaves out secp521r1, which rind has.
        let expected = aws_lc_rs::ALL_KX_GROUPS
            .iter()
            .map(|group| group.name())
            .filter(|name| *name != NamedGroup::MLKEM1024)
            .chain([NamedGroup::secp521r1])
            .map(u16::from);
        assert_eq!(groups(ALL_KX_GROUPS), sorted(expected));

        let ours = default_provider()
            .unwrap()
            .signature_verification_algorithms;
        let theirs = aws_lc_rs::default_provider().signature_verification_algorithms;
        let ml_dsa = [alg_id::ML_DSA_44, alg_id::ML_DSA_65, alg_id::ML_DSA_87];
        let theirs_all = theirs
            .all
            .iter()
            .copied()
            .filter(|alg| !ml_dsa.contains(&alg.public_key_alg_id()))
            .collect::<Vec<_>>();
        assert_eq!(ids(ours.all), ids(&theirs_all));

        // Each scheme verifies with the same algorithms, the first for the
        // scheme's own curve, which is the only one TLS 1.3 uses.
        let ml_dsa = [
            SignatureScheme::ML_DSA_44,
            SignatureScheme::ML_DSA_65,
            SignatureScheme::ML_DSA_87,
        ];
        let theirs = theirs
            .mapping
            .iter()
            .filter(|(scheme, _)| !ml_dsa.contains(scheme))
            .collect::<Vec<_>>();
        assert_eq!(ours.mapping.len(), theirs.len());
        for (scheme, theirs) in theirs {
            let (_, ours) = ours
                .mapping
                .iter()
                .find(|(ours, _)| ours == scheme)
                .unwrap();
            assert_eq!(ids(&ours[..1]), ids(&theirs[..1]), "{scheme:?}");
            assert_eq!(ids(ours), ids(theirs), "{scheme:?}");
        }
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
