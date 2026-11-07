//! <h1 align="center">rind-str0m</h1>
//! <img width="40%" align="right" src="https://raw.githubusercontent.com/moq-dev/rind/main/admin/logo.png">
//!
//! This crate provides a [`CryptoProvider`] for [str0m](https://github.com/algesten/str0m), backed by [rind](https://github.com/moq-dev/rind/), a fork of [Graviola](https://github.com/ctz/graviola/).
//!
//! Build str0m with `default-features = false`, since its default features compile aws-lc-rs.
//! Then hand the provider to each connection:
//!
//! ```rust
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! use std::sync::Arc;
//! use std::time::Instant;
//!
//! // Refuses a CPU missing a feature rind requires.
//! let provider = rind_str0m::default_provider()?;
//! let rtc = str0m::Rtc::builder()
//!     .set_crypto_provider(Arc::new(provider))
//!     .build(Instant::now());
//! # Ok(())
//! # }
//! ```
//!
//! Or install it for the process with [`CryptoProvider::install_process_default`].

use core::fmt;

use str0m::crypto::CryptoProvider;

mod dtls;
mod hash;
mod srtp;

/// A CPU feature rind requires that this CPU lacks.
#[derive(Debug)]
pub struct MissingFeature(rind::cpu::MissingFeature);

impl fmt::Display for MissingFeature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl std::error::Error for MissingFeature {}

/// Returns a str0m [`CryptoProvider`] backed by rind, or the CPU feature rind
/// requires that this CPU lacks.
///
/// It protects SRTP with AES-128-CM-HMAC-SHA1-80, AEAD-AES-128-GCM, and
/// AEAD-AES-256-GCM, signs STUN with HMAC-SHA1, hashes certificate
/// fingerprints with SHA-1 and SHA-256, and runs DTLS 1.2 and 1.3 through
/// dimpl on rind-dimpl with a self-signed ECDSA P-256 certificate.
pub fn default_provider() -> Result<CryptoProvider, MissingFeature> {
    rind::cpu::check().map_err(MissingFeature)?;
    Ok(CryptoProvider {
        srtp_provider: &srtp::SRTP,
        sha1_hmac_provider: &hash::SHA1_HMAC,
        sha1_provider: &hash::SHA1,
        sha256_provider: &hash::SHA256,
        dtls_provider: &dtls::DTLS,
    })
}
