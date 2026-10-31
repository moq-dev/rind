//! <h1 align="center">rind-rcgen</h1>
//! <img width="40%" align="right" src="https://raw.githubusercontent.com/moq-dev/rind/main/admin/picture.png">
//!
//! This crate provides a signing key for [rcgen](https://github.com/rustls/rcgen), backed by [rind](https://github.com/moq-dev/rind/), a fork of [Graviola](https://github.com/ctz/graviola/).
//! It generates and loads ECDSA P-256 and P-384 and Ed25519 keys, and loads RSA keys.
//!
//! Build rcgen with `default-features = false` so it compiles no other crypto backend.
//! rcgen then needs each certificate's serial number set explicitly.
//!
//! ```rust
//! let key = rind_rcgen::KeyPair::generate(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
//!
//! let mut serial = [0u8; 16];
//! rind::rand::fill(&mut serial).unwrap();
//!
//! let mut params = rcgen::CertificateParams::new(["localhost".to_string()]).unwrap();
//! params.serial_number = Some(rcgen::SerialNumber::from_slice(&serial));
//!
//! let cert = params.self_signed(&key).unwrap();
//! let key = key.to_pkcs8();
//! ```
//!
//! rind panics on a CPU missing a feature it requires, so call
//! [`rind::cpu::check`] before using a [`KeyPair`].

use core::fmt;

use rcgen::{
    Error, PKCS_ECDSA_P256_SHA256, PKCS_ECDSA_P384_SHA384, PKCS_ED25519, PKCS_RSA_SHA256,
    PKCS_RSA_SHA384, PKCS_RSA_SHA512, SignatureAlgorithm,
};
use rind::signature::{
    EcdsaKeyPair, EcdsaSigningAlgorithm, Ed25519KeyPair, PublicKey, RsaKeyPair,
    RsaSigningAlgorithm, sign,
};
use rustls_pki_types::PrivatePkcs8KeyDer;
use zeroize::Zeroizing;

/// A key pair that signs rcgen certificates and requests with one algorithm.
pub struct KeyPair {
    key: Key,
    algorithm: &'static SignatureAlgorithm,
    // Kept for `der_bytes`, which lends its encoding.
    public_key: PublicKey,
}

#[allow(clippy::large_enum_variant)]
enum Key {
    Ecdsa(EcdsaKeyPair),
    Ed25519(Ed25519KeyPair),
    Rsa(RsaKeyPair, &'static RsaSigningAlgorithm),
}

impl KeyPair {
    /// Generates a random key pair that signs with `algorithm`: ECDSA P-256 or
    /// P-384, or Ed25519.
    pub fn generate(algorithm: &'static SignatureAlgorithm) -> Result<Self, Error> {
        let key = match signer(algorithm)? {
            Signer::Ecdsa(signing) => {
                Key::Ecdsa(EcdsaKeyPair::generate(signing).map_err(|_| Error::RingUnspecified)?)
            }
            Signer::Ed25519 => {
                Key::Ed25519(Ed25519KeyPair::generate().map_err(|_| Error::RingUnspecified)?)
            }
            Signer::Rsa(_) => return Err(Error::KeyGenerationUnavailable),
        };
        Ok(Self::new(key, algorithm))
    }

    /// Loads a PKCS#8 private key that signs with `algorithm`: ECDSA P-256 or
    /// P-384, Ed25519, or RSA PKCS#1 v1.5.
    pub fn from_pkcs8(
        algorithm: &'static SignatureAlgorithm,
        der: &PrivatePkcs8KeyDer<'_>,
    ) -> Result<Self, Error> {
        let der = der.secret_pkcs8_der();
        let key = match signer(algorithm)? {
            Signer::Ecdsa(signing) => {
                Key::Ecdsa(EcdsaKeyPair::from_pkcs8(signing, der).map_err(rejected)?)
            }
            Signer::Ed25519 => Key::Ed25519(Ed25519KeyPair::from_pkcs8(der).map_err(rejected)?),
            Signer::Rsa(padding) => {
                Key::Rsa(RsaKeyPair::from_pkcs8(der).map_err(rejected)?, padding)
            }
        };
        Ok(Self::new(key, algorithm))
    }

    /// Encodes the private key as PKCS#8, which is wiped on drop.
    pub fn to_pkcs8(&self) -> Zeroizing<PrivatePkcs8KeyDer<'static>> {
        let pkcs8 = match &self.key {
            Key::Ecdsa(key) => key.to_pkcs8(),
            Key::Ed25519(key) => key.to_pkcs8(),
            Key::Rsa(key, _) => key.to_pkcs8(),
        };
        Zeroizing::new(PrivatePkcs8KeyDer::from(pkcs8.as_ref().to_vec()))
    }

    fn new(key: Key, algorithm: &'static SignatureAlgorithm) -> Self {
        let public_key = match &key {
            Key::Ecdsa(key) => key.public_key(),
            Key::Ed25519(key) => key.public_key(),
            Key::Rsa(key, padding) => key.public_key(padding),
        };
        Self {
            key,
            algorithm,
            public_key,
        }
    }
}

/// How rind signs for an rcgen algorithm.
enum Signer {
    Ecdsa(&'static EcdsaSigningAlgorithm),
    Ed25519,
    Rsa(&'static RsaSigningAlgorithm),
}

/// Finds how rind signs for `algorithm`, refusing one it doesn't support.
fn signer(algorithm: &SignatureAlgorithm) -> Result<Signer, Error> {
    // rcgen's algorithms are statics compared by value, so this can't match on them.
    Ok(if *algorithm == PKCS_ECDSA_P256_SHA256 {
        Signer::Ecdsa(&sign::ECDSA_P256_SHA256_ASN1)
    } else if *algorithm == PKCS_ECDSA_P384_SHA384 {
        Signer::Ecdsa(&sign::ECDSA_P384_SHA384_ASN1)
    } else if *algorithm == PKCS_ED25519 {
        Signer::Ed25519
    } else if *algorithm == PKCS_RSA_SHA256 {
        Signer::Rsa(&sign::RSA_PKCS1_SHA256)
    } else if *algorithm == PKCS_RSA_SHA384 {
        Signer::Rsa(&sign::RSA_PKCS1_SHA384)
    } else if *algorithm == PKCS_RSA_SHA512 {
        Signer::Rsa(&sign::RSA_PKCS1_SHA512)
    } else {
        return Err(Error::UnsupportedSignatureAlgorithm);
    })
}

/// Keeps rind's reason for refusing a key, as rcgen does for its backends.
fn rejected(err: rind::Error) -> Error {
    match err {
        rind::Error::KeyRejected(reason) => Error::RingKeyRejected(reason.to_string()),
        other => Error::RingKeyRejected(other.to_string()),
    }
}

impl rcgen::PublicKeyData for KeyPair {
    // rcgen takes the uncompressed point for ECDSA, the 32 bytes for Ed25519,
    // and PKCS#1 `RSAPublicKey` DER for RSA, which is rind's encoding of each.
    fn der_bytes(&self) -> &[u8] {
        self.public_key.as_ref()
    }

    fn algorithm(&self) -> &'static SignatureAlgorithm {
        self.algorithm
    }
}

impl rcgen::SigningKey for KeyPair {
    fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, Error> {
        let signature = match &self.key {
            Key::Ecdsa(key) => key.sign(msg),
            Key::Ed25519(key) => Ok(key.sign(msg)),
            Key::Rsa(key, padding) => key.sign(padding, msg),
        }
        .map_err(|_| Error::RingUnspecified)?;
        Ok(signature.as_ref().to_vec())
    }
}

impl fmt::Debug for KeyPair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeyPair")
            .field("algorithm", self.algorithm)
            .finish_non_exhaustive()
    }
}
