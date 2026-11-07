// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0
use pyo3::prelude::*;
use pyo3::types::PyBytes;
use rind::signature::{self, sign, verify};

use crate::rsa::KeySize;
use crate::{Bytes, algorithm, bytes, constants, error, submodule};

algorithm!(
    /// An algorithm an `EcdsaKeyPair` signs with.
    EcdsaSigningAlgorithm(signature::EcdsaSigningAlgorithm) as "pyrind.signature"."EcdsaSigningAlgorithm" {}
);

algorithm!(
    /// An algorithm an `RsaKeyPair` signs with.
    RsaSigningAlgorithm(signature::RsaSigningAlgorithm) as "pyrind.signature"."RsaSigningAlgorithm" {}
);

algorithm!(
    /// An algorithm a `PublicKey` verifies with.
    VerificationAlgorithm(signature::VerificationAlgorithm) as "pyrind.signature"."VerificationAlgorithm" {}
);

algorithm!(
    /// An RSA algorithm a `PublicKey` verifies with, which also loads a key
    /// from its components.
    RsaVerificationAlgorithm(signature::RsaVerificationAlgorithm) as "pyrind.signature"."RsaVerificationAlgorithm" {}
);

/// Either kind of verification algorithm.
#[derive(FromPyObject)]
enum AnyVerificationAlgorithm<'py> {
    Plain(Bound<'py, VerificationAlgorithm>),
    Rsa(Bound<'py, RsaVerificationAlgorithm>),
}

impl AnyVerificationAlgorithm<'_> {
    fn get(&self) -> &'static signature::VerificationAlgorithm {
        match self {
            Self::Plain(algorithm) => algorithm.get().inner,
            Self::Rsa(algorithm) => algorithm.get().inner.as_ref(),
        }
    }
}

/// A public key that verifies signatures for one algorithm, whose `bytes`
/// are its encoding: an uncompressed SEC1 point for ECDSA, 32 bytes for
/// Ed25519, and a PKCS#1 `RSAPublicKey` for RSA.
#[pyclass(frozen, module = "pyrind.signature")]
struct PublicKey(Box<signature::PublicKey>);

#[pymethods]
impl PublicKey {
    /// Parses a public key for `algorithm` from its `bytes` encoding.
    #[new]
    fn new(algorithm: AnyVerificationAlgorithm<'_>, data: Bytes<'_>) -> PyResult<Self> {
        signature::PublicKey::new(algorithm.get(), &data)
            .map(Box::new)
            .map(Self)
            .map_err(error)
    }

    /// Parses a public key for `algorithm` from `SubjectPublicKeyInfo` DER,
    /// refusing one that names another algorithm or curve.
    #[staticmethod]
    fn from_spki(algorithm: AnyVerificationAlgorithm<'_>, der: Bytes<'_>) -> PyResult<Self> {
        signature::PublicKey::from_spki(algorithm.get(), &der)
            .map(Box::new)
            .map(Self)
            .map_err(error)
    }

    /// Loads an RSA key for `algorithm` from its big-endian modulus `n` and
    /// exponent `e`, as a JWK carries them.
    #[staticmethod]
    fn from_components(
        algorithm: &Bound<'_, RsaVerificationAlgorithm>,
        n: Bytes<'_>,
        e: Bytes<'_>,
    ) -> PyResult<Self> {
        let components = rind::rsa::PublicKeyComponents { n: &*n, e: &*e };
        signature::PublicKey::from_components(algorithm.get().inner, &components)
            .map(Box::new)
            .map(Self)
            .map_err(error)
    }

    /// Checks `signature` over `message`; raises `BadSignature` if it does
    /// not verify.
    fn verify(&self, message: Bytes<'_>, signature: Bytes<'_>) -> PyResult<()> {
        self.0.verify(&message, &signature).map_err(error)
    }

    /// Encodes the key as `SubjectPublicKeyInfo` DER.
    fn to_spki<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        bytes(py, self.0.to_spki())
    }

    fn __bytes__<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        bytes(py, &*self.0)
    }
}

/// An ECDSA key pair, which signs with one algorithm.
#[pyclass(frozen, module = "pyrind.signature")]
struct EcdsaKeyPair(Box<signature::EcdsaKeyPair>);

#[pymethods]
impl EcdsaKeyPair {
    /// Generates a key pair for `algorithm`.
    #[staticmethod]
    fn generate(algorithm: &Bound<'_, EcdsaSigningAlgorithm>) -> PyResult<Self> {
        signature::EcdsaKeyPair::generate(algorithm.get().inner)
            .map(Box::new)
            .map(Self)
            .map_err(error)
    }

    /// Loads a key pair for `algorithm` from PKCS#8 DER.
    #[staticmethod]
    fn from_pkcs8(algorithm: &Bound<'_, EcdsaSigningAlgorithm>, der: Bytes<'_>) -> PyResult<Self> {
        signature::EcdsaKeyPair::from_pkcs8(algorithm.get().inner, &der)
            .map(Box::new)
            .map(Self)
            .map_err(error)
    }

    /// Loads a key pair for `algorithm` from SEC1 `ECPrivateKey` DER.
    #[staticmethod]
    fn from_sec1(algorithm: &Bound<'_, EcdsaSigningAlgorithm>, der: Bytes<'_>) -> PyResult<Self> {
        signature::EcdsaKeyPair::from_sec1(algorithm.get().inner, &der)
            .map(Box::new)
            .map(Self)
            .map_err(error)
    }

    /// Loads a key pair for `algorithm` from its big-endian scalar and its
    /// uncompressed public key, as a JWK's `d`, `x`, and `y` carry them,
    /// refused unless they match.
    #[staticmethod]
    fn from_scalar_and_public_key(
        algorithm: &Bound<'_, EcdsaSigningAlgorithm>,
        scalar: Bytes<'_>,
        public_key: Bytes<'_>,
    ) -> PyResult<Self> {
        signature::EcdsaKeyPair::from_scalar_and_public_key(
            algorithm.get().inner,
            &scalar,
            &public_key,
        )
        .map(Box::new)
        .map(Self)
        .map_err(error)
    }

    /// The public key, which verifies with the verification algorithm of the
    /// same name.
    fn public_key(&self) -> PublicKey {
        PublicKey(Box::new(self.0.public_key()))
    }

    /// Signs `message`.
    fn sign<'py>(&self, py: Python<'py>, message: Bytes<'_>) -> PyResult<Bound<'py, PyBytes>> {
        let signature = self.0.sign(&message).map_err(error)?;
        Ok(bytes(py, signature))
    }

    /// Encodes the key pair as PKCS#8 DER.
    fn to_pkcs8<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        bytes(py, self.0.to_pkcs8())
    }

    /// Encodes the key pair as SEC1 `ECPrivateKey` DER.
    fn to_sec1<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        bytes(py, self.0.to_sec1())
    }

    /// Returns the private key's big-endian scalar.
    fn to_scalar<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        bytes(py, self.0.to_scalar())
    }

    /// Encodes the public key as `SubjectPublicKeyInfo` DER.
    fn to_spki<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        bytes(py, self.0.to_spki())
    }
}

/// An Ed25519 key pair.
#[pyclass(frozen, module = "pyrind.signature")]
struct Ed25519KeyPair(Box<signature::Ed25519KeyPair>);

#[pymethods]
impl Ed25519KeyPair {
    /// Generates a key pair.
    #[staticmethod]
    fn generate() -> PyResult<Self> {
        signature::Ed25519KeyPair::generate()
            .map(Box::new)
            .map(Self)
            .map_err(error)
    }

    /// Loads a key pair from PKCS#8 v1 or v2 DER, refused if a v2 key's
    /// public key does not match.
    #[staticmethod]
    fn from_pkcs8(der: Bytes<'_>) -> PyResult<Self> {
        signature::Ed25519KeyPair::from_pkcs8(&der)
            .map(Box::new)
            .map(Self)
            .map_err(error)
    }

    /// Loads a 32-byte seed, as a JWK's `d` holds it, deriving its public
    /// key.
    #[staticmethod]
    fn from_seed(seed: Bytes<'_>) -> PyResult<Self> {
        signature::Ed25519KeyPair::from_seed(&seed)
            .map(Box::new)
            .map(Self)
            .map_err(error)
    }

    /// Loads a 32-byte seed, refused unless `public_key` is its public key.
    #[staticmethod]
    fn from_seed_and_public_key(seed: Bytes<'_>, public_key: Bytes<'_>) -> PyResult<Self> {
        signature::Ed25519KeyPair::from_seed_and_public_key(&seed, &public_key)
            .map(Box::new)
            .map(Self)
            .map_err(error)
    }

    /// The public key, which verifies with `verify.ED25519`.
    fn public_key(&self) -> PublicKey {
        PublicKey(Box::new(self.0.public_key()))
    }

    /// Signs `message`.
    fn sign<'py>(&self, py: Python<'py>, message: Bytes<'_>) -> Bound<'py, PyBytes> {
        bytes(py, self.0.sign(&message))
    }

    /// Encodes the key pair as PKCS#8 v2 DER (RFC 5958), with its public key.
    fn to_pkcs8<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        bytes(py, self.0.to_pkcs8())
    }

    /// Encodes the private key as PKCS#8 v1 DER (RFC 8410), as OpenSSL
    /// writes it.
    fn to_pkcs8v1<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        bytes(py, self.0.to_pkcs8v1())
    }

    /// Returns the private key's 32-byte seed.
    fn to_seed<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        bytes(py, self.0.to_seed())
    }

    /// Encodes the public key as `SubjectPublicKeyInfo` DER.
    fn to_spki<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        bytes(py, self.0.to_spki())
    }
}

/// An RSA key pair, which signs with any RSA signing algorithm.
#[pyclass(frozen, module = "pyrind.signature")]
struct RsaKeyPair(Box<signature::RsaKeyPair>);

#[pymethods]
impl RsaKeyPair {
    /// Generates a key pair of `size`, releasing the GIL: about 30
    /// milliseconds for 2048 bits, and seconds for the largest sizes.
    #[staticmethod]
    fn generate(py: Python<'_>, size: KeySize) -> PyResult<Self> {
        py.detach(|| signature::RsaKeyPair::generate(size.into()))
            .map(Box::new)
            .map(Self)
            .map_err(error)
    }

    /// Loads a PKCS#8 RSA private key.
    #[staticmethod]
    fn from_pkcs8(der: Bytes<'_>) -> PyResult<Self> {
        signature::RsaKeyPair::from_pkcs8(&der)
            .map(Box::new)
            .map(Self)
            .map_err(error)
    }

    /// Loads a PKCS#1 `RSAPrivateKey`.
    #[staticmethod]
    fn from_pkcs1(der: Bytes<'_>) -> PyResult<Self> {
        signature::RsaKeyPair::from_pkcs1(&der)
            .map(Box::new)
            .map(Self)
            .map_err(error)
    }

    /// The public key, which verifies what this key pair signs with
    /// `algorithm`.
    fn public_key(&self, algorithm: &Bound<'_, RsaSigningAlgorithm>) -> PublicKey {
        PublicKey(Box::new(self.0.public_key(algorithm.get().inner)))
    }

    /// Signs `message` with `algorithm`, releasing the GIL.
    fn sign<'py>(
        &self,
        py: Python<'py>,
        algorithm: &Bound<'_, RsaSigningAlgorithm>,
        message: Bytes<'_>,
    ) -> PyResult<Bound<'py, PyBytes>> {
        let algorithm = algorithm.get().inner;
        let signature = py
            .detach(|| self.0.sign(algorithm, &message))
            .map_err(error)?;
        Ok(bytes(py, signature))
    }

    /// Encodes the private key as PKCS#8 DER.
    fn to_pkcs8<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        bytes(py, self.0.to_pkcs8())
    }

    /// Encodes the public key as `SubjectPublicKeyInfo` DER.
    fn to_spki<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        bytes(py, self.0.to_spki())
    }
}

pub(crate) fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<EcdsaSigningAlgorithm>()?;
    m.add_class::<RsaSigningAlgorithm>()?;
    m.add_class::<VerificationAlgorithm>()?;
    m.add_class::<RsaVerificationAlgorithm>()?;
    m.add_class::<PublicKey>()?;
    m.add_class::<EcdsaKeyPair>()?;
    m.add_class::<Ed25519KeyPair>()?;
    m.add_class::<RsaKeyPair>()?;
    submodule(m, "pyrind.signature.sign", |m| {
        constants!(m, EcdsaSigningAlgorithm, "pyrind.signature.sign", {
            ECDSA_P256_SHA256_ASN1 => &sign::ECDSA_P256_SHA256_ASN1,
            ECDSA_P256_SHA256_FIXED => &sign::ECDSA_P256_SHA256_FIXED,
            ECDSA_P384_SHA384_ASN1 => &sign::ECDSA_P384_SHA384_ASN1,
            ECDSA_P384_SHA384_FIXED => &sign::ECDSA_P384_SHA384_FIXED,
            ECDSA_P521_SHA512_ASN1 => &sign::ECDSA_P521_SHA512_ASN1,
            ECDSA_P521_SHA512_FIXED => &sign::ECDSA_P521_SHA512_FIXED,
        });
        constants!(m, RsaSigningAlgorithm, "pyrind.signature.sign", {
            RSA_PKCS1_SHA256 => &sign::RSA_PKCS1_SHA256,
            RSA_PKCS1_SHA384 => &sign::RSA_PKCS1_SHA384,
            RSA_PKCS1_SHA512 => &sign::RSA_PKCS1_SHA512,
            RSA_PSS_SHA256 => &sign::RSA_PSS_SHA256,
            RSA_PSS_SHA384 => &sign::RSA_PSS_SHA384,
            RSA_PSS_SHA512 => &sign::RSA_PSS_SHA512,
        });
        Ok(())
    })?;
    submodule(m, "pyrind.signature.verify", |m| {
        constants!(m, VerificationAlgorithm, "pyrind.signature.verify", {
            ECDSA_P256_SHA256_ASN1 => &verify::ECDSA_P256_SHA256_ASN1,
            ECDSA_P256_SHA256_FIXED => &verify::ECDSA_P256_SHA256_FIXED,
            ECDSA_P256_SHA384_ASN1 => &verify::ECDSA_P256_SHA384_ASN1,
            ECDSA_P256_SHA512_ASN1 => &verify::ECDSA_P256_SHA512_ASN1,
            ECDSA_P384_SHA256_ASN1 => &verify::ECDSA_P384_SHA256_ASN1,
            ECDSA_P384_SHA384_ASN1 => &verify::ECDSA_P384_SHA384_ASN1,
            ECDSA_P384_SHA384_FIXED => &verify::ECDSA_P384_SHA384_FIXED,
            ECDSA_P384_SHA512_ASN1 => &verify::ECDSA_P384_SHA512_ASN1,
            ECDSA_P521_SHA256_ASN1 => &verify::ECDSA_P521_SHA256_ASN1,
            ECDSA_P521_SHA384_ASN1 => &verify::ECDSA_P521_SHA384_ASN1,
            ECDSA_P521_SHA512_ASN1 => &verify::ECDSA_P521_SHA512_ASN1,
            ECDSA_P521_SHA512_FIXED => &verify::ECDSA_P521_SHA512_FIXED,
            ED25519 => &verify::ED25519,
        });
        constants!(m, RsaVerificationAlgorithm, "pyrind.signature.verify", {
            RSA_PKCS1_SHA256 => &verify::RSA_PKCS1_SHA256,
            RSA_PKCS1_SHA384 => &verify::RSA_PKCS1_SHA384,
            RSA_PKCS1_SHA512 => &verify::RSA_PKCS1_SHA512,
            RSA_PSS_SHA256 => &verify::RSA_PSS_SHA256,
            RSA_PSS_SHA256_ANY_SALT => &verify::RSA_PSS_SHA256_ANY_SALT,
            RSA_PSS_SHA384 => &verify::RSA_PSS_SHA384,
            RSA_PSS_SHA384_ANY_SALT => &verify::RSA_PSS_SHA384_ANY_SALT,
            RSA_PSS_SHA512 => &verify::RSA_PSS_SHA512,
            RSA_PSS_SHA512_ANY_SALT => &verify::RSA_PSS_SHA512_ANY_SALT,
        });
        submodule(m, "pyrind.signature.verify.legacy", |legacy| {
            constants!(legacy, RsaVerificationAlgorithm, "pyrind.signature.verify.legacy", {
                RSA_PKCS1_1024_SHA1 => &verify::legacy::RSA_PKCS1_1024_SHA1,
                RSA_PKCS1_1024_SHA256 => &verify::legacy::RSA_PKCS1_1024_SHA256,
                RSA_PKCS1_1024_SHA512 => &verify::legacy::RSA_PKCS1_1024_SHA512,
                RSA_PKCS1_3072_SHA384 => &verify::legacy::RSA_PKCS1_3072_SHA384,
                RSA_PKCS1_SHA1 => &verify::legacy::RSA_PKCS1_SHA1,
            });
            Ok(())
        })
    })
}
