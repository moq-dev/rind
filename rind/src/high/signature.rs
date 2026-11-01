// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

use core::fmt;

use super::curve::{Curve, MAX_SCALAR_LEN, MAX_UNCOMPRESSED_PUBLIC_KEY_LEN, P256, P384, P521};
use super::ecdsa;
use super::ed25519::{Ed25519SigningKey, Ed25519VerifyingKey};
use super::hash::{Sha256, Sha384, Sha512};
use super::rsa;
use crate::error::{Error, KeyFormatError};
use crate::low::{self, Zeroable};
pub use crate::mid::rsa_key_size::RsaKeySize;
use crate::mid::rsa_pub::MAX_PUBLIC_MODULUS_BYTES;

/// The hash a signature algorithm applies to the message.
///
/// No variant is SHA-1, so SHA-1 never reaches signing or ECDSA: only
/// [`RsaVerification::Pkcs1Sha1`] takes it.
#[derive(Clone, Copy, Debug, PartialEq)]
#[repr(u8)]
enum HashId {
    Sha256,
    Sha384,
    Sha512,
}

/// Runs `$body` with `$H` naming the hash type for `$hash`.
macro_rules! with_hash {
    ($hash:expr, |$H:ident| $body:expr) => {
        match $hash {
            HashId::Sha256 => {
                type $H = Sha256;
                $body
            }
            HashId::Sha384 => {
                type $H = Sha384;
                $body
            }
            HashId::Sha512 => {
                type $H = Sha512;
                $body
            }
        }
    };
}

/// Up to `N` bytes, as the owned encodings and signatures hold them.
#[derive(Clone, Copy)]
struct Buffer<const N: usize> {
    bytes: [u8; N],
    len: usize,
}

impl<const N: usize> Buffer<N> {
    fn new() -> Self {
        Self {
            bytes: [0; N],
            len: 0,
        }
    }

    fn copy_from(bytes: &[u8]) -> Result<Self, Error> {
        let mut buffer = Self::new();
        buffer
            .bytes
            .get_mut(..bytes.len())
            .ok_or(Error::WrongLength)?
            .copy_from_slice(bytes);
        buffer.len = bytes.len();
        Ok(buffer)
    }

    /// Runs `write`, which writes to the start of its argument and returns
    /// the written span.
    fn write(write: impl FnOnce(&mut [u8]) -> Result<&[u8], Error>) -> Result<Self, Error> {
        let mut buffer = Self::new();
        buffer.len = write(&mut buffer.bytes)?.len();
        Ok(buffer)
    }

    /// Copies into a buffer at least as large.
    fn widen<const M: usize>(&self) -> Buffer<M> {
        const { assert!(M >= N) };
        let mut wide = Buffer::new();
        wide.bytes[..N].copy_from_slice(&self.bytes);
        wide.len = self.len;
        wide
    }

    /// Runs `encode` as [`Self::write`] does, for an encoder `N` is sized
    /// for.
    ///
    /// Every `N` holds the encoding of the largest key a loader accepts, so
    /// an encoder that runs out of room is a bug in rind, not bad input.
    fn encode(encode: impl FnOnce(&mut [u8]) -> Result<&[u8], Error>) -> Self {
        Self::write(encode).expect("sized for the largest key")
    }
}

impl<const N: usize> From<[u8; N]> for Buffer<N> {
    fn from(bytes: [u8; N]) -> Self {
        Self { bytes, len: N }
    }
}

impl<const N: usize> AsRef<[u8]> for Buffer<N> {
    fn as_ref(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}

// Bytes and a length, both valid at zero.
impl<const N: usize> Zeroable for Buffer<N> {}

/// A signature verification algorithm, which a [`PublicKey`] is bound to.
pub struct VerificationAlgorithm(Verification);

#[derive(Clone, Copy, Debug)]
enum Verification {
    Ecdsa(Ecdsa),
    Rsa(Rsa),
    Ed25519,
}

impl fmt::Debug for VerificationAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl AsRef<Self> for VerificationAlgorithm {
    fn as_ref(&self) -> &Self {
        self
    }
}

/// An RSA signature verification algorithm, which also parses
/// [`RsaPublicKeyComponents`].
pub struct RsaVerificationAlgorithm {
    rsa: Rsa,
    algorithm: VerificationAlgorithm,
}

impl AsRef<VerificationAlgorithm> for RsaVerificationAlgorithm {
    fn as_ref(&self) -> &VerificationAlgorithm {
        &self.algorithm
    }
}

impl fmt::Debug for RsaVerificationAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.rsa.fmt(f)
    }
}

/// A public key, bound to the one algorithm it verifies signatures with.
///
/// Its bytes are its encoding, as [`PublicKey::new`] takes it.
pub struct PublicKey {
    key: Parsed,
    encoding: Buffer<{ rsa::MAX_PUBLIC_KEY_LEN }>,
}

#[allow(clippy::large_enum_variant)]
enum Parsed {
    EcdsaP256(ecdsa::VerifyingKey<P256>, Ecdsa),
    EcdsaP384(ecdsa::VerifyingKey<P384>, Ecdsa),
    EcdsaP521(ecdsa::VerifyingKey<P521>, Ecdsa),
    Rsa(rsa::VerifyingKey, RsaVerification),
    Ed25519(Ed25519VerifyingKey),
}

impl PublicKey {
    /// Parses a public key for `algorithm`, any `verify` constant,
    /// refusing a malformed key before any signature arrives.
    ///
    /// ECDSA keys are X9.62 uncompressed points, RSA keys are PKCS#1
    /// `RSAPublicKey` DER, and Ed25519 keys are their 32 bytes. A compressed
    /// ECDSA point is refused: no consumer sends one.
    pub fn new(
        algorithm: &'static impl AsRef<VerificationAlgorithm>,
        bytes: &[u8],
    ) -> Result<Self, Error> {
        let key = match algorithm.as_ref().0 {
            Verification::Ecdsa(ecdsa) => match ecdsa.curve {
                CurveId::P256 => {
                    Parsed::EcdsaP256(ecdsa::VerifyingKey::from_x962_uncompressed(bytes)?, ecdsa)
                }
                CurveId::P384 => {
                    Parsed::EcdsaP384(ecdsa::VerifyingKey::from_x962_uncompressed(bytes)?, ecdsa)
                }
                CurveId::P521 => {
                    Parsed::EcdsaP521(ecdsa::VerifyingKey::from_x962_uncompressed(bytes)?, ecdsa)
                }
            },
            Verification::Rsa(rsa) => {
                return Self::rsa(rsa, rsa::VerifyingKey::from_pkcs1_der(bytes)?);
            }
            Verification::Ed25519 => Parsed::Ed25519(Ed25519VerifyingKey::from_bytes(bytes)?),
        };
        Ok(Self {
            key,
            encoding: Buffer::copy_from(bytes)?,
        })
    }

    /// Binds an RSA key to `rsa`, refusing it below the algorithm's floor.
    ///
    /// The encoding is the key's DER, whether it came as DER or components.
    fn rsa(rsa: Rsa, key: rsa::VerifyingKey) -> Result<Self, Error> {
        let key = rsa.check(key)?;
        Ok(Self {
            encoding: Buffer::write(|output| key.to_pkcs1_der(output))?,
            key: Parsed::Rsa(key, rsa.verification),
        })
    }

    /// Verifies `signature` over `message`, refusing a malformed signature.
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), Error> {
        match &self.key {
            Parsed::EcdsaP256(key, algorithm) => algorithm.verify(key, message, signature),
            Parsed::EcdsaP384(key, algorithm) => algorithm.verify(key, message, signature),
            Parsed::EcdsaP521(key, algorithm) => algorithm.verify(key, message, signature),
            Parsed::Rsa(key, verification) => verification.verify(key, message, signature),
            Parsed::Ed25519(key) => key.verify(signature, message),
        }
    }
}

impl AsRef<[u8]> for PublicKey {
    fn as_ref(&self) -> &[u8] {
        self.encoding.as_ref()
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut f = f.debug_struct("PublicKey");
        match &self.key {
            Parsed::EcdsaP256(_, algorithm)
            | Parsed::EcdsaP384(_, algorithm)
            | Parsed::EcdsaP521(_, algorithm) => f.field("algorithm", algorithm),
            Parsed::Rsa(_, verification) => f.field("algorithm", verification),
            Parsed::Ed25519(_) => f.field("algorithm", &Verification::Ed25519),
        };
        f.field("bytes", &self.as_ref()).finish()
    }
}

/// A signature from any key pair.
#[derive(Clone, Copy)]
pub struct Signature(Buffer<SIGNATURE_MAX_LEN>);

// RSA's, as long as the largest modulus, is longer than any ECDSA DER
// signature: a `SEQUENCE`, whose length takes two bytes, of two P-521
// `INTEGER`s, each with a sign byte.
const SIGNATURE_MAX_LEN: usize = MAX_PUBLIC_MODULUS_BYTES;
const _: () = assert!(3 + 2 * (2 + MAX_SCALAR_LEN + 1) <= SIGNATURE_MAX_LEN);

impl AsRef<[u8]> for Signature {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl fmt::Debug for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Signature").field(&self.as_ref()).finish()
    }
}

/// A private key encoded as PKCS#8 DER, wiped on drop.
pub struct Pkcs8(Buffer<{ rsa::MAX_PKCS8_LEN }>);

impl AsRef<[u8]> for Pkcs8 {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl fmt::Debug for Pkcs8 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Pkcs8").finish_non_exhaustive()
    }
}

impl Drop for Pkcs8 {
    fn drop(&mut self) {
        low::zeroise_value(&mut self.0);
    }
}

/// A public key encoded as a `SubjectPublicKeyInfo` in DER.
#[derive(Clone)]
pub struct Spki(Buffer<{ rsa::MAX_SPKI_LEN }>);

impl AsRef<[u8]> for Spki {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl fmt::Debug for Spki {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Spki").field(&self.as_ref()).finish()
    }
}

/// An ECDSA private key as a big-endian scalar exactly the curve's length,
/// wiped on drop.
pub struct EcdsaScalar(Buffer<MAX_SCALAR_LEN>);

impl AsRef<[u8]> for EcdsaScalar {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl fmt::Debug for EcdsaScalar {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("EcdsaScalar").finish_non_exhaustive()
    }
}

impl Drop for EcdsaScalar {
    fn drop(&mut self) {
        low::zeroise_value(&mut self.0);
    }
}

/// An Ed25519 private key as its 32-byte seed, wiped on drop.
pub struct Ed25519Seed([u8; 32]);

impl AsRef<[u8]> for Ed25519Seed {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for Ed25519Seed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Ed25519Seed").finish_non_exhaustive()
    }
}

impl Drop for Ed25519Seed {
    fn drop(&mut self) {
        low::zeroise(&mut self.0);
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
#[repr(u8)]
enum CurveId {
    P256,
    P384,
    P521,
}

#[derive(Clone, Copy, Debug, PartialEq)]
#[repr(u8)]
enum EcdsaEncoding {
    /// A DER `Ecdsa-Sig-Value`, as X.509 and TLS use.
    Asn1,
    /// `r || s`, each the curve's scalar length, as JWS uses.
    Fixed,
}

/// A curve, a hash, and a signature encoding.
#[derive(Clone, Copy, Debug)]
struct Ecdsa {
    curve: CurveId,
    hash: HashId,
    encoding: EcdsaEncoding,
}

impl Ecdsa {
    fn verify<C: Curve>(
        self,
        key: &ecdsa::VerifyingKey<C>,
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), Error> {
        with_hash!(self.hash, |H| match self.encoding {
            EcdsaEncoding::Asn1 => key.verify_asn1::<H>(message, signature),
            EcdsaEncoding::Fixed => key.verify::<H>(message, signature),
        })
    }
}

const fn ecdsa_verification(
    curve: CurveId,
    hash: HashId,
    encoding: EcdsaEncoding,
) -> VerificationAlgorithm {
    VerificationAlgorithm(Verification::Ecdsa(Ecdsa {
        curve,
        hash,
        encoding,
    }))
}

/// Signs as `verification` verifies, which must be ECDSA: checked when a
/// static is compiled, never at run time.
const fn ecdsa_signing(verification: &VerificationAlgorithm) -> EcdsaSigningAlgorithm {
    match verification.0 {
        Verification::Ecdsa(ecdsa) => EcdsaSigningAlgorithm(ecdsa),
        _ => panic!("not an ECDSA algorithm"),
    }
}

/// An ECDSA signing algorithm, which an [`EcdsaKeyPair`] is bound to.
#[derive(Debug)]
pub struct EcdsaSigningAlgorithm(Ecdsa);

/// An ECDSA private key and its public key, bound to one signing algorithm.
pub struct EcdsaKeyPair {
    key: EcdsaKey,
    algorithm: Ecdsa,
    point: Buffer<MAX_UNCOMPRESSED_PUBLIC_KEY_LEN>,
}

// `repr(u8)` puts `P256` at tag zero, so all-bits-zero is a valid value.
#[allow(clippy::large_enum_variant)]
#[repr(u8)]
enum EcdsaKey {
    P256(ecdsa::SigningKey<P256>, ecdsa::VerifyingKey<P256>),
    P384(ecdsa::SigningKey<P384>, ecdsa::VerifyingKey<P384>),
    P521(ecdsa::SigningKey<P521>, ecdsa::VerifyingKey<P521>),
}

/// Loads a key on `$algorithm`'s curve with `SigningKey::$load`.
macro_rules! load_ecdsa {
    ($algorithm:expr, $load:ident($($arg:expr),*)) => {
        match $algorithm.0.curve {
            CurveId::P256 => {
                EcdsaKeyPair::new($algorithm, ecdsa::SigningKey::$load($($arg),*)?, EcdsaKey::P256)
            }
            CurveId::P384 => {
                EcdsaKeyPair::new($algorithm, ecdsa::SigningKey::$load($($arg),*)?, EcdsaKey::P384)
            }
            CurveId::P521 => {
                EcdsaKeyPair::new($algorithm, ecdsa::SigningKey::$load($($arg),*)?, EcdsaKey::P521)
            }
        }
    };
}

/// Runs `$body` with `$key` bound to whichever curve's signing key `$pair`
/// holds.
macro_rules! on_ecdsa {
    ($pair:expr, |$key:ident| $body:expr) => {
        match &$pair.key {
            EcdsaKey::P256($key, _) => $body,
            EcdsaKey::P384($key, _) => $body,
            EcdsaKey::P521($key, _) => $body,
        }
    };
}

impl EcdsaKeyPair {
    /// Generates a key pair for `algorithm` from the system random source.
    pub fn generate(algorithm: &'static EcdsaSigningAlgorithm) -> Result<Self, Error> {
        load_ecdsa!(algorithm, generate())
    }

    /// Loads a PKCS#8 `ECPrivateKey` on `algorithm`'s curve.
    pub fn from_pkcs8(
        algorithm: &'static EcdsaSigningAlgorithm,
        der: &[u8],
    ) -> Result<Self, Error> {
        load_ecdsa!(algorithm, from_pkcs8_der(der))
    }

    /// Loads a SEC1 (RFC 5915) `ECPrivateKey` on `algorithm`'s curve.
    ///
    /// This refuses PKCS#8, which [`Self::from_pkcs8`] takes: a caller always
    /// knows which of the two it holds.
    pub fn from_sec1(algorithm: &'static EcdsaSigningAlgorithm, der: &[u8]) -> Result<Self, Error> {
        load_ecdsa!(algorithm, from_sec1_der(der))
    }

    /// Loads a fixed-length big-endian private scalar, refused unless
    /// `public_key`, an X9.62 uncompressed point, is its public key.
    ///
    /// This suits a JWK's `d` and `x`/`y`; prefer [`Self::from_pkcs8`] for
    /// stored keys.
    pub fn from_private_key_and_public_key(
        algorithm: &'static EcdsaSigningAlgorithm,
        private_key: &[u8],
        public_key: &[u8],
    ) -> Result<Self, Error> {
        load_ecdsa!(
            algorithm,
            from_private_key_and_public_key(private_key, public_key)
        )
    }

    fn new<C: Curve>(
        algorithm: &'static EcdsaSigningAlgorithm,
        key: ecdsa::SigningKey<C>,
        variant: fn(ecdsa::SigningKey<C>, ecdsa::VerifyingKey<C>) -> EcdsaKey,
    ) -> Result<Self, Error> {
        let point = Buffer::copy_from(key.public_key_uncompressed())?;
        let public = ecdsa::VerifyingKey::from_x962_uncompressed(point.as_ref())?;
        Ok(Self {
            key: variant(key, public),
            algorithm: algorithm.0,
            point,
        })
    }

    /// Returns the public key, which verifies what this key pair signs.
    pub fn public_key(&self) -> PublicKey {
        let algorithm = self.algorithm;
        PublicKey {
            key: match &self.key {
                EcdsaKey::P256(_, key) => Parsed::EcdsaP256(key.clone(), algorithm),
                EcdsaKey::P384(_, key) => Parsed::EcdsaP384(key.clone(), algorithm),
                EcdsaKey::P521(_, key) => Parsed::EcdsaP521(key.clone(), algorithm),
            },
            encoding: self.point.widen(),
        }
    }

    /// Signs `message` with a fresh nonce.
    pub fn sign(&self, message: &[u8]) -> Result<Signature, Error> {
        Buffer::write(|output| {
            on_ecdsa!(self, |key| with_hash!(self.algorithm.hash, |H| {
                match self.algorithm.encoding {
                    EcdsaEncoding::Asn1 => key.sign_asn1::<H>(message, output),
                    EcdsaEncoding::Fixed => key.sign::<H>(message, output),
                }
            }))
        })
        .map(Signature)
    }

    /// Encodes the private key as PKCS#8.
    pub fn to_pkcs8(&self) -> Pkcs8 {
        Pkcs8(Buffer::encode(|output| {
            on_ecdsa!(self, |key| key.to_pkcs8_der(output))
        }))
    }

    /// Encodes the private key as a big-endian scalar exactly the curve's
    /// length, as a JWK's `d` and SEC1's `privateKey` hold it.
    ///
    /// This is what [`Self::from_private_key_and_public_key`] loads; prefer
    /// [`Self::to_pkcs8`] for stored keys.
    pub fn to_scalar(&self) -> EcdsaScalar {
        EcdsaScalar(Buffer::encode(|output| {
            on_ecdsa!(self, |key| key.to_scalar(output))
        }))
    }

    /// Encodes the public key as a `SubjectPublicKeyInfo`.
    pub fn to_spki(&self) -> Spki {
        Spki(Buffer::encode(|output| {
            on_ecdsa!(self, |key| key.to_spki_der(output))
        }))
    }
}

impl fmt::Debug for EcdsaKeyPair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EcdsaKeyPair")
            .field("algorithm", &self.algorithm)
            .field("public_key", &self.point.as_ref())
            .finish_non_exhaustive()
    }
}

// Every field is plain words or a `repr(u8)` enum with a variant at zero.
impl Zeroable for EcdsaKeyPair {}

impl Drop for EcdsaKeyPair {
    fn drop(&mut self) {
        // The key wipes its own scalar. Wiping the rest, which is not secret,
        // lets `tests/zeroing.rs` check every byte.
        low::zeroise_value(self);
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum RsaPadding {
    /// RSASSA-PKCS1-v1_5.
    Pkcs1,
    /// RSASSA-PSS, with MGF1 on the same hash and a salt of the hash's length.
    Pss,
}

#[derive(Clone, Copy, Debug)]
struct RsaScheme {
    padding: RsaPadding,
    hash: HashId,
}

impl RsaScheme {
    fn sign(self, key: &rsa::SigningKey, message: &[u8], out: &mut [u8]) -> Result<(), Error> {
        match (self.padding, self.hash) {
            (RsaPadding::Pkcs1, HashId::Sha256) => key.sign_pkcs1_sha256(out, message),
            (RsaPadding::Pkcs1, HashId::Sha384) => key.sign_pkcs1_sha384(out, message),
            (RsaPadding::Pkcs1, HashId::Sha512) => key.sign_pkcs1_sha512(out, message),
            (RsaPadding::Pss, HashId::Sha256) => key.sign_pss_sha256(out, message),
            (RsaPadding::Pss, HashId::Sha384) => key.sign_pss_sha384(out, message),
            (RsaPadding::Pss, HashId::Sha512) => key.sign_pss_sha512(out, message),
        }
        .map(|_| ())
    }

    fn verify(
        self,
        key: &rsa::VerifyingKey,
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), Error> {
        match (self.padding, self.hash) {
            (RsaPadding::Pkcs1, HashId::Sha256) => key.verify_pkcs1_sha256(signature, message),
            (RsaPadding::Pkcs1, HashId::Sha384) => key.verify_pkcs1_sha384(signature, message),
            (RsaPadding::Pkcs1, HashId::Sha512) => key.verify_pkcs1_sha512(signature, message),
            (RsaPadding::Pss, HashId::Sha256) => key.verify_pss_sha256(signature, message),
            (RsaPadding::Pss, HashId::Sha384) => key.verify_pss_sha384(signature, message),
            (RsaPadding::Pss, HashId::Sha512) => key.verify_pss_sha512(signature, message),
        }
    }
}

/// What an RSA verification algorithm verifies: a scheme rind also signs
/// with, or PKCS#1 v1.5 with SHA-1, which it only verifies.
#[derive(Clone, Copy, Debug)]
enum RsaVerification {
    Scheme(RsaScheme),
    Pkcs1Sha1,
}

impl RsaVerification {
    fn verify(
        self,
        key: &rsa::VerifyingKey,
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), Error> {
        match self {
            Self::Scheme(scheme) => scheme.verify(key, message, signature),
            Self::Pkcs1Sha1 => key.verify_pkcs1_sha1(signature, message),
        }
    }
}

/// An RSA verification algorithm: a padding, a hash, and the smallest
/// modulus it accepts.
#[derive(Clone, Copy, Debug)]
struct Rsa {
    verification: RsaVerification,
    min_bits: usize,
}

impl Rsa {
    /// Refuses `key` if its modulus is below this algorithm's floor.
    fn check(self, key: rsa::VerifyingKey) -> Result<rsa::VerifyingKey, Error> {
        match key.modulus_len_bits() >= self.min_bits {
            true => Ok(key),
            false => Err(KeyFormatError::RsaModulus.into()),
        }
    }
}

const fn rsa_verification(scheme: RsaScheme, min_bits: usize) -> RsaVerificationAlgorithm {
    rsa_algorithm(RsaVerification::Scheme(scheme), min_bits)
}

const fn rsa_sha1_verification(min_bits: usize) -> RsaVerificationAlgorithm {
    rsa_algorithm(RsaVerification::Pkcs1Sha1, min_bits)
}

const fn rsa_algorithm(verification: RsaVerification, min_bits: usize) -> RsaVerificationAlgorithm {
    let rsa = Rsa {
        verification,
        min_bits,
    };
    RsaVerificationAlgorithm {
        rsa,
        algorithm: VerificationAlgorithm(Verification::Rsa(rsa)),
    }
}

/// An RSA public key as its big-endian modulus and exponent, as a JWK
/// carries it, rather than DER.
#[derive(Clone, Copy, Debug)]
pub struct RsaPublicKeyComponents<B> {
    /// The modulus, without leading zero bytes.
    pub n: B,
    /// The public exponent, without leading zero bytes.
    pub e: B,
}

impl<B: AsRef<[u8]>> RsaPublicKeyComponents<B> {
    /// Parses this key for `algorithm`.
    pub fn to_public_key(
        &self,
        algorithm: &'static RsaVerificationAlgorithm,
    ) -> Result<PublicKey, Error> {
        let key = rsa::VerifyingKey::from_components(self.n.as_ref(), self.e.as_ref())?;
        PublicKey::rsa(algorithm.rsa, key)
    }
}

/// An RSA signing algorithm: a padding and a hash, for [`RsaKeyPair::sign`].
#[derive(Debug)]
pub struct RsaSigningAlgorithm(RsaScheme);

const PKCS1_SHA256: RsaScheme = RsaScheme {
    padding: RsaPadding::Pkcs1,
    hash: HashId::Sha256,
};
const PKCS1_SHA384: RsaScheme = RsaScheme {
    padding: RsaPadding::Pkcs1,
    hash: HashId::Sha384,
};
const PKCS1_SHA512: RsaScheme = RsaScheme {
    padding: RsaPadding::Pkcs1,
    hash: HashId::Sha512,
};
const PSS_SHA256: RsaScheme = RsaScheme {
    padding: RsaPadding::Pss,
    hash: HashId::Sha256,
};
const PSS_SHA384: RsaScheme = RsaScheme {
    padding: RsaPadding::Pss,
    hash: HashId::Sha384,
};
const PSS_SHA512: RsaScheme = RsaScheme {
    padding: RsaPadding::Pss,
    hash: HashId::Sha512,
};

/// The smallest modulus a verification algorithm accepts, unless it is
/// under [`verify::legacy`], and the smallest a key pair loads.
const RSA_MIN_BITS: usize = 2048;

/// A two-prime RSA private key, with a modulus of 2048 to 8192 bits, and its public key.
pub struct RsaKeyPair {
    key: rsa::SigningKey,
    public_key: RsaPublicKeyDer,
}

/// The public key's PKCS#1 DER.
// Aligned like the private key's words, so on 32-bit targets the key pair's
// padding falls inside this value, which `RsaKeyPair`'s drop wipes whole,
// rather than after it, where `tests/zeroing.rs` finds stale bytes.
#[derive(Clone, Copy)]
#[repr(align(8))]
struct RsaPublicKeyDer(Buffer<{ rsa::MAX_PUBLIC_KEY_LEN }>);

impl Zeroable for RsaPublicKeyDer {}

impl RsaKeyPair {
    /// Generates a key pair of `size` from the system random source.
    ///
    /// This is slow: about 30 milliseconds for 2048 bits, and 15 seconds or
    /// more for 8192 bits, with no upper bound. It is also not side-channel
    /// safe, so avoid it in untrusted multi-tenant or physical environments.
    pub fn generate(size: RsaKeySize) -> Result<Self, Error> {
        Self::new(rsa::SigningKey::generate(size)?)
    }

    /// Loads a PKCS#8 `rsaEncryption` private key.
    pub fn from_pkcs8(der: &[u8]) -> Result<Self, Error> {
        Self::new(rsa::SigningKey::from_pkcs8_der(der)?)
    }

    /// Loads a PKCS#1 `RSAPrivateKey`.
    pub fn from_pkcs1(der: &[u8]) -> Result<Self, Error> {
        Self::new(rsa::SigningKey::from_pkcs1_der(der)?)
    }

    fn new(key: rsa::SigningKey) -> Result<Self, Error> {
        let public_key = Buffer::write(|output| key.public_key().to_pkcs1_der(output))?;
        Ok(Self {
            key,
            public_key: RsaPublicKeyDer(public_key),
        })
    }

    /// Returns the public key, which verifies what this key pair signs with
    /// `algorithm`.
    ///
    /// Unlike an ECDSA key pair, an RSA key pair signs with any padding and
    /// hash, so the public key needs the one it verifies.
    pub fn public_key(&self, algorithm: &'static RsaSigningAlgorithm) -> PublicKey {
        // A key pair's modulus is at least `RSA_MIN_BITS`, the floor of the
        // algorithm that verifies `algorithm`'s signatures.
        PublicKey {
            key: Parsed::Rsa(self.key.public_key(), RsaVerification::Scheme(algorithm.0)),
            encoding: self.public_key.0,
        }
    }

    /// Signs `message` with `algorithm`, as long as the modulus.
    pub fn sign(
        &self,
        algorithm: &'static RsaSigningAlgorithm,
        message: &[u8],
    ) -> Result<Signature, Error> {
        Buffer::write(|output| {
            let output = output
                .get_mut(..self.key.modulus_len_bytes())
                .ok_or(Error::WrongLength)?;
            algorithm.0.sign(&self.key, message, output)?;
            Ok(output)
        })
        .map(Signature)
    }

    /// Encodes the private key as PKCS#8.
    pub fn to_pkcs8(&self) -> Pkcs8 {
        Pkcs8(Buffer::encode(|output| self.key.to_pkcs8_der(output)))
    }

    /// Encodes the public key as a `SubjectPublicKeyInfo`.
    pub fn to_spki(&self) -> Spki {
        Spki(Buffer::encode(|output| {
            self.key.public_key().to_spki_der(output)
        }))
    }
}

impl fmt::Debug for RsaKeyPair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RsaKeyPair")
            .field("public_key", &self.public_key.0.as_ref())
            .finish_non_exhaustive()
    }
}

impl Drop for RsaKeyPair {
    fn drop(&mut self) {
        // Not secret, but wiping it lets `tests/zeroing.rs` check every byte.
        low::zeroise_value(&mut self.public_key);
    }
}

/// An Ed25519 private key and its public key.
pub struct Ed25519KeyPair {
    key: Ed25519SigningKey,
    public_key: [u8; 32],
}

impl Ed25519KeyPair {
    /// Generates a key pair from the system random source.
    pub fn generate() -> Result<Self, Error> {
        Ok(Self::new(Ed25519SigningKey::generate()?))
    }

    /// Loads a PKCS#8 Ed25519 key, refused if it carries a public key
    /// (v2, RFC 5958) that does not match.
    ///
    /// This also takes PKCS#8 v1, which carries no public key: common tools
    /// write v1, and such a key is no less valid.
    pub fn from_pkcs8(der: &[u8]) -> Result<Self, Error> {
        Ok(Self::new(Ed25519SigningKey::from_pkcs8_der(der)?))
    }

    /// Loads a 32-byte seed, refused unless `public_key` is its public key.
    ///
    /// This suits a JWK's `d` and `x`.
    pub fn from_seed_and_public_key(seed: &[u8], public_key: &[u8]) -> Result<Self, Error> {
        let pair = Self::new(Ed25519SigningKey::from_bytes(seed)?);
        match pair.public_key.as_slice() == public_key {
            true => Ok(pair),
            false => Err(KeyFormatError::MismatchedPublicKey.into()),
        }
    }

    fn new(key: Ed25519SigningKey) -> Self {
        let public_key = key.public_key().as_bytes();
        Self { key, public_key }
    }

    /// Returns the public key, which verifies what this key pair signs.
    pub fn public_key(&self) -> PublicKey {
        PublicKey {
            key: Parsed::Ed25519(self.key.public_key()),
            encoding: Buffer::from(self.public_key).widen(),
        }
    }

    /// Signs `message`.
    pub fn sign(&self, message: &[u8]) -> Signature {
        Signature(Buffer::from(self.key.sign(message)).widen())
    }

    /// Encodes the key pair as PKCS#8 v2 (RFC 5958).
    pub fn to_pkcs8(&self) -> Pkcs8 {
        Pkcs8(Buffer::encode(|output| self.key.to_pkcs8_der(output)))
    }

    /// Returns the private key's 32-byte seed, as a JWK's `d` holds it.
    ///
    /// This is what [`Self::from_seed_and_public_key`] loads; prefer
    /// [`Self::to_pkcs8`] for stored keys.
    pub fn to_seed(&self) -> Ed25519Seed {
        Ed25519Seed(*self.key.seed())
    }

    /// Encodes the public key as a `SubjectPublicKeyInfo`.
    pub fn to_spki(&self) -> Spki {
        Spki(Buffer::encode(|output| {
            self.key.public_key().to_spki_der(output)
        }))
    }
}

impl fmt::Debug for Ed25519KeyPair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ed25519KeyPair")
            .field("public_key", &self.public_key)
            .finish_non_exhaustive()
    }
}

impl Drop for Ed25519KeyPair {
    fn drop(&mut self) {
        // Not secret, but wiping it lets `tests/zeroing.rs` check every byte.
        low::zeroise(&mut self.public_key);
    }
}

/// Algorithms a key pair signs with.
pub(crate) mod sign {
    use super::*;

    /// ECDSA on P-256 with SHA-256, ASN.1 signatures.
    pub static ECDSA_P256_SHA256_ASN1: EcdsaSigningAlgorithm =
        ecdsa_signing(&verify::ECDSA_P256_SHA256_ASN1);

    /// ECDSA on P-384 with SHA-384, ASN.1 signatures.
    pub static ECDSA_P384_SHA384_ASN1: EcdsaSigningAlgorithm =
        ecdsa_signing(&verify::ECDSA_P384_SHA384_ASN1);

    /// ECDSA on P-521 with SHA-512, ASN.1 signatures.
    pub static ECDSA_P521_SHA512_ASN1: EcdsaSigningAlgorithm =
        ecdsa_signing(&verify::ECDSA_P521_SHA512_ASN1);

    /// ECDSA on P-256 with SHA-256, fixed-length `r || s` signatures (JWS's ES256).
    pub static ECDSA_P256_SHA256_FIXED: EcdsaSigningAlgorithm =
        ecdsa_signing(&verify::ECDSA_P256_SHA256_FIXED);

    /// ECDSA on P-384 with SHA-384, fixed-length `r || s` signatures (JWS's ES384).
    pub static ECDSA_P384_SHA384_FIXED: EcdsaSigningAlgorithm =
        ecdsa_signing(&verify::ECDSA_P384_SHA384_FIXED);

    /// ECDSA on P-521 with SHA-512, fixed-length `r || s` signatures (JWS's ES512).
    pub static ECDSA_P521_SHA512_FIXED: EcdsaSigningAlgorithm =
        ecdsa_signing(&verify::ECDSA_P521_SHA512_FIXED);

    /// RSASSA-PKCS1-v1_5 with SHA-256.
    pub static RSA_PKCS1_SHA256: RsaSigningAlgorithm = RsaSigningAlgorithm(PKCS1_SHA256);

    /// RSASSA-PKCS1-v1_5 with SHA-384.
    pub static RSA_PKCS1_SHA384: RsaSigningAlgorithm = RsaSigningAlgorithm(PKCS1_SHA384);

    /// RSASSA-PKCS1-v1_5 with SHA-512.
    pub static RSA_PKCS1_SHA512: RsaSigningAlgorithm = RsaSigningAlgorithm(PKCS1_SHA512);

    /// RSASSA-PSS with SHA-256, MGF1-SHA-256, and a 32-byte salt.
    pub static RSA_PSS_SHA256: RsaSigningAlgorithm = RsaSigningAlgorithm(PSS_SHA256);

    /// RSASSA-PSS with SHA-384, MGF1-SHA-384, and a 48-byte salt.
    pub static RSA_PSS_SHA384: RsaSigningAlgorithm = RsaSigningAlgorithm(PSS_SHA384);

    /// RSASSA-PSS with SHA-512, MGF1-SHA-512, and a 64-byte salt.
    pub static RSA_PSS_SHA512: RsaSigningAlgorithm = RsaSigningAlgorithm(PSS_SHA512);
}

/// Algorithms a public key verifies with.
pub(crate) mod verify {
    use super::*;

    /// ECDSA on P-256 with SHA-256, ASN.1 signatures.
    pub static ECDSA_P256_SHA256_ASN1: VerificationAlgorithm =
        ecdsa_verification(CurveId::P256, HashId::Sha256, EcdsaEncoding::Asn1);

    /// ECDSA on P-256 with SHA-384, ASN.1 signatures.
    pub static ECDSA_P256_SHA384_ASN1: VerificationAlgorithm =
        ecdsa_verification(CurveId::P256, HashId::Sha384, EcdsaEncoding::Asn1);

    /// ECDSA on P-256 with SHA-512, ASN.1 signatures.
    pub static ECDSA_P256_SHA512_ASN1: VerificationAlgorithm =
        ecdsa_verification(CurveId::P256, HashId::Sha512, EcdsaEncoding::Asn1);

    /// ECDSA on P-384 with SHA-256, ASN.1 signatures.
    pub static ECDSA_P384_SHA256_ASN1: VerificationAlgorithm =
        ecdsa_verification(CurveId::P384, HashId::Sha256, EcdsaEncoding::Asn1);

    /// ECDSA on P-384 with SHA-384, ASN.1 signatures.
    pub static ECDSA_P384_SHA384_ASN1: VerificationAlgorithm =
        ecdsa_verification(CurveId::P384, HashId::Sha384, EcdsaEncoding::Asn1);

    /// ECDSA on P-384 with SHA-512, ASN.1 signatures.
    pub static ECDSA_P384_SHA512_ASN1: VerificationAlgorithm =
        ecdsa_verification(CurveId::P384, HashId::Sha512, EcdsaEncoding::Asn1);

    /// ECDSA on P-521 with SHA-256, ASN.1 signatures.
    pub static ECDSA_P521_SHA256_ASN1: VerificationAlgorithm =
        ecdsa_verification(CurveId::P521, HashId::Sha256, EcdsaEncoding::Asn1);

    /// ECDSA on P-521 with SHA-384, ASN.1 signatures.
    pub static ECDSA_P521_SHA384_ASN1: VerificationAlgorithm =
        ecdsa_verification(CurveId::P521, HashId::Sha384, EcdsaEncoding::Asn1);

    /// ECDSA on P-521 with SHA-512, ASN.1 signatures.
    pub static ECDSA_P521_SHA512_ASN1: VerificationAlgorithm =
        ecdsa_verification(CurveId::P521, HashId::Sha512, EcdsaEncoding::Asn1);

    /// ECDSA on P-256 with SHA-256, fixed-length `r || s` signatures (JWS's ES256).
    pub static ECDSA_P256_SHA256_FIXED: VerificationAlgorithm =
        ecdsa_verification(CurveId::P256, HashId::Sha256, EcdsaEncoding::Fixed);

    /// ECDSA on P-384 with SHA-384, fixed-length `r || s` signatures (JWS's ES384).
    pub static ECDSA_P384_SHA384_FIXED: VerificationAlgorithm =
        ecdsa_verification(CurveId::P384, HashId::Sha384, EcdsaEncoding::Fixed);

    /// ECDSA on P-521 with SHA-512, fixed-length `r || s` signatures (JWS's ES512).
    pub static ECDSA_P521_SHA512_FIXED: VerificationAlgorithm =
        ecdsa_verification(CurveId::P521, HashId::Sha512, EcdsaEncoding::Fixed);

    /// RSASSA-PKCS1-v1_5 with SHA-256, for moduli of 2048 to 8192 bits.
    pub static RSA_PKCS1_SHA256: RsaVerificationAlgorithm =
        rsa_verification(PKCS1_SHA256, RSA_MIN_BITS);

    /// RSASSA-PKCS1-v1_5 with SHA-384, for moduli of 2048 to 8192 bits.
    pub static RSA_PKCS1_SHA384: RsaVerificationAlgorithm =
        rsa_verification(PKCS1_SHA384, RSA_MIN_BITS);

    /// RSASSA-PKCS1-v1_5 with SHA-512, for moduli of 2048 to 8192 bits.
    pub static RSA_PKCS1_SHA512: RsaVerificationAlgorithm =
        rsa_verification(PKCS1_SHA512, RSA_MIN_BITS);

    /// RSASSA-PSS with SHA-256, MGF1-SHA-256, and a 32-byte salt, for moduli of 2048 to 8192 bits.
    pub static RSA_PSS_SHA256: RsaVerificationAlgorithm =
        rsa_verification(PSS_SHA256, RSA_MIN_BITS);

    /// RSASSA-PSS with SHA-384, MGF1-SHA-384, and a 48-byte salt, for moduli of 2048 to 8192 bits.
    pub static RSA_PSS_SHA384: RsaVerificationAlgorithm =
        rsa_verification(PSS_SHA384, RSA_MIN_BITS);

    /// RSASSA-PSS with SHA-512, MGF1-SHA-512, and a 64-byte salt, for moduli of 2048 to 8192 bits.
    pub static RSA_PSS_SHA512: RsaVerificationAlgorithm =
        rsa_verification(PSS_SHA512, RSA_MIN_BITS);

    /// Ed25519, with 32-byte public keys and 64-byte signatures.
    ///
    /// See [RFC8032](https://datatracker.ietf.org/doc/html/rfc8032).
    pub static ED25519: VerificationAlgorithm = VerificationAlgorithm(Verification::Ed25519);

    /// Verification algorithms with a modulus floor other than 2048 bits, or SHA-1.
    pub(crate) mod legacy {
        use super::super::*;

        /// RSASSA-PKCS1-v1_5 with SHA-1, for old signatures only: SHA-1 collisions are practical.
        pub static RSA_PKCS1_SHA1: RsaVerificationAlgorithm = rsa_sha1_verification(RSA_MIN_BITS);

        /// RSASSA-PKCS1-v1_5 with SHA-1, for old signatures by keys with moduli down to 1024 bits.
        pub static RSA_PKCS1_1024_SHA1: RsaVerificationAlgorithm = rsa_sha1_verification(1024);

        /// RSASSA-PKCS1-v1_5 with SHA-256, for old keys with moduli down to 1024 bits.
        pub static RSA_PKCS1_1024_SHA256: RsaVerificationAlgorithm =
            rsa_verification(PKCS1_SHA256, 1024);

        /// RSASSA-PKCS1-v1_5 with SHA-512, for old keys with moduli down to 1024 bits.
        pub static RSA_PKCS1_1024_SHA512: RsaVerificationAlgorithm =
            rsa_verification(PKCS1_SHA512, 1024);

        /// RSASSA-PKCS1-v1_5 with SHA-384, for moduli of 3072 to 8192 bits.
        pub static RSA_PKCS1_3072_SHA384: RsaVerificationAlgorithm =
            rsa_verification(PKCS1_SHA384, 3072);
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::high::asn1::{Type, pkix};

    const ECDSA_SIGNING: [&EcdsaSigningAlgorithm; 6] = [
        &sign::ECDSA_P256_SHA256_ASN1,
        &sign::ECDSA_P256_SHA256_FIXED,
        &sign::ECDSA_P384_SHA384_ASN1,
        &sign::ECDSA_P384_SHA384_FIXED,
        &sign::ECDSA_P521_SHA512_ASN1,
        &sign::ECDSA_P521_SHA512_FIXED,
    ];

    fn rejected(result: Result<impl fmt::Debug, Error>) -> Error {
        result.expect_err("accepted")
    }

    #[test]
    fn ecdsa_verifies_only_under_its_algorithm() {
        let verification = [
            &verify::ECDSA_P256_SHA256_ASN1,
            &verify::ECDSA_P256_SHA256_FIXED,
            &verify::ECDSA_P384_SHA384_ASN1,
            &verify::ECDSA_P384_SHA384_FIXED,
            &verify::ECDSA_P521_SHA512_ASN1,
            &verify::ECDSA_P521_SHA512_FIXED,
        ];
        for (i, signing) in ECDSA_SIGNING.into_iter().enumerate() {
            let pair = EcdsaKeyPair::generate(signing).unwrap();
            let signature = pair.sign(b"message").unwrap();
            let encoded = pair.public_key();
            for (j, algorithm) in verification.into_iter().enumerate() {
                let result = PublicKey::new(algorithm, encoded.as_ref())
                    .and_then(|key| key.verify(b"message", signature.as_ref()));
                assert_eq!(result.is_ok(), i == j, "{signing:?} {algorithm:?}");
            }
            encoded.verify(b"message", signature.as_ref()).unwrap();
            assert_eq!(
                encoded.verify(b"other", signature.as_ref()),
                Err(Error::BadSignature)
            );
        }
    }

    // Signing as a verify-only constant, such as a cross-hash pair, needs
    // crate access, so this differential test lives here rather than in
    // `tests/crosschecks.rs`. Wycheproof has no P-256 with SHA-384 vectors,
    // nor P-521 with SHA-256 or SHA-384.
    #[test]
    fn ecdsa_verification_matches_aws_lc_rs() {
        use aws_lc_rs::signature as theirs;

        let algorithms: [(_, &'static theirs::EcdsaVerificationAlgorithm); 12] = [
            (
                &verify::ECDSA_P256_SHA256_ASN1,
                &theirs::ECDSA_P256_SHA256_ASN1,
            ),
            (
                &verify::ECDSA_P256_SHA384_ASN1,
                &theirs::ECDSA_P256_SHA384_ASN1,
            ),
            (
                &verify::ECDSA_P256_SHA512_ASN1,
                &theirs::ECDSA_P256_SHA512_ASN1,
            ),
            (
                &verify::ECDSA_P384_SHA256_ASN1,
                &theirs::ECDSA_P384_SHA256_ASN1,
            ),
            (
                &verify::ECDSA_P384_SHA384_ASN1,
                &theirs::ECDSA_P384_SHA384_ASN1,
            ),
            (
                &verify::ECDSA_P384_SHA512_ASN1,
                &theirs::ECDSA_P384_SHA512_ASN1,
            ),
            (
                &verify::ECDSA_P521_SHA256_ASN1,
                &theirs::ECDSA_P521_SHA256_ASN1,
            ),
            (
                &verify::ECDSA_P521_SHA384_ASN1,
                &theirs::ECDSA_P521_SHA384_ASN1,
            ),
            (
                &verify::ECDSA_P521_SHA512_ASN1,
                &theirs::ECDSA_P521_SHA512_ASN1,
            ),
            (
                &verify::ECDSA_P256_SHA256_FIXED,
                &theirs::ECDSA_P256_SHA256_FIXED,
            ),
            (
                &verify::ECDSA_P384_SHA384_FIXED,
                &theirs::ECDSA_P384_SHA384_FIXED,
            ),
            (
                &verify::ECDSA_P521_SHA512_FIXED,
                &theirs::ECDSA_P521_SHA512_FIXED,
            ),
        ];
        for (ours, theirs) in algorithms {
            let signing = Box::leak(Box::new(ecdsa_signing(ours)));
            let pair = EcdsaKeyPair::generate(signing).unwrap();
            let signature = pair.sign(b"message").unwrap();
            let encoded = pair.public_key();
            theirs::UnparsedPublicKey::new(theirs, encoded.as_ref())
                .verify(b"message", signature.as_ref())
                .unwrap_or_else(|_| panic!("aws-lc-rs refused {ours:?}"));

            let verifier = PublicKey::new(ours, encoded.as_ref()).unwrap();
            verifier.verify(b"message", signature.as_ref()).unwrap();
            assert_eq!(
                verifier.verify(b"other", signature.as_ref()),
                Err(Error::BadSignature)
            );
        }
    }

    #[test]
    fn public_key_refuses_malformed_keys() {
        let pair = EcdsaKeyPair::generate(&sign::ECDSA_P256_SHA256_ASN1).unwrap();
        let encoded = pair.public_key();
        let point = encoded.as_ref();

        let malformed: [(&'static VerificationAlgorithm, &[u8]); 4] = [
            (&verify::ECDSA_P256_SHA256_ASN1, &point[1..]),
            (&verify::ECDSA_P384_SHA384_ASN1, point),
            (&verify::ED25519, &point[..31]),
            (verify::RSA_PKCS1_SHA256.as_ref(), point),
        ];
        for (algorithm, bytes) in malformed {
            assert!(PublicKey::new(algorithm, bytes).is_err(), "{algorithm:?}");
        }

        // An Ed25519 encoding of the right length but off the curve.
        let off_curve = PublicKey::new(&verify::ED25519, &[0xff; 32]);
        assert_eq!(off_curve.err(), Some(KeyFormatError::NotOnCurve.into()));
    }

    #[test]
    fn ecdsa_private_key_round_trips() {
        for signing in ECDSA_SIGNING {
            let pair = EcdsaKeyPair::generate(signing).unwrap();
            let len = match signing.0.curve {
                CurveId::P256 => 32,
                CurveId::P384 => 48,
                CurveId::P521 => 66,
            };
            // The scalar stays secret, so ctgrind checks the copy out and the
            // load back in.
            let scalar = pair.to_scalar();
            let scalar = scalar.as_ref();
            assert_eq!(scalar.len(), len);

            let encoded = pair.public_key();
            let public = encoded.as_ref();
            let reloaded =
                EcdsaKeyPair::from_private_key_and_public_key(signing, scalar, public).unwrap();
            assert_eq!(reloaded.public_key().as_ref(), public);
            assert_eq!(reloaded.to_pkcs8().as_ref(), pair.to_pkcs8().as_ref());

            // The scalar must be exactly the curve's length, even with a zero
            // byte added or removed.
            let padded = [&[0][..], scalar].concat();
            assert_eq!(
                rejected(EcdsaKeyPair::from_private_key_and_public_key(
                    signing, &padded, public
                )),
                KeyFormatError::WrongLength.into()
            );
            assert_eq!(
                rejected(EcdsaKeyPair::from_private_key_and_public_key(
                    signing,
                    &scalar[1..],
                    public
                )),
                KeyFormatError::WrongLength.into()
            );

            // Zero and anything at or above the order are refused.
            let zero = [0u8; MAX_SCALAR_LEN];
            assert_eq!(
                rejected(EcdsaKeyPair::from_private_key_and_public_key(
                    signing,
                    &zero[..len],
                    public
                )),
                KeyFormatError::ScalarOutOfRange.into()
            );
            let ones = [0xffu8; MAX_SCALAR_LEN];
            assert_eq!(
                rejected(EcdsaKeyPair::from_private_key_and_public_key(
                    signing,
                    &ones[..len],
                    public
                )),
                KeyFormatError::ScalarOutOfRange.into()
            );

            // Another key's point, or the point truncated, is refused.
            let other = EcdsaKeyPair::generate(signing).unwrap().public_key();
            for public in [other.as_ref(), &public[..public.len() - 1]] {
                assert_eq!(
                    rejected(EcdsaKeyPair::from_private_key_and_public_key(
                        signing, scalar, public
                    )),
                    KeyFormatError::MismatchedPublicKey.into()
                );
            }
        }
    }

    #[test]
    fn ecdsa_key_is_bound_to_its_curve() {
        let p256 = include_bytes!("ecdsa/secp256r1.pkcs8.der");
        let p384 = include_bytes!("ecdsa/secp384r1.pkcs8.der");
        let p521 = include_bytes!("ecdsa/secp521r1.pkcs8.der");
        EcdsaKeyPair::from_pkcs8(&sign::ECDSA_P256_SHA256_ASN1, p256).unwrap();
        EcdsaKeyPair::from_pkcs8(&sign::ECDSA_P384_SHA384_ASN1, p384).unwrap();
        EcdsaKeyPair::from_pkcs8(&sign::ECDSA_P521_SHA512_ASN1, p521).unwrap();
        assert!(EcdsaKeyPair::from_pkcs8(&sign::ECDSA_P256_SHA256_ASN1, p384).is_err());
        assert!(EcdsaKeyPair::from_pkcs8(&sign::ECDSA_P384_SHA384_ASN1, p256).is_err());
        assert!(EcdsaKeyPair::from_pkcs8(&sign::ECDSA_P384_SHA384_ASN1, p521).is_err());
        assert!(EcdsaKeyPair::from_pkcs8(&sign::ECDSA_P521_SHA512_ASN1, p384).is_err());

        let p256 = include_bytes!("ecdsa/secp256r1.der");
        let p384 = include_bytes!("ecdsa/secp384r1.der");
        EcdsaKeyPair::from_sec1(&sign::ECDSA_P256_SHA256_ASN1, p256).unwrap();
        assert!(EcdsaKeyPair::from_sec1(&sign::ECDSA_P256_SHA256_ASN1, p384).is_err());

        // A P-384 point is the wrong length for a P-256 key.
        let pair = EcdsaKeyPair::from_pkcs8(
            &sign::ECDSA_P384_SHA384_ASN1,
            include_bytes!("ecdsa/secp384r1.pkcs8.der"),
        )
        .unwrap();
        assert_eq!(
            rejected(PublicKey::new(
                &verify::ECDSA_P256_SHA384_ASN1,
                pair.public_key().as_ref()
            )),
            KeyFormatError::WrongLength.into()
        );
    }

    #[test]
    fn rsa_signs_as_long_as_the_modulus() {
        let pair = RsaKeyPair::from_pkcs1(include_bytes!("rsa/rsa2048.der")).unwrap();
        let signature = pair.sign(&sign::RSA_PSS_SHA256, b"message").unwrap();
        assert_eq!(signature.as_ref().len(), 256);

        let public_key = pair.public_key(&sign::RSA_PSS_SHA256);
        public_key.verify(b"message", signature.as_ref()).unwrap();
        assert_eq!(
            public_key.verify(b"other", signature.as_ref()),
            Err(Error::BadSignature)
        );
        assert_eq!(
            pair.public_key(&sign::RSA_PKCS1_SHA256)
                .verify(b"message", signature.as_ref()),
            Err(Error::BadSignature)
        );

        // The encoding parses for the verification algorithm of the same name.
        PublicKey::new(&verify::RSA_PSS_SHA256, public_key.as_ref())
            .unwrap()
            .verify(b"message", signature.as_ref())
            .unwrap();
    }

    #[test]
    fn rsa_public_key_components() {
        let pair = RsaKeyPair::from_pkcs1(include_bytes!("rsa/rsa2048.der")).unwrap();
        let signature = pair.sign(&sign::RSA_PKCS1_SHA256, b"message").unwrap();
        let signature = signature.as_ref();

        let der = pair.public_key(&sign::RSA_PKCS1_SHA256);
        let parsed = pkix::RSAPublicKey::from_bytes(der.as_ref()).unwrap();
        let n = parsed.modulus.as_ref().strip_prefix(&[0]).unwrap();
        let e = parsed.publicExponent.as_ref();
        let key = RsaPublicKeyComponents { n, e };
        for algorithm in [
            &verify::RSA_PKCS1_SHA256,
            &verify::legacy::RSA_PKCS1_1024_SHA256,
        ] {
            let public_key = key.to_public_key(algorithm).unwrap();
            assert_eq!(public_key.as_ref(), der.as_ref());
            public_key.verify(b"message", signature).unwrap();
            assert_eq!(
                public_key.verify(b"other", signature),
                Err(Error::BadSignature)
            );
        }
        for algorithm in [
            &verify::legacy::RSA_PKCS1_SHA1,
            &verify::legacy::RSA_PKCS1_1024_SHA512,
        ] {
            assert_eq!(
                key.to_public_key(algorithm)
                    .unwrap()
                    .verify(b"message", signature),
                Err(Error::BadSignature)
            );
        }

        // A 2048-bit key is below this algorithm's floor, in either form.
        assert_eq!(
            rejected(key.to_public_key(&verify::legacy::RSA_PKCS1_3072_SHA384)),
            KeyFormatError::RsaModulus.into()
        );
        assert_eq!(
            rejected(PublicKey::new(
                &verify::legacy::RSA_PKCS1_3072_SHA384,
                der.as_ref()
            )),
            KeyFormatError::RsaModulus.into()
        );

        let n0 = [&[0], n].concat();
        let e0 = [&[0], e].concat();
        let malformed: [(&[u8], &[u8], Error); 5] = [
            (&n0, e, KeyFormatError::LeadingZero.into()),
            (n, &e0, KeyFormatError::LeadingZero.into()),
            (n, &[1, 0, 0, 0, 1], KeyFormatError::RsaExponent.into()),
            (&[], e, KeyFormatError::RsaModulus.into()),
            (n, &[], KeyFormatError::RsaExponent.into()),
        ];
        for (n, e, expected) in malformed {
            let key = RsaPublicKeyComponents { n, e };
            assert_eq!(
                rejected(key.to_public_key(&verify::RSA_PKCS1_SHA256)),
                expected
            );
        }
    }

    #[test]
    fn ed25519_seed_and_public_key() {
        let seed = [7u8; 32];
        let public = Ed25519SigningKey::from_bytes(&seed)
            .unwrap()
            .public_key()
            .as_bytes();
        let pair = Ed25519KeyPair::from_seed_and_public_key(&seed, &public).unwrap();
        let encoded = pair.public_key();
        assert_eq!(encoded.as_ref(), public);
        let signature = pair.sign(b"message");
        assert_eq!(signature.as_ref().len(), 64);
        encoded.verify(b"message", signature.as_ref()).unwrap();

        let other = Ed25519KeyPair::generate().unwrap().public_key();
        for public in [other.as_ref(), &public[..31]] {
            assert_eq!(
                rejected(Ed25519KeyPair::from_seed_and_public_key(&seed, public)),
                KeyFormatError::MismatchedPublicKey.into()
            );
        }
        for seed in [&seed[..31], &[seed.as_slice(), &[0]].concat()] {
            assert_eq!(
                rejected(Ed25519KeyPair::from_seed_and_public_key(seed, &public)),
                KeyFormatError::WrongLength.into()
            );
        }
    }

    #[test]
    fn ed25519_seed_round_trips() {
        // The seed stays secret, so ctgrind checks the copy out and the load
        // back in.
        let pair = Ed25519KeyPair::generate().unwrap();
        let seed = pair.to_seed();
        let public = pair.public_key();
        let reloaded =
            Ed25519KeyPair::from_seed_and_public_key(seed.as_ref(), public.as_ref()).unwrap();
        assert_eq!(reloaded.to_pkcs8().as_ref(), pair.to_pkcs8().as_ref());
    }

    // The owned encodings are sized for the largest key each loader takes,
    // so encoding one must not run out of room.
    #[test]
    fn encodings_fit_the_largest_keys() {
        let rsa = RsaKeyPair::from_pkcs1(include_bytes!("rsa/rsa8192.der")).unwrap();
        let pkcs8 = rsa.to_pkcs8();
        assert_eq!(pkcs8.as_ref(), include_bytes!("rsa/rsa8192.pkcs8.der"));
        let spki = rsa.to_spki();
        let parsed = pkix::SubjectPublicKeyInfo::from_bytes(spki.as_ref()).unwrap();
        let encoded = rsa.public_key(&sign::RSA_PSS_SHA512);
        assert_eq!(parsed.subjectPublicKey.as_octets(), encoded.as_ref());
        let signature = rsa.sign(&sign::RSA_PSS_SHA512, b"message").unwrap();
        assert_eq!(signature.as_ref().len(), 1024);
        encoded.verify(b"message", signature.as_ref()).unwrap();

        let p521 = include_bytes!("ecdsa/secp521r1.pkcs8.der");
        let ecdsa = EcdsaKeyPair::from_pkcs8(&sign::ECDSA_P521_SHA512_ASN1, p521).unwrap();
        let reloaded =
            EcdsaKeyPair::from_pkcs8(&sign::ECDSA_P521_SHA512_ASN1, ecdsa.to_pkcs8().as_ref())
                .unwrap();
        assert_eq!(reloaded.public_key().as_ref(), ecdsa.public_key().as_ref());
        let spki = ecdsa.to_spki();
        let parsed = pkix::SubjectPublicKeyInfo::from_bytes(spki.as_ref()).unwrap();
        assert_eq!(
            parsed.subjectPublicKey.as_octets(),
            ecdsa.public_key().as_ref()
        );

        let ed25519 = Ed25519KeyPair::generate().unwrap();
        let reloaded = Ed25519KeyPair::from_pkcs8(ed25519.to_pkcs8().as_ref()).unwrap();
        assert_eq!(
            reloaded.public_key().as_ref(),
            ed25519.public_key().as_ref()
        );
        let spki = ed25519.to_spki();
        let parsed = pkix::SubjectPublicKeyInfo::from_bytes(spki.as_ref()).unwrap();
        assert_eq!(
            parsed.subjectPublicKey.as_octets(),
            ed25519.public_key().as_ref()
        );
    }
}
