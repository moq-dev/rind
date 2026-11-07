// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

use core::fmt;

use super::asn1::{self, Type};
use super::curve::{self, Curve, MAX_SCALAR_LEN};
use super::pkcs8;
use super::sec1;
use super::signature::{Buffer, Pkcs8, Spki};
use super::spki;
use crate::error::{Error, KeyFormatError};
use crate::low;
use crate::mid::{p256, p384, p521, x25519};

/// A key agreement algorithm: a curve and its public key encoding.
pub struct Algorithm {
    id: AlgorithmId,
    // The only paths to the curve's code, so a binary links only the curves
    // whose algorithms it names.
    generate: fn() -> Result<Private, Error>,
    load: fn(Source<'_>) -> Result<Private, Error>,
    parse_public: fn(&[u8]) -> Result<PublicKey, Error>,
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum AlgorithmId {
    X25519,
    EcdhP256,
    EcdhP384,
    EcdhP521,
}

impl fmt::Debug for Algorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.id.fmt(f)
    }
}

/// X25519, with 32-byte public keys.
///
/// See [RFC7748](https://datatracker.ietf.org/doc/html/rfc7748).
pub static X25519: Algorithm = Algorithm {
    id: AlgorithmId::X25519,
    generate: Keyed::<x25519::PrivateKey>::generate,
    load: Keyed::<x25519::PrivateKey>::load,
    parse_public: x25519_public_key,
};

/// ECDH on P-256, with X9.62 uncompressed public keys.
///
/// [`PublicKey::new`] also takes compressed ones.
///
/// P-256 is also known as "NISTP256", "prime256v1", or "secp256r1".
pub static ECDH_P256: Algorithm = Algorithm {
    id: AlgorithmId::EcdhP256,
    generate: Keyed::<p256::PrivateKey>::generate,
    load: Keyed::<p256::PrivateKey>::load,
    parse_public: p256_public_key,
};

/// ECDH on P-384, with X9.62 uncompressed public keys.
///
/// [`PublicKey::new`] also takes compressed ones.
///
/// P-384 is also known as "NISTP384", or "secp384r1".
pub static ECDH_P384: Algorithm = Algorithm {
    id: AlgorithmId::EcdhP384,
    generate: Keyed::<p384::PrivateKey>::generate,
    load: Keyed::<p384::PrivateKey>::load,
    parse_public: p384_public_key,
};

/// ECDH on P-521, with X9.62 uncompressed public keys.
///
/// [`PublicKey::new`] also takes compressed ones.
///
/// P-521 is also known as "NISTP521", or "secp521r1".
pub static ECDH_P521: Algorithm = Algorithm {
    id: AlgorithmId::EcdhP521,
    generate: Keyed::<p521::PrivateKey>::generate,
    load: Keyed::<p521::PrivateKey>::load,
    parse_public: p521_public_key,
};

/// A private key, which agrees with any number of peers, wiped on drop under the `wipe` feature.
pub struct PrivateKey(Private);

// `repr(u8)` puts `X25519` at tag zero, and every variant's key is plain
// words beside a `ZeroableRef`, so all-bits-zero is a valid value and `Drop`
// can wipe the tag and any unused tail along with the key.
#[repr(u8)]
enum Private {
    X25519(Keyed<x25519::PrivateKey>),
    P256(Keyed<p256::PrivateKey>),
    P384(Keyed<p384::PrivateKey>),
    P521(Keyed<p521::PrivateKey>),
}

impl low::Zeroable for Private {}

/// An encoded private key, as one of [`PrivateKey`]'s loaders takes it.
enum Source<'a> {
    Scalar(&'a [u8]),
    Pkcs8(&'a [u8]),
    Sec1(&'a [u8]),
}

impl PrivateKey {
    /// Generates a private key for `algorithm` from the system random source.
    pub fn generate(algorithm: &'static Algorithm) -> Result<Self, Error> {
        Ok(Self((algorithm.generate)()?))
    }

    /// Loads a private key for `algorithm` from its scalar: X25519's 32
    /// bytes, any value, or a NIST curve's big-endian scalar, exactly the
    /// curve's length and refused unless it is from 1 to n - 1.
    ///
    /// This suits a JWK's `d`; prefer [`Self::from_pkcs8`] for stored keys.
    pub fn from_scalar(algorithm: &'static Algorithm, scalar: &[u8]) -> Result<Self, Error> {
        Ok(Self((algorithm.load)(Source::Scalar(scalar))?))
    }

    /// Loads a PKCS#8 private key for `algorithm`.
    ///
    /// X25519 takes RFC 8410's, v1 or v2, refused if a v2 public key does
    /// not match; a NIST curve takes v1 `ECPrivateKey` on its curve, as
    /// [`EcdsaKeyPair::from_pkcs8`](crate::signature::EcdsaKeyPair::from_pkcs8)
    /// does.
    pub fn from_pkcs8(algorithm: &'static Algorithm, der: &[u8]) -> Result<Self, Error> {
        Ok(Self((algorithm.load)(Source::Pkcs8(der))?))
    }

    /// Loads a SEC1 (RFC 5915) `ECPrivateKey` on `algorithm`'s curve, as
    /// [`EcdsaKeyPair::from_sec1`](crate::signature::EcdsaKeyPair::from_sec1)
    /// does.
    ///
    /// X25519 has no SEC1 encoding, so it refuses every key.
    pub fn from_sec1(algorithm: &'static Algorithm, der: &[u8]) -> Result<Self, Error> {
        Ok(Self((algorithm.load)(Source::Sec1(der))?))
    }

    /// Returns the public key to send to the peer.
    pub fn public_key(&self) -> PublicKey {
        match &self.0 {
            Private::X25519(key) => key.public_key(),
            Private::P256(key) => key.public_key(),
            Private::P384(key) => key.public_key(),
            Private::P521(key) => key.public_key(),
        }
    }

    /// Agrees on a secret with the peer's encoded public key.
    ///
    /// The peer's key is parsed for this key's algorithm, and refused if it
    /// is malformed or off the curve, and so is X25519's all-zero output from
    /// a small-order point
    /// ([RFC7748 section 6.1](https://datatracker.ietf.org/doc/html/rfc7748#section-6.1)).
    /// A NIST curve's key is an uncompressed point, as TLS sends it;
    /// [`PublicKey::new`] decompresses a compressed one.
    pub fn agree(&self, peer: &[u8]) -> Result<SharedSecret, Error> {
        Ok(SharedSecret(match &self.0 {
            Private::X25519(key) => key.agree(peer),
            Private::P256(key) => key.agree(peer),
            Private::P384(key) => key.agree(peer),
            Private::P521(key) => key.agree(peer),
        }?))
    }

    /// Encodes the private key as PKCS#8: v1 for X25519, and for a NIST
    /// curve as [`EcdsaKeyPair::to_pkcs8`](crate::signature::EcdsaKeyPair::to_pkcs8)
    /// does, with its public key.
    pub fn to_pkcs8(&self) -> Pkcs8 {
        Pkcs8(Buffer::encode(|output| match &self.0 {
            Private::X25519(key) => key.to_pkcs8(output),
            Private::P256(key) => key.to_pkcs8(output),
            Private::P384(key) => key.to_pkcs8(output),
            Private::P521(key) => key.to_pkcs8(output),
        }))
    }

    /// Encodes the private key as the scalar [`Self::from_scalar`] loads.
    pub fn to_scalar(&self) -> Scalar {
        Scalar(Buffer::encode(|output| match &self.0 {
            Private::X25519(key) => key.to_scalar(output),
            Private::P256(key) => key.to_scalar(output),
            Private::P384(key) => key.to_scalar(output),
            Private::P521(key) => key.to_scalar(output),
        }))
    }
}

impl Drop for PrivateKey {
    fn drop(&mut self) {
        low::zeroise_value(&mut self.0);
    }
}

impl fmt::Debug for PrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateKey").finish_non_exhaustive()
    }
}

/// A private key as its scalar, which [`PrivateKey::from_scalar`]
/// loads, wiped on drop under the `wipe` feature.
pub struct Scalar(Buffer<MAX_SCALAR_LEN>);

impl AsRef<[u8]> for Scalar {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl fmt::Debug for Scalar {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Scalar").finish_non_exhaustive()
    }
}

impl Drop for Scalar {
    fn drop(&mut self) {
        low::zeroise_value(&mut self.0);
    }
}

/// Writes to the start of an output and returns the written span.
type Write<K> = for<'a> fn(&K, &'a mut [u8]) -> Result<&'a [u8], Error>;

/// A curve's private key, as key agreement runs it.
trait Agree: Sized + 'static {
    fn random() -> Result<Self, Error>;

    fn load(source: Source<'_>) -> Result<Self, Error>;

    fn wrap(key: Keyed<Self>) -> Private;

    fn encode_public(&self) -> PublicKey;

    fn agree(&self, peer: &[u8]) -> Result<Secret, Error>;

    fn encode_pkcs8<'a>(&self, output: &'a mut [u8]) -> Result<&'a [u8], Error>;

    fn encode_scalar<'a>(&self, output: &'a mut [u8]) -> Result<&'a [u8], Error>;
}

/// A private key with its curve's code, which it reaches only through
/// `ops`: matching on [`Private`] then names no curve's code.
struct Keyed<K: Agree> {
    key: K,
    ops: low::ZeroableRef<Ops<K>>,
}

struct Ops<K> {
    public_key: fn(&K) -> PublicKey,
    agree: fn(&K, &[u8]) -> Result<Secret, Error>,
    to_pkcs8: Write<K>,
    to_scalar: Write<K>,
}

impl<K: Agree> Keyed<K> {
    fn generate() -> Result<Private, Error> {
        Ok(K::wrap(Self::new(K::random()?)))
    }

    fn load(source: Source<'_>) -> Result<Private, Error> {
        Ok(K::wrap(Self::new(K::load(source)?)))
    }

    fn new(key: K) -> Self {
        Self {
            key,
            ops: low::ZeroableRef::new(
                const {
                    &Ops {
                        public_key: K::encode_public,
                        agree: K::agree,
                        to_pkcs8: K::encode_pkcs8,
                        to_scalar: K::encode_scalar,
                    }
                },
            ),
        }
    }

    fn public_key(&self) -> PublicKey {
        (self.ops.get().public_key)(&self.key)
    }

    fn agree(&self, peer: &[u8]) -> Result<Secret, Error> {
        (self.ops.get().agree)(&self.key, peer)
    }

    fn to_pkcs8<'a>(&self, output: &'a mut [u8]) -> Result<&'a [u8], Error> {
        (self.ops.get().to_pkcs8)(&self.key, output)
    }

    fn to_scalar<'a>(&self, output: &'a mut [u8]) -> Result<&'a [u8], Error> {
        (self.ops.get().to_scalar)(&self.key, output)
    }
}

impl Agree for x25519::PrivateKey {
    fn random() -> Result<Self, Error> {
        Self::new_random()
    }

    fn load(source: Source<'_>) -> Result<Self, Error> {
        match source {
            Source::Scalar(scalar) => Self::from_bytes(scalar),
            Source::Pkcs8(der) => x25519_from_pkcs8(der),
            Source::Sec1(_) => Err(KeyFormatError::MismatchedSec1Curve.into()),
        }
    }

    fn wrap(key: Keyed<Self>) -> Private {
        Private::X25519(key)
    }

    fn encode_public(&self) -> PublicKey {
        PublicKey::from_encoding(&self.public_key().as_bytes())
    }

    fn agree(&self, peer: &[u8]) -> Result<Secret, Error> {
        let peer = x25519::PublicKey::try_from_slice(peer)?;
        Ok(Secret::X25519(self.diffie_hellman(&peer)?))
    }

    fn encode_pkcs8<'a>(&self, output: &'a mut [u8]) -> Result<&'a [u8], Error> {
        x25519_to_pkcs8(self, output)
    }

    fn encode_scalar<'a>(&self, output: &'a mut [u8]) -> Result<&'a [u8], Error> {
        let output = output.get_mut(..32).ok_or(Error::WrongLength)?;
        output.copy_from_slice(&self.secret_bytes());
        Ok(output)
    }
}

/// Parses a peer's X25519 public key: any 32 bytes, as [`Agree::agree`]
/// takes them.
fn x25519_public_key(bytes: &[u8]) -> Result<PublicKey, Error> {
    x25519::PublicKey::try_from_slice(bytes)?;
    Ok(PublicKey::from_encoding(bytes))
}

/// Loads an RFC 8410 PKCS#8 X25519 key, whose `privateKey` holds an
/// `OCTET STRING` of the key's 32 bytes, checking a v2 key's public key.
fn x25519_from_pkcs8(der: &[u8]) -> Result<x25519::PrivateKey, Error> {
    let _entry = low::Entry::new_secret();
    let p8 = pkcs8::Key::decode(der, &[&asn1::oid::id_X25519], None)?;
    let key = asn1::OctetString::from_bytes(p8.private_key())
        .map_err(|e| Error::from(KeyFormatError::Asn1(e)))
        .and_then(|key| x25519::PrivateKey::from_bytes(key.as_octets()))?;
    match p8.public_key() {
        Some(public_key) if public_key != key.public_key().as_bytes() => {
            Err(KeyFormatError::MismatchedPkcs8PublicKey.into())
        }
        _ => Ok(key),
    }
}

/// Encodes an X25519 key as RFC 8410's PKCS#8 v1, which, as aws-lc and
/// OpenSSL write it, carries no public key to compute.
fn x25519_to_pkcs8<'a>(key: &x25519::PrivateKey, output: &'a mut [u8]) -> Result<&'a [u8], Error> {
    let _entry = low::Entry::new_secret();
    let mut private_key = [0u8; 34];
    let len = asn1::OctetString::new(&key.secret_bytes())
        .encode(&mut asn1::Encoder::new(&mut private_key))
        .map_err(|_| Error::WrongLength)?;
    let encoded = pkcs8::Key::construct(
        &private_key[..len],
        None,
        asn1::oid::id_X25519.clone(),
        None,
    )
    .encode(output)?;
    // The caller owns the encoding, as with the key's scalar.
    low::ct::public_slice(encoded);
    Ok(encoded)
}

/// Implements [`Agree`] for a NIST curve's private key, and defines
/// `$public_key`, which parses a peer's X9.62 point, uncompressed or
/// compressed, as its uncompressed encoding.
macro_rules! nist_curve {
    ($curve:ident, $variant:ident, $curve_type:ty, $public_key:ident) => {
        fn $public_key(bytes: &[u8]) -> Result<PublicKey, Error> {
            let mut decompressed = [0; $curve::PublicKey::BYTES];
            let point =
                sec1::uncompressed(bytes, $curve::PublicKey::decompress, &mut decompressed)?;
            $curve::PublicKey::from_x962_uncompressed(point)?;
            Ok(PublicKey::from_encoding(point))
        }

        impl Agree for $curve::PrivateKey {
            fn random() -> Result<Self, Error> {
                Self::new_random()
            }

            fn load(source: Source<'_>) -> Result<Self, Error> {
                let _entry = low::Entry::new_secret();
                let decoded = match source {
                    Source::Scalar(scalar) if scalar.len() == $curve::Scalar::BYTES => {
                        return Self::from_bytes(scalar);
                    }
                    Source::Scalar(_) => return Err(KeyFormatError::WrongLength.into()),
                    Source::Pkcs8(der) => sec1::decode_pkcs8(der, &<$curve_type>::oid())?,
                    Source::Sec1(der) => sec1::decode(der, &<$curve_type>::oid())?,
                };
                let key = Self::from_bytes(decoded.private_key)?;
                match decoded.public_key {
                    Some(public_key)
                        if !sec1::is_public_key(&key.public_key_uncompressed(), public_key) =>
                    {
                        Err(KeyFormatError::MismatchedSec1PublicKey.into())
                    }
                    _ => Ok(key),
                }
            }

            fn wrap(key: Keyed<Self>) -> Private {
                Private::$variant(key)
            }

            fn encode_public(&self) -> PublicKey {
                PublicKey::from_encoding(&self.public_key_uncompressed())
            }

            fn agree(&self, peer: &[u8]) -> Result<Secret, Error> {
                let peer = $curve::PublicKey::from_x962_uncompressed(peer)?;
                Ok(Secret::$variant(self.diffie_hellman(&peer)?))
            }

            fn encode_pkcs8<'a>(&self, output: &'a mut [u8]) -> Result<&'a [u8], Error> {
                let _entry = low::Entry::new_secret();
                sec1::encode_pkcs8(
                    &self.secret_bytes(),
                    &self.public_key_uncompressed(),
                    <$curve_type>::oid(),
                    output,
                )
            }

            fn encode_scalar<'a>(&self, output: &'a mut [u8]) -> Result<&'a [u8], Error> {
                let output = output
                    .get_mut(..$curve::Scalar::BYTES)
                    .ok_or(Error::WrongLength)?;
                output.copy_from_slice(&self.secret_bytes());
                Ok(output)
            }
        }
    };
}

nist_curve!(p256, P256, curve::P256, p256_public_key);
nist_curve!(p384, P384, curve::P384, p384_public_key);
nist_curve!(p521, P521, curve::P521, p521_public_key);

/// A public key: 32 bytes for X25519, or an X9.62 uncompressed point.
///
/// Each algorithm's key has its own length, which names its algorithm.
#[derive(Clone)]
pub struct PublicKey {
    bytes: [u8; Self::MAX_LEN],
    len: usize,
}

impl PublicKey {
    // P-521's uncompressed point.
    const MAX_LEN: usize = p521::PublicKey::BYTES;

    /// Parses a peer's public key for `algorithm`: X25519's 32 bytes, any
    /// value, or a NIST curve's X9.62 point, uncompressed or compressed,
    /// refused off the curve.
    ///
    /// Its bytes are then what [`PrivateKey::agree`] takes, a NIST curve's
    /// point uncompressed.
    pub fn new(algorithm: &'static Algorithm, bytes: &[u8]) -> Result<Self, Error> {
        (algorithm.parse_public)(bytes)
    }

    /// Parses a public key for `algorithm` from its `SubjectPublicKeyInfo`
    /// DER, as [`Self::new`] parses the key it holds.
    ///
    /// A NIST curve's key names `id-ecPublicKey` and the curve, or, as
    /// WebCrypto also takes for ECDH, `id-ecDH`.
    pub fn from_spki(algorithm: &'static Algorithm, der: &[u8]) -> Result<Self, Error> {
        let ec = [&asn1::oid::id_ecPublicKey, &asn1::oid::id_ecDH];
        let curve = |oid: asn1::ObjectId| Some(asn1::Any::ObjectId(oid));
        let key = match algorithm.id {
            AlgorithmId::X25519 => spki::decode(der, &[&asn1::oid::id_X25519], None),
            AlgorithmId::EcdhP256 => spki::decode(der, &ec, curve(curve::P256::oid())),
            AlgorithmId::EcdhP384 => spki::decode(der, &ec, curve(curve::P384::oid())),
            AlgorithmId::EcdhP521 => spki::decode(der, &ec, curve(curve::P521::oid())),
        }?;
        Self::new(algorithm, key)
    }

    /// Encodes the public key as a `SubjectPublicKeyInfo`: X25519's, or
    /// `id-ecPublicKey` on the key's curve.
    pub fn to_spki(&self) -> Spki {
        let (algorithm, curve) = match self.len {
            32 => (&asn1::oid::id_X25519, None),
            p256::PublicKey::BYTES => (&asn1::oid::id_ecPublicKey, Some(curve::P256::oid())),
            p384::PublicKey::BYTES => (&asn1::oid::id_ecPublicKey, Some(curve::P384::oid())),
            _ => (&asn1::oid::id_ecPublicKey, Some(curve::P521::oid())),
        };
        Spki(Buffer::encode(|output| {
            spki::encode(
                self.as_ref(),
                algorithm,
                curve.map(asn1::Any::ObjectId),
                output,
            )
        }))
    }

    fn from_encoding(encoded: &[u8]) -> Self {
        let mut public = Self {
            bytes: [0; Self::MAX_LEN],
            len: encoded.len(),
        };
        public.bytes[..encoded.len()].copy_from_slice(encoded);
        public
    }
}

impl AsRef<[u8]> for PublicKey {
    fn as_ref(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("PublicKey").field(&self.as_ref()).finish()
    }
}

/// The secret both parties agree on, wiped on drop under the `wipe` feature.
pub struct SharedSecret(Secret);

// As `Private`: all-bits-zero is a valid `X25519` secret.
#[repr(u8)]
enum Secret {
    X25519(x25519::SharedSecret),
    P256(p256::SharedSecret),
    P384(p384::SharedSecret),
    P521(p521::SharedSecret),
}

impl AsRef<[u8]> for SharedSecret {
    fn as_ref(&self) -> &[u8] {
        match &self.0 {
            Secret::X25519(secret) => &secret.0,
            Secret::P256(secret) => &secret.0,
            Secret::P384(secret) => &secret.0,
            Secret::P521(secret) => &secret.0,
        }
    }
}

impl low::Zeroable for Secret {}

impl Drop for SharedSecret {
    fn drop(&mut self) {
        low::zeroise_value(&mut self.0);
    }
}

impl fmt::Debug for SharedSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("SharedSecret").finish_non_exhaustive()
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use serde::Deserialize;

    use super::*;
    use crate::high::signature::{EcdsaKeyPair, sign};
    use crate::test::{Expected, wycheproof};

    const ALGORITHMS: [&Algorithm; 4] = [&X25519, &ECDH_P256, &ECDH_P384, &ECDH_P521];

    fn public(secret: &SharedSecret) -> Vec<u8> {
        let secret = secret.as_ref().to_vec();
        low::ct::public_slice(&secret);
        secret
    }

    #[test]
    fn agrees() {
        for algorithm in ALGORITHMS {
            let alice = PrivateKey::generate(algorithm).unwrap();
            let bob = PrivateKey::generate(algorithm).unwrap();
            let alice_public = alice.public_key();
            let bob_public = bob.public_key();

            let alice_secret = public(&alice.agree(bob_public.as_ref()).unwrap());
            let bob_secret = public(&bob.agree(alice_public.as_ref()).unwrap());
            assert_eq!(alice_secret, bob_secret);
            // A key agrees again, with the same result.
            assert_eq!(
                public(&alice.agree(bob_public.as_ref()).unwrap()),
                alice_secret
            );
        }
    }

    #[test]
    fn round_trips() {
        for algorithm in ALGORITHMS {
            let key = PrivateKey::generate(algorithm).unwrap();
            let peer = PrivateKey::generate(algorithm).unwrap().public_key();
            let secret = public(&key.agree(peer.as_ref()).unwrap());

            let scalar = key.to_scalar();
            let pkcs8 = key.to_pkcs8();
            for loaded in [
                PrivateKey::from_scalar(algorithm, scalar.as_ref()).unwrap(),
                PrivateKey::from_pkcs8(algorithm, pkcs8.as_ref()).unwrap(),
            ] {
                assert_eq!(loaded.public_key().as_ref(), key.public_key().as_ref());
                assert_eq!(public(&loaded.agree(peer.as_ref()).unwrap()), secret);
                let (loaded_scalar, loaded_pkcs8) = (loaded.to_scalar(), loaded.to_pkcs8());
                low::ct::public_slice(loaded_scalar.as_ref());
                // Loading marks the input's scalar secret.
                low::ct::public_slice(scalar.as_ref());
                low::ct::public_slice(pkcs8.as_ref());
                assert_eq!(loaded_scalar.as_ref(), scalar.as_ref());
                assert_eq!(loaded_pkcs8.as_ref(), pkcs8.as_ref());
            }
        }
    }

    /// Each loader, with the scalar inside its encoding marked secret, so
    /// that ctgrind checks parsing it branches on nothing secret.
    #[test]
    fn loads_in_constant_time() {
        type Load = fn(&'static Algorithm, &[u8]) -> Result<PrivateKey, Error>;
        for algorithm in ALGORITHMS {
            let key = PrivateKey::generate(algorithm).unwrap();
            let peer = PrivateKey::generate(algorithm).unwrap().public_key();
            let scalar = key.to_scalar().as_ref().to_vec();
            low::ct::public_slice(&scalar);
            let mut encodings: Vec<(Load, Vec<u8>)> = vec![
                (PrivateKey::from_scalar, scalar.clone()),
                (PrivateKey::from_pkcs8, key.to_pkcs8().as_ref().to_vec()),
            ];
            let curve = match algorithm.id {
                AlgorithmId::X25519 => None,
                AlgorithmId::EcdhP256 => Some(curve::P256::oid()),
                AlgorithmId::EcdhP384 => Some(curve::P384::oid()),
                AlgorithmId::EcdhP521 => Some(curve::P521::oid()),
            };
            if let Some(curve) = curve {
                let mut sec1 = [0; 256];
                let sec1 = sec1::encode(&scalar, key.public_key().as_ref(), Some(curve), &mut sec1);
                encodings.push((PrivateKey::from_sec1, sec1.unwrap().to_vec()));
            }

            for (load, encoding) in encodings {
                let at = encoding
                    .windows(scalar.len())
                    .position(|w| w == scalar)
                    .unwrap();
                low::ct::secret_slice(&encoding[at..at + scalar.len()]);
                let loaded = load(algorithm, &encoding).unwrap();
                public(&loaded.agree(peer.as_ref()).unwrap());
            }
        }
    }

    #[test]
    fn loads_ecdsa_keys() {
        for (algorithm, signing, pkcs8, sec1) in [
            (
                &ECDH_P256,
                &sign::ECDSA_P256_SHA256_ASN1,
                &include_bytes!("ecdsa/secp256r1.pkcs8.der")[..],
                &include_bytes!("ecdsa/secp256r1.der")[..],
            ),
            (
                &ECDH_P384,
                &sign::ECDSA_P384_SHA384_ASN1,
                &include_bytes!("ecdsa/secp384r1.pkcs8.der")[..],
                &include_bytes!("ecdsa/secp384r1.der")[..],
            ),
            (
                &ECDH_P521,
                &sign::ECDSA_P521_SHA512_ASN1,
                &include_bytes!("ecdsa/secp521r1.pkcs8.der")[..],
                &include_bytes!("ecdsa/secp521r1.der")[..],
            ),
        ] {
            let ecdsa = EcdsaKeyPair::from_pkcs8(signing, pkcs8).unwrap();
            let from_pkcs8 = PrivateKey::from_pkcs8(algorithm, pkcs8).unwrap();
            let from_sec1 = PrivateKey::from_sec1(algorithm, sec1).unwrap();
            for key in [&from_pkcs8, &from_sec1] {
                assert_eq!(key.public_key().as_ref(), ecdsa.public_key().as_ref());
                assert_eq!(key.to_pkcs8().as_ref(), ecdsa.to_pkcs8().as_ref());
            }
            // Another curve's key, and each NIST encoding to X25519, are
            // refused.
            for other in [&ECDH_P256, &ECDH_P384, &ECDH_P521] {
                if !core::ptr::eq(other, algorithm) {
                    assert_eq!(
                        PrivateKey::from_pkcs8(other, pkcs8).err(),
                        Some(KeyFormatError::MismatchedPkcs8Parameters.into())
                    );
                    assert_eq!(
                        PrivateKey::from_sec1(other, sec1).err(),
                        Some(KeyFormatError::MismatchedSec1Curve.into())
                    );
                }
            }
            assert_eq!(
                PrivateKey::from_pkcs8(&X25519, pkcs8).err(),
                Some(KeyFormatError::MismatchedPkcs8Algorithm.into())
            );
            assert_eq!(
                PrivateKey::from_sec1(&X25519, sec1).err(),
                Some(KeyFormatError::MismatchedSec1Curve.into())
            );
        }
        assert_eq!(
            PrivateKey::from_sec1(
                &ECDH_P256,
                include_bytes!("ecdsa/secp256r1.wrong-public-key.der")
            )
            .err(),
            Some(KeyFormatError::MismatchedSec1PublicKey.into())
        );
    }

    #[test]
    fn refuses_scalars() {
        for (algorithm, len) in [
            (&X25519, 32),
            (&ECDH_P256, 32),
            (&ECDH_P384, 48),
            (&ECDH_P521, 66),
        ] {
            for wrong in [0, len - 1, len + 1] {
                assert_eq!(
                    PrivateKey::from_scalar(algorithm, &vec![1; wrong]).err(),
                    Some(KeyFormatError::WrongLength.into()),
                );
            }
        }
        // Zero, and n, the smallest scalar not below it.
        let n = |hex: &str| hex::decode(hex).unwrap();
        for (algorithm, n) in [
            (
                &ECDH_P256,
                n("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551"),
            ),
            (
                &ECDH_P384,
                n(
                    "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973",
                ),
            ),
            (
                &ECDH_P521,
                n(
                    "01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409",
                ),
            ),
        ] {
            for scalar in [vec![0; n.len()], n] {
                assert_eq!(
                    PrivateKey::from_scalar(algorithm, &scalar).err(),
                    Some(KeyFormatError::ScalarOutOfRange.into()),
                );
            }
        }
    }

    #[test]
    fn x25519_pkcs8() {
        let key = PrivateKey::generate(&X25519).unwrap();
        let scalar = key.to_scalar();
        low::ct::public_slice(scalar.as_ref());
        let public_key = key.public_key();

        // v2, with its public key, loads as the same key, and is refused
        // with another.
        let v2 = |public_key: &[u8]| {
            [
                &[
                    0x30, 0x51, 0x02, 0x01, 0x01, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e,
                ][..],
                &[0x04, 0x22, 0x04, 0x20],
                scalar.as_ref(),
                &[0x81, 0x21, 0x00],
                public_key,
            ]
            .concat()
        };
        let loaded = PrivateKey::from_pkcs8(&X25519, &v2(public_key.as_ref())).unwrap();
        assert_eq!(loaded.public_key().as_ref(), public_key.as_ref());
        assert_eq!(loaded.to_pkcs8().as_ref(), key.to_pkcs8().as_ref());
        let other = PrivateKey::generate(&X25519).unwrap().public_key();
        assert_eq!(
            PrivateKey::from_pkcs8(&X25519, &v2(other.as_ref())).err(),
            Some(KeyFormatError::MismatchedPkcs8PublicKey.into())
        );

        // An Ed25519 key, and an X25519 key to a NIST curve, are refused.
        assert_eq!(
            PrivateKey::from_pkcs8(&X25519, include_bytes!("asn1/testdata/ed25519-p8v1.bin")).err(),
            Some(KeyFormatError::MismatchedPkcs8Algorithm.into())
        );
        assert_eq!(
            PrivateKey::from_pkcs8(&ECDH_P256, key.to_pkcs8().as_ref()).err(),
            Some(KeyFormatError::MismatchedPkcs8Algorithm.into())
        );
    }

    #[derive(Deserialize, Debug)]
    struct EcdhTest {
        #[serde(rename = "tcId")]
        id: usize,
        flags: Vec<String>,
        #[serde(with = "hex::serde")]
        public: Vec<u8>,
        #[serde(with = "hex::serde")]
        private: Vec<u8>,
        #[serde(with = "hex::serde")]
        shared: Vec<u8>,
        result: Expected,
    }

    impl EcdhTest {
        fn has_flag(&self, flag: &str) -> bool {
            self.flags.iter().any(|f| f == flag)
        }
    }

    /// Wycheproof's private key, an integer that may have a sign byte or
    /// fewer bytes than the curve's scalar, at the scalar's length.
    fn fixed_scalar(private: &[u8], len: usize) -> Vec<u8> {
        let start = private
            .iter()
            .position(|b| *b != 0)
            .unwrap_or(private.len());
        let digits = &private[start..];
        [vec![0; len - digits.len()], digits.to_vec()].concat()
    }

    /// Wycheproof's X9.62 points, which `agree` takes uncompressed and
    /// [`PublicKey::new`] compressed too.
    fn check_nist_ecdh(file: &str, algorithm: &'static Algorithm, len: usize) {
        for test in wycheproof::<EcdhTest>(file) {
            let private =
                PrivateKey::from_scalar(algorithm, &fixed_scalar(&test.private, len)).unwrap();
            let direct = private.agree(&test.public).map(|shared| public(&shared));
            let result = PublicKey::new(algorithm, &test.public)
                .and_then(|peer| private.agree(peer.as_ref()))
                .map(|shared| public(&shared));
            let compressed = test.has_flag("CompressedPoint");
            match compressed {
                true => assert_eq!(
                    direct,
                    Err(KeyFormatError::Compressed.into()),
                    "{}",
                    test.id
                ),
                false => assert_eq!(direct, result, "{}", test.id),
            }

            match (test.result, &result) {
                (Expected::Valid, Ok(shared)) => assert_eq!(shared, &test.shared, "{}", test.id),
                (Expected::Acceptable, Ok(shared)) if compressed => {
                    assert_eq!(shared, &test.shared, "{}", test.id)
                }
                (Expected::Invalid, Err(e))
                    if (test.has_flag("InvalidCurveAttack")
                        || test.has_flag("InvalidCompressedPublic"))
                        && *e == KeyFormatError::NotOnCurve.into() => {}
                (Expected::Invalid, Err(e))
                    if test.has_flag("InvalidEncoding")
                        && *e == KeyFormatError::WrongLength.into() => {}
                // A point on the twist, compressed, names no point on the
                // curve; another curve's is the wrong length.
                (Expected::Invalid, Err(e))
                    if test.has_flag("WrongCurve")
                        && [KeyFormatError::NotOnCurve, KeyFormatError::WrongLength]
                            .map(Error::from)
                            .contains(e) => {}
                _ => panic!("{}: expected {:?} got {:?}", test.id, test.result, result),
            }
        }
    }

    /// Wycheproof's public keys as `SubjectPublicKeyInfo`, many naming
    /// curves by their parameters, which rind refuses.
    fn check_nist_ecdh_spki(file: &str, algorithm: &'static Algorithm, len: usize) {
        for test in wycheproof::<EcdhTest>(file) {
            let private =
                PrivateKey::from_scalar(algorithm, &fixed_scalar(&test.private, len)).unwrap();
            let peer = PublicKey::from_spki(algorithm, &test.public);
            let result = peer
                .as_ref()
                .map_err(|e| *e)
                .and_then(|peer| private.agree(peer.as_ref()))
                .map(|shared| public(&shared));
            match (test.result, &result) {
                (Expected::Valid, Ok(shared)) => assert_eq!(shared, &test.shared, "{}", test.id),
                (Expected::Acceptable, Ok(shared)) => {
                    assert_eq!(shared, &test.shared, "{}", test.id)
                }
                (Expected::Invalid | Expected::Acceptable, Err(_)) => {}
                _ => panic!("{}: expected {:?} got {:?}", test.id, test.result, result),
            }
            // A key that parsed encodes back to Wycheproof's SPKI, but for
            // a compressed point, which it decompresses.
            if let Ok(peer) = peer
                && !test.has_flag("CompressedPublic")
            {
                assert_eq!(peer.to_spki().as_ref(), &test.public[..], "{}", test.id);
            }
        }
    }

    #[test]
    fn wycheproof_p256() {
        check_nist_ecdh("ecdh_secp256r1_ecpoint_test.json", &ECDH_P256, 32);
        check_nist_ecdh_spki("ecdh_secp256r1_test.json", &ECDH_P256, 32);
    }

    #[test]
    fn wycheproof_p384() {
        check_nist_ecdh("ecdh_secp384r1_ecpoint_test.json", &ECDH_P384, 48);
        check_nist_ecdh_spki("ecdh_secp384r1_test.json", &ECDH_P384, 48);
    }

    #[test]
    fn wycheproof_p521() {
        check_nist_ecdh("ecdh_secp521r1_ecpoint_test.json", &ECDH_P521, 66);
        check_nist_ecdh_spki("ecdh_secp521r1_test.json", &ECDH_P521, 66);
    }

    fn check_x25519(test: &EcdhTest, result: Result<Vec<u8>, Error>) {
        match (test.result, &result) {
            (Expected::Acceptable, Err(e))
                if test.has_flag("ZeroSharedSecret") && *e == KeyFormatError::SmallOrder.into() => {
            }
            (Expected::Invalid, Err(_))
                if test.has_flag("InvalidPublic") || test.has_flag("MissingOctetString") => {}
            (Expected::Valid | Expected::Acceptable, Ok(shared)) => {
                assert_eq!(shared, &test.shared, "{}", test.id)
            }
            _ => panic!("{}: expected {:?} got {:?}", test.id, test.result, result),
        }
    }

    #[test]
    fn wycheproof_x25519() {
        for test in wycheproof::<EcdhTest>("x25519_test.json") {
            let private = PrivateKey::from_scalar(&X25519, &test.private).unwrap();
            check_x25519(&test, private.agree(&test.public).map(|s| public(&s)));
        }
    }

    /// Private keys in PKCS#8, and public keys in SPKI.
    #[test]
    fn wycheproof_x25519_pkcs8() {
        for test in wycheproof::<EcdhTest>("x25519_asn_test.json") {
            let peer = PublicKey::from_spki(&X25519, &test.public);
            if let Ok(peer) = &peer {
                assert_eq!(peer.to_spki().as_ref(), &test.public[..], "{}", test.id);
            }
            let result = PrivateKey::from_pkcs8(&X25519, &test.private)
                .and_then(|private| private.agree(peer?.as_ref()).map(|s| public(&s)));
            check_x25519(&test, result);
        }
    }

    /// The point `uncompressed`, compressed.
    fn compress(uncompressed: &[u8]) -> Vec<u8> {
        let (x, y) = uncompressed[1..].split_at(uncompressed.len() / 2);
        [&[2 | (y[y.len() - 1] & 1)][..], x].concat()
    }

    #[test]
    fn public_keys_round_trip() {
        for algorithm in ALGORITHMS {
            let ours = PrivateKey::generate(algorithm).unwrap().public_key();
            let parsed = PublicKey::new(algorithm, ours.as_ref()).unwrap();
            assert_eq!(parsed.as_ref(), ours.as_ref());
            let spki = ours.to_spki();
            let parsed = PublicKey::from_spki(algorithm, spki.as_ref()).unwrap();
            assert_eq!(parsed.as_ref(), ours.as_ref());

            // Another algorithm's key is refused, raw and in SPKI.
            for other in ALGORITHMS.into_iter().filter(|a| a.id != algorithm.id) {
                assert!(PublicKey::new(other, ours.as_ref()).is_err());
                assert_eq!(
                    PublicKey::from_spki(other, spki.as_ref()).err(),
                    Some(KeyFormatError::MismatchedSpkiAlgorithm.into())
                );
            }
        }
    }

    #[test]
    fn decompresses_points() {
        for algorithm in &ALGORITHMS[1..] {
            for _ in 0..16 {
                let private = PrivateKey::generate(algorithm).unwrap();
                let ours = private.public_key();
                let compressed = compress(ours.as_ref());
                let parsed = PublicKey::new(algorithm, &compressed).unwrap();
                assert_eq!(parsed.as_ref(), ours.as_ref());

                // The other root of `x`.
                let mut negated = compressed.clone();
                negated[0] ^= 1;
                let other = PublicKey::new(algorithm, &negated).unwrap();
                assert_ne!(other.as_ref(), ours.as_ref());
                assert_eq!(other.as_ref()[1..compressed.len()], compressed[1..]);

                // `agree` itself takes only uncompressed points.
                assert_eq!(
                    private.agree(&compressed).err(),
                    Some(KeyFormatError::Compressed.into())
                );

                // An SPKI's point may be compressed too, under
                // `id-ecPublicKey` or `id-ecDH`.
                let curve = match algorithm.id {
                    AlgorithmId::EcdhP256 => curve::P256::oid(),
                    AlgorithmId::EcdhP384 => curve::P384::oid(),
                    _ => curve::P521::oid(),
                };
                for oid in [&asn1::oid::id_ecPublicKey, &asn1::oid::id_ecDH] {
                    let mut der = [0; 256];
                    let parameters = Some(asn1::Any::ObjectId(curve.clone()));
                    let der = spki::encode(&compressed, oid, parameters, &mut der).unwrap();
                    let parsed = PublicKey::from_spki(algorithm, der).unwrap();
                    assert_eq!(parsed.as_ref(), ours.as_ref());
                }
            }

            // A hybrid point, an unknown tag, an empty key, the wrong
            // length, and `x` at or above p are refused.
            let ours = PrivateKey::generate(algorithm).unwrap().public_key();
            let mut hybrid = ours.as_ref().to_vec();
            hybrid[0] = 6 | (hybrid[hybrid.len() - 1] & 1);
            let compressed = compress(ours.as_ref());
            let refusals: [(&[u8], KeyFormatError); 5] = [
                (&hybrid, KeyFormatError::PointEncoding),
                (
                    &[&[5][..], &compressed[1..]].concat(),
                    KeyFormatError::PointEncoding,
                ),
                (&[], KeyFormatError::WrongLength),
                (
                    &compressed[..compressed.len() - 1],
                    KeyFormatError::WrongLength,
                ),
                (
                    &[&[2][..], &vec![0xff; compressed.len() - 1]].concat(),
                    KeyFormatError::NotOnCurve,
                ),
            ];
            for (bytes, error) in refusals {
                assert_eq!(PublicKey::new(algorithm, bytes).err(), Some(error.into()));
            }
        }
    }
}
