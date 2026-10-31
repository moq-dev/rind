// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

use core::fmt;

use crate::error::Error;
use crate::low;
use crate::mid::{p256, p384, p521, x25519};

/// A key agreement algorithm: a curve and its public key encoding.
pub struct Algorithm {
    id: AlgorithmId,
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
};

/// ECDH on P-256, with X9.62 uncompressed public keys.
///
/// P-256 is also known as "NISTP256", "prime256v1", or "secp256r1".
pub static ECDH_P256: Algorithm = Algorithm {
    id: AlgorithmId::EcdhP256,
};

/// ECDH on P-384, with X9.62 uncompressed public keys.
///
/// P-384 is also known as "NISTP384", or "secp384r1".
pub static ECDH_P384: Algorithm = Algorithm {
    id: AlgorithmId::EcdhP384,
};

/// ECDH on P-521, with X9.62 uncompressed public keys.
///
/// P-521 is also known as "NISTP521", or "secp521r1".
pub static ECDH_P521: Algorithm = Algorithm {
    id: AlgorithmId::EcdhP521,
};

/// A private key used for one key agreement, wiped on drop.
///
/// There is no static private key: no consumer agrees twice with one key.
pub struct PrivateKey(Private);

// `repr(u8)` puts `X25519` at tag zero, and every variant's key is plain
// words, so all-bits-zero is a valid value and `Drop` can wipe the tag and
// any unused tail along with the key.
#[repr(u8)]
enum Private {
    X25519(x25519::PrivateKey),
    P256(p256::PrivateKey),
    P384(p384::PrivateKey),
    P521(p521::PrivateKey),
}

impl low::Zeroable for Private {}

impl PrivateKey {
    /// Generates a private key for `algorithm` from the system random source.
    pub fn generate(algorithm: &'static Algorithm) -> Result<Self, Error> {
        Ok(Self(match algorithm.id {
            AlgorithmId::X25519 => Private::X25519(x25519::PrivateKey::new_random()?),
            AlgorithmId::EcdhP256 => Private::P256(p256::PrivateKey::new_random()?),
            AlgorithmId::EcdhP384 => Private::P384(p384::PrivateKey::new_random()?),
            AlgorithmId::EcdhP521 => Private::P521(p521::PrivateKey::new_random()?),
        }))
    }

    /// Returns the public key to send to the peer.
    pub fn public_key(&self) -> PublicKey {
        let mut public = PublicKey {
            bytes: [0; PublicKey::MAX_LEN],
            len: 0,
        };
        let encoded: &[u8] = match &self.0 {
            Private::X25519(key) => &key.public_key().as_bytes(),
            Private::P256(key) => &key.public_key_uncompressed(),
            Private::P384(key) => &key.public_key_uncompressed(),
            Private::P521(key) => &key.public_key_uncompressed(),
        };
        public.bytes[..encoded.len()].copy_from_slice(encoded);
        public.len = encoded.len();
        public
    }

    /// Agrees on a secret with the peer's encoded public key, consuming this key.
    ///
    /// The peer's key is parsed for this key's algorithm, and refused if it
    /// is malformed or off the curve, and so is X25519's all-zero output from
    /// a small-order point
    /// ([RFC7748 section 6.1](https://datatracker.ietf.org/doc/html/rfc7748#section-6.1)).
    pub fn agree(self, peer: &[u8]) -> Result<SharedSecret, Error> {
        Ok(SharedSecret(match &self.0 {
            Private::X25519(key) => {
                Secret::X25519(key.diffie_hellman(&x25519::PublicKey::try_from_slice(peer)?)?)
            }
            Private::P256(key) => {
                Secret::P256(key.diffie_hellman(&p256::PublicKey::from_x962_uncompressed(peer)?)?)
            }
            Private::P384(key) => {
                Secret::P384(key.diffie_hellman(&p384::PublicKey::from_x962_uncompressed(peer)?)?)
            }
            Private::P521(key) => {
                Secret::P521(key.diffie_hellman(&p521::PublicKey::from_x962_uncompressed(peer)?)?)
            }
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

/// Our public key: 32 bytes for X25519, or an X9.62 uncompressed point.
#[derive(Clone)]
pub struct PublicKey {
    bytes: [u8; Self::MAX_LEN],
    len: usize,
}

impl PublicKey {
    // P-521's uncompressed point.
    const MAX_LEN: usize = p521::PublicKey::BYTES;
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

/// The secret both parties agree on, wiped on drop.
pub struct SharedSecret(Secret);

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
    use crate::error::KeyFormatError;
    use crate::test::{Expected, wycheproof};

    #[test]
    fn agrees() {
        for algorithm in [&X25519, &ECDH_P256, &ECDH_P384, &ECDH_P521] {
            let alice = PrivateKey::generate(algorithm).unwrap();
            let bob = PrivateKey::generate(algorithm).unwrap();
            let alice_public = alice.public_key();
            let bob_public = bob.public_key();

            let alice_secret = alice.agree(bob_public.as_ref()).unwrap();
            let bob_secret = bob.agree(alice_public.as_ref()).unwrap();
            low::ct::public_slice(alice_secret.as_ref());
            low::ct::public_slice(bob_secret.as_ref());
            assert_eq!(alice_secret.as_ref(), bob_secret.as_ref());
        }
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

    fn check_nist_ecdh(file: &str, agree: impl Fn(&EcdhTest) -> Result<Vec<u8>, Error>) {
        for test in wycheproof::<EcdhTest>(file) {
            let result = agree(&test);
            // Point compression is unsupported.
            if test.has_flag("CompressedPublic") || test.has_flag("CompressedPoint") {
                assert_eq!(
                    result,
                    Err(KeyFormatError::Compressed.into()),
                    "{}",
                    test.id
                );
                continue;
            }

            match (test.result, &result) {
                (Expected::Valid, Ok(shared)) => assert_eq!(shared, &test.shared, "{}", test.id),
                (Expected::Invalid, Err(e))
                    if test.has_flag("InvalidCurveAttack")
                        && *e == KeyFormatError::NotOnCurve.into() => {}
                (Expected::Invalid, Err(e))
                    if test.has_flag("InvalidEncoding")
                        && *e == KeyFormatError::WrongLength.into() => {}
                _ => panic!("{}: expected {:?} got {:?}", test.id, test.result, result),
            }
        }
    }

    #[test]
    fn wycheproof_p256() {
        check_nist_ecdh("ecdh_secp256r1_ecpoint_test.json", |test| {
            let private = p256::StaticPrivateKey::from_bytes(&test.private).unwrap();
            let peer = p256::PublicKey::from_x962_uncompressed(&test.public)?;
            Ok(low::ct::into_public(private.diffie_hellman(&peer)?.0).to_vec())
        });
    }

    #[test]
    fn wycheproof_p384() {
        check_nist_ecdh("ecdh_secp384r1_ecpoint_test.json", |test| {
            let private = p384::StaticPrivateKey::from_bytes(&test.private).unwrap();
            let peer = p384::PublicKey::from_x962_uncompressed(&test.public)?;
            Ok(low::ct::into_public(private.diffie_hellman(&peer)?.0).to_vec())
        });
    }

    #[test]
    fn wycheproof_p521() {
        check_nist_ecdh("ecdh_secp521r1_ecpoint_test.json", |test| {
            let private = p521::StaticPrivateKey::from_bytes(&test.private).unwrap();
            let peer = p521::PublicKey::from_x962_uncompressed(&test.public)?;
            Ok(low::ct::into_public(private.diffie_hellman(&peer)?.0).to_vec())
        });
    }

    #[test]
    fn wycheproof_x25519() {
        for test in wycheproof::<EcdhTest>("x25519_test.json") {
            let private = x25519::StaticPrivateKey::try_from_slice(&test.private).unwrap();
            let result = x25519::PublicKey::try_from_slice(&test.public)
                .and_then(|peer| private.diffie_hellman(&peer))
                .map(|shared| low::ct::into_public(shared.0));
            match (test.result, &result) {
                (Expected::Acceptable, Err(e))
                    if test.has_flag("ZeroSharedSecret")
                        && *e == KeyFormatError::SmallOrder.into() => {}
                (Expected::Valid | Expected::Acceptable, Ok(shared)) => {
                    assert_eq!(&shared[..], &test.shared, "{}", test.id)
                }
                _ => panic!("{}: expected {:?} got {:?}", test.id, test.result, result),
            }
        }
    }

    // A fixed private key needs crate access, so this differential test lives
    // here rather than beside the other curves' in `tests/crosschecks.rs`.
    mod x25519_crosscheck {
        use aws_lc_rs::agreement::{self, PrivateKey, UnparsedPublicKey, X25519};
        use proptest::prelude::*;

        use super::*;

        // Any 32 bytes is a private key or a peer's u-coordinate, including
        // coordinates at or above the field prime. The fixed peers have small
        // order, which both sides refuse for the all-zero secret they give.
        fn peer() -> impl Strategy<Value = [u8; 32]> {
            let mut one = [0u8; 32];
            one[0] = 1;
            prop_oneof![
                8 => any::<[u8; 32]>(),
                1 => Just([0u8; 32]),
                1 => Just(one),
            ]
        }

        proptest! {
            #[test]
            fn ecdh(private in any::<[u8; 32]>(), peer in peer()) {
                // rind marks its copy secret, which aws-lc-rs's must not be.
                let ours_private = private;
                let ours = x25519::StaticPrivateKey::from_array(&ours_private);
                let theirs = PrivateKey::from_private_key(&X25519, &private).unwrap();
                let theirs_public = theirs.compute_public_key().unwrap();
                prop_assert_eq!(&ours.public_key().as_bytes()[..], theirs_public.as_ref());

                let ours_secret = ours
                    .diffie_hellman(&x25519::PublicKey::from_array(&peer))
                    .map(|secret| low::ct::into_public(secret.0));
                let theirs_secret = agreement::agree(
                    &theirs,
                    UnparsedPublicKey::new(&X25519, peer),
                    (),
                    |secret| Ok(secret.to_vec()),
                );
                match (ours_secret, theirs_secret) {
                    (Ok(ours), Ok(theirs)) => prop_assert_eq!(&ours[..], &theirs[..]),
                    (Err(_), Err(())) => {}
                    (ours, theirs) => prop_assert!(
                        false,
                        "rind gave {:?}, aws-lc-rs {:?}",
                        ours.err(),
                        theirs.err()
                    ),
                }
            }
        }
    }
}
