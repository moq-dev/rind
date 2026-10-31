//! Constant-time checks for the secret paths rind-ring adds over rind, run
//! under valgrind by `admin/ctgrind`.
//!
//! Secret inputs are marked undefined, so memcheck flags any branch or memory
//! index that depends on them. Outputs that are public by design are marked
//! defined before the test checks them. rind itself marks the private keys it
//! generates or parses.

use std::num::NonZeroU32;

use crabgrind::memcheck::{self, MemState};
use crabgrind::valgrind::{self, RunningMode};
use rind_ring::aead::{self, quic};
use rind_ring::signature::{self, KeyPair};
use rind_ring::{hkdf, hmac, pbkdf2, rand};

/// Marks `value` secret: memcheck flags any branch or index that depends on it.
fn secret<T: ?Sized>(value: &T) {
    mark(value, MemState::Undefined);
}

/// Marks `value` public, so the test may branch on it.
fn public<T: ?Sized>(value: &T) {
    mark(value, MemState::Defined);
}

fn mark<T: ?Sized>(value: &T, state: MemState) {
    if let RunningMode::Valgrind = valgrind::running_mode() {
        memcheck::mark_memory((value as *const T).cast(), size_of_val(value), state).unwrap();
    }
}

/// HKDF, built here on rind's HMAC, and the keys it fills.
#[test]
fn hkdf() {
    for algorithm in [
        hkdf::HKDF_SHA1_FOR_LEGACY_USE_ONLY,
        hkdf::HKDF_SHA256,
        hkdf::HKDF_SHA384,
        hkdf::HKDF_SHA512,
    ] {
        let ikm = [0x0b; 22];
        let info: [&[u8]; 2] = [b"label", b"context"];
        let derive = |ikm: &[u8], out: &mut [u8]| {
            let prk = hkdf::Salt::new(algorithm, b"salt").extract(ikm);
            prk.expand(&info, Len(out.len()))
                .unwrap()
                .fill(out)
                .unwrap();
            hkdf::Prk::from(prk.expand(&info, algorithm).unwrap())
        };
        // Three blocks of the longest hash, and a partial one.
        let mut expected = [0u8; 200];
        derive(&ikm, &mut expected);

        secret(&ikm);
        let mut okm = [0u8; 200];
        let prk = derive(&ikm, &mut okm);
        public(&okm);
        assert_eq!(okm, expected, "{algorithm:?}");

        // Each key a secret `Okm` fills, used once, and its output declassified.
        let key = hmac::Key::from(prk.expand(&info, algorithm.hmac_algorithm()).unwrap());
        let tag = hmac::sign(&key, b"message");
        public(tag.as_ref());

        let key = aead::LessSafeKey::new(aead::UnboundKey::from(
            prk.expand(&info, &aead::AES_256_GCM).unwrap(),
        ));
        let nonce = aead::Nonce::assume_unique_for_key([0; 12]);
        let mut sealed = b"message".to_vec();
        key.seal_in_place_append_tag(nonce, aead::Aad::empty(), &mut sealed)
            .unwrap();
        public(&sealed[..]);

        let key = quic::HeaderProtectionKey::from(prk.expand(&info, &quic::AES_128).unwrap());
        let mask = key.new_mask(&[0; 16]).unwrap();
        public(&mask);
    }
}

struct Len(usize);

impl hkdf::KeyType for Len {
    fn len(&self) -> usize {
        self.0
    }
}

/// `open_within` moves the plaintext to the front of the buffer.
#[test]
fn open_within() {
    let key_bytes = [0x42; 16];
    let key = |key_bytes: &[u8]| {
        aead::LessSafeKey::new(aead::UnboundKey::new(&aead::AES_128_GCM, key_bytes).unwrap())
    };
    let nonce = || aead::Nonce::assume_unique_for_key([1; 12]);
    let mut sealed = b"prefix--message".to_vec();
    key(&key_bytes)
        .seal_in_place_append_tag(nonce(), aead::Aad::empty(), &mut sealed)
        .unwrap();

    secret(&key_bytes);
    let key = key(&key_bytes);
    let mut in_out = [&b"header"[..], &sealed].concat();
    let plaintext = key
        .open_within(nonce(), aead::Aad::empty(), &mut in_out, 6..)
        .unwrap();
    public(plaintext);
    assert_eq!(plaintext, b"prefix--message");
}

/// A stored PBKDF2 value shorter than the hash, which rind-ring compares itself.
#[test]
fn pbkdf2_short() {
    let iterations = NonZeroU32::new(2).unwrap();
    let password = *b"password";
    let mut stored = [0u8; 16];
    pbkdf2::derive(
        pbkdf2::PBKDF2_HMAC_SHA256,
        iterations,
        b"salt",
        &password,
        &mut stored,
    )
    .unwrap();

    secret(&password);
    secret(&stored);
    let result = pbkdf2::verify(
        pbkdf2::PBKDF2_HMAC_SHA256,
        iterations,
        b"salt",
        &password,
        &stored,
    );
    public(&result);
    assert_eq!(result, Ok(()));
}

/// Ed25519 PKCS#8, which rind-ring parses itself to take ring's encodings,
/// and a bare seed.
#[test]
fn ed25519() {
    let rng = rand::SystemRandom::new();
    let mut pkcs8 = signature::Ed25519KeyPair::generate_pkcs8(&rng)
        .unwrap()
        .as_ref()
        .to_vec();
    let expected = signature::Ed25519KeyPair::from_pkcs8(&pkcs8)
        .unwrap()
        .public_key()
        .as_ref()
        .to_vec();

    // RFC 8410's layout puts the 32-byte seed at offset 16.
    secret(&pkcs8[16..48]);
    for load in [
        signature::Ed25519KeyPair::from_pkcs8,
        signature::Ed25519KeyPair::from_pkcs8_maybe_unchecked,
    ] {
        let key_pair = load(&pkcs8).unwrap();
        public(key_pair.public_key().as_ref());
        assert_eq!(key_pair.public_key().as_ref(), expected);
    }

    let seed = pkcs8.split_off(16)[..32].to_vec();
    secret(&seed[..]);
    let key_pair = signature::Ed25519KeyPair::from_seed_unchecked(&seed).unwrap();
    public(key_pair.public_key().as_ref());
    assert_eq!(key_pair.public_key().as_ref(), expected);
}
