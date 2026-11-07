//! Constant-time checks for each secret path, run under valgrind by
//! `admin/ctgrind`.
//!
//! Secret inputs are marked undefined, so memcheck flags any branch or memory
//! index that depends on them. Outputs that are public by design are marked
//! defined before the test checks them.

use crabgrind::memcheck::{self, MemState};
use crabgrind::valgrind::{self, RunningMode};
use snow::params::{CipherChoice, DHChoice, HashChoice};
use snow::resolvers::{CryptoResolver, DefaultResolver};

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

#[test]
fn x25519() {
    let resolver = rind_snow::resolver().unwrap();
    let mut peer = DefaultResolver.resolve_dh(&DHChoice::Curve25519).unwrap();
    peer.set(&[0x24; 32]);
    let mut reference = DefaultResolver.resolve_dh(&DHChoice::Curve25519).unwrap();
    reference.set(&[0x42; 32]);
    let mut expected = [0u8; 32];
    reference.dh(peer.pubkey(), &mut expected).unwrap();

    let key = [0x42u8; 32];
    secret(&key);
    let mut dh = resolver.resolve_dh(&DHChoice::Curve25519).unwrap();
    dh.set(&key);
    let mut shared = [0u8; 32];
    dh.dh(peer.pubkey(), &mut shared).unwrap();

    public(dh.pubkey());
    public(&shared);
    assert_eq!(dh.pubkey(), reference.pubkey());
    assert_eq!(shared, expected);
}

#[test]
fn ciphers() {
    let resolver = rind_snow::resolver().unwrap();
    for choice in [CipherChoice::ChaChaPoly, CipherChoice::AESGCM] {
        let key = [0x42u8; 32];
        let plaintext = [0x17u8; 100];
        secret(&key);
        secret(&plaintext);
        let mut cipher = resolver.resolve_cipher(&choice).unwrap();
        cipher.set(&key);
        let mut sealed = [0u8; 116];
        assert_eq!(cipher.encrypt(1, b"ad", &plaintext, &mut sealed), 116);
        public(&sealed);

        let mut opened = [0u8; 100];
        assert_eq!(cipher.decrypt(1, b"ad", &sealed, &mut opened), Ok(100));
        public(&opened);
        assert_eq!(opened, [0x17; 100], "{choice:?}");

        // Rekeying seals the key under the old one.
        cipher.rekey();
        cipher.encrypt(2, b"ad", &plaintext, &mut sealed);
        public(&sealed);
    }
}

#[test]
fn hashes() {
    let resolver = rind_snow::resolver().unwrap();
    for choice in [HashChoice::SHA256, HashChoice::SHA512] {
        let mut reference = DefaultResolver.resolve_hash(&choice).unwrap();
        let len = reference.hash_len();
        let chaining_key = [0x42u8; 64];
        let input = [0x24u8; 32];
        let mut expected = [[0u8; 64]; 3];
        let [e1, e2, e3] = &mut expected;
        reference.hkdf(&chaining_key[..len], &input, 3, e1, e2, e3);

        // Noise's chaining key and DH outputs are secret, and reach the hash
        // as both HMAC keys and data.
        secret(&chaining_key);
        secret(&input);
        let mut hash = resolver.resolve_hash(&choice).unwrap();
        let mut out = [[0u8; 64]; 3];
        let [o1, o2, o3] = &mut out;
        hash.hkdf(&chaining_key[..len], &input, 3, o1, o2, o3);

        public(&out);
        assert_eq!(out, expected, "{choice:?}");
    }
}
