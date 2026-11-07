//! Checks that the secret copies rind-aws-lc-rs keeps on the heap, beyond
//! the rind keys it wraps, are wiped before they are freed.
//!
//! rind's own `tests/zeroing.rs` checks that its keys wipe themselves. This
//! one installs an allocator that, while armed with a secret, counts each
//! freed block still holding it, and checks no block does once the values
//! that held the secret are dropped. Inline values are boxed so they live on
//! the heap too.
//!
//! Is this test sound? No, as rind's isn't: it reads a block the program has
//! freed, including bytes it never initialized, such as padding and a
//! vector's spare capacity. It reads them with volatile byte loads into
//! plain integers before handing the block back to `System`, so the compiler
//! cannot assume their contents, and the block is still allocated as far as
//! the system allocator knows. In theory it could still miss a failed wipe;
//! `detects_a_leak` checks that it catches one in practice.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

use rind_aws_lc_rs::encoding::{
    AsBigEndian, AsDer, Curve25519SeedBin, EcPrivateKeyBin, EcPrivateKeyRfc5915Der, Pkcs8V1Der,
    Pkcs8V2Der,
};
use rind_aws_lc_rs::{agreement, cipher, kem, rsa, signature};

/// How many bytes of a secret the allocator looks for.
const NEEDLE_LEN: usize = 16;

/// The secret being watched for, if any.
static NEEDLE: Mutex<Option<[u8; NEEDLE_LEN]>> = Mutex::new(None);
/// Blocks freed while still holding the needle.
static LEAKS: AtomicUsize = AtomicUsize::new(0);

struct Scan;

// SAFETY: forwards every call to `System`, and only reads a block it is
// about to free; the module documentation explains what that read risks.
unsafe impl GlobalAlloc for Scan {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: the caller's contract, passed on.
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // Locking allocates nothing, so this cannot recurse.
        if let Some(needle) = *NEEDLE.lock().unwrap_or_else(|e| e.into_inner()) {
            // The last `NEEDLE_LEN` bytes read, oldest first.
            let mut window = [0u8; NEEDLE_LEN];
            for i in 0..layout.size() {
                window.copy_within(1.., 0);
                // SAFETY: `ptr` is `layout.size()` bytes that `System` keeps
                // allocated until the call below.
                window[NEEDLE_LEN - 1] = unsafe { ptr.add(i).read_volatile() };
                if i + 1 >= NEEDLE_LEN && window == needle {
                    LEAKS.fetch_add(1, Ordering::Relaxed);
                    break;
                }
            }
        }
        // SAFETY: the caller's contract, passed on.
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static ALLOCATOR: Scan = Scan;

/// Serializes the tests, which share the allocator's needle.
static SERIAL: Mutex<()> = Mutex::new(());

/// Counts the blocks freed while `drop` runs that still hold the first
/// bytes of `secret`.
fn leaks(secret: &[u8], drop: impl FnOnce()) -> usize {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let needle = secret[..NEEDLE_LEN].try_into().unwrap();
    LEAKS.store(0, Ordering::Relaxed);
    *NEEDLE.lock().unwrap() = Some(needle);
    drop();
    *NEEDLE.lock().unwrap() = None;
    LEAKS.load(Ordering::Relaxed)
}

/// Bytes unlikely to appear anywhere else.
fn distinct<const N: usize>(start: u8) -> [u8; N] {
    core::array::from_fn(|i| start.wrapping_add((i as u8).wrapping_mul(29)))
}

/// The check sees a secret left on the heap, so a clean result means something.
#[test]
fn detects_a_leak() {
    let secret: [u8; 32] = distinct(1);
    let copy = secret.to_vec();
    assert_eq!(leaks(&secret, || drop(copy)), 1);
}

/// A decrypting key's PKCS#8 copy, with every algorithm's key cached and the
/// last clone dropped.
#[test]
fn rsa_oaep() {
    let pkcs8 = include_bytes!("../../rind/src/high/rsa/rsa2048.pkcs8.der");
    // The last bytes are the CRT coefficient, which only the private key holds.
    let secret = &pkcs8[pkcs8.len() - NEEDLE_LEN..];
    let leaked = leaks(secret, || {
        let key = rsa::PrivateDecryptingKey::from_pkcs8(pkcs8).unwrap();
        let public = rsa::OaepPublicEncryptingKey::new(key.public_key()).unwrap();
        let decrypting = rsa::OaepPrivateDecryptingKey::new(key.clone()).unwrap();
        for algorithm in [
            &rsa::OAEP_SHA1_MGF1SHA1,
            &rsa::OAEP_SHA256_MGF1SHA256,
            &rsa::OAEP_SHA384_MGF1SHA384,
            &rsa::OAEP_SHA512_MGF1SHA512,
        ] {
            let mut ciphertext = [0; 256];
            let ciphertext = public
                .encrypt(algorithm, b"message", &mut ciphertext, None)
                .unwrap();
            let mut plaintext = [0; 256];
            let plaintext = decrypting
                .decrypt(algorithm, ciphertext, &mut plaintext, None)
                .unwrap();
            assert_eq!(plaintext, b"message");
        }
        let der: Pkcs8V1Der<'static> = key.as_der().unwrap();
        assert_eq!(der.as_ref(), pkcs8);
    });
    assert_eq!(leaked, 0);
}

/// An Ed25519 seed, and the PKCS#8 documents and encodings holding it.
#[test]
fn ed25519() {
    let seed: [u8; 32] = distinct(3);
    let leaked = leaks(&seed, || {
        let key = Box::new(signature::Ed25519KeyPair::from_seed_unchecked(&seed).unwrap());
        let exported = Box::new(key.seed().unwrap());
        let bin: Curve25519SeedBin<'static> = exported.as_be_bytes().unwrap();
        assert_eq!(bin.as_ref(), seed);
        let _v1 = key.to_pkcs8v1().unwrap();
        let _v2 = key.to_pkcs8().unwrap();
        let _der_v1: Pkcs8V1Der<'static> = key.as_der().unwrap();
        let _der_v2: Pkcs8V2Der<'static> = key.as_der().unwrap();
    });
    assert_eq!(leaked, 0);
}

/// Key agreement private keys and their encodings.
#[test]
fn agreement() {
    let scalar: [u8; 32] = distinct(5);
    let leaked = leaks(&scalar, || {
        let key = agreement::PrivateKey::from_private_key(&agreement::ECDH_P256, &scalar);
        let key = Box::new(key.unwrap());
        let bin: EcPrivateKeyBin<'static> = key.as_be_bytes().unwrap();
        assert_eq!(bin.as_ref(), scalar);
        let _sec1: EcPrivateKeyRfc5915Der<'static> = key.as_der().unwrap();
        let _pkcs8: Pkcs8V1Der<'static> = key.as_der().unwrap();
    });
    assert_eq!(leaked, 0);

    let seed: [u8; 32] = distinct(7);
    let leaked = leaks(&seed, || {
        let key = agreement::PrivateKey::from_private_key(&agreement::X25519, &seed);
        let key = Box::new(key.unwrap());
        let bin: Curve25519SeedBin<'static> = key.as_be_bytes().unwrap();
        assert_eq!(bin.as_ref(), seed);
    });
    assert_eq!(leaked, 0);
}

/// Raw cipher key bytes, held until a mode expands them.
#[test]
fn cipher() {
    let key_bytes: [u8; 32] = distinct(9);
    let leaked = leaks(&key_bytes, || {
        let key = cipher::UnboundCipherKey::new(&cipher::AES_256, &key_bytes).unwrap();
        drop(Box::new(key));
        let key = cipher::UnboundCipherKey::new(&cipher::AES_256, &key_bytes).unwrap();
        drop(Box::new(cipher::EncryptingKey::ctr(key).unwrap()));
    });
    assert_eq!(leaked, 0);
}

/// An ML-KEM shared secret, on both sides.
#[test]
fn kem() {
    let decapsulation = kem::DecapsulationKey::generate(&kem::ML_KEM_768).unwrap();
    let (ciphertext, sent) = decapsulation
        .encapsulation_key()
        .unwrap()
        .encapsulate()
        .unwrap();
    let received = decapsulation.decapsulate(ciphertext).unwrap();
    let mut secret = [0; 32];
    secret.copy_from_slice(sent.as_ref());
    assert_eq!(received.as_ref(), secret);
    assert_eq!(leaks(&secret, || drop((sent, received))), 0);
}
