//! <h1 align="center">rind-snow</h1>
//! <img width="40%" align="right" src="https://raw.githubusercontent.com/moq-dev/rind/main/admin/logo.png">
//!
//! This crate provides a [`CryptoResolver`] for [snow](https://github.com/mcginty/snow), backed by [rind](https://github.com/moq-dev/rind/), a fork of [Graviola](https://github.com/ctz/graviola/).
//!
//! Hand it to each builder:
//!
//! ```rust
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let params: snow::params::NoiseParams = "Noise_XX_25519_ChaChaPoly_SHA256".parse()?;
//! let key = snow::Builder::with_resolver(params.clone(), rind_snow::resolver()?)
//!     .generate_keypair()?;
//! let initiator = snow::Builder::with_resolver(params, rind_snow::resolver()?)
//!     .local_private_key(&key.private)?
//!     .build_initiator()?;
//! # Ok(())
//! # }
//! ```
//!
//! It resolves X25519, ChaCha20-Poly1305, AES-256-GCM, SHA-256, SHA-512, and
//! the system random source, and nothing else: building a protocol that
//! names BLAKE2 or Curve448 fails. For BLAKE2, put snow's default resolver
//! behind it with [`FallbackResolver`](snow::resolvers::FallbackResolver);
//! snow 0.10 has no Curve448.
//!
//! rind is young, and Noise is a security-critical handshake: weigh that
//! before deploying it.

use core::fmt;

use rind::agreement::{self, PrivateKey, PublicKey, Scalar};
use rind::{aead, digest};
use snow::Error;
use snow::params::{CipherChoice, DHChoice, HashChoice};
use snow::resolvers::{BoxedCryptoResolver, CryptoResolver};
use snow::types::{Cipher, Dh, Hash, Random};

/// A CPU feature rind requires that this CPU lacks.
#[derive(Debug)]
pub struct MissingFeature(rind::cpu::MissingFeature);

impl fmt::Display for MissingFeature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl std::error::Error for MissingFeature {}

/// Returns a snow [`CryptoResolver`] backed by rind, or the CPU feature rind
/// requires that this CPU lacks.
pub fn resolver() -> Result<BoxedCryptoResolver, MissingFeature> {
    rind::cpu::check().map_err(MissingFeature)?;
    Ok(Box::new(Resolver))
}

/// Built only by [`resolver`], so no primitive runs before the CPU check.
struct Resolver;

impl CryptoResolver for Resolver {
    fn resolve_rng(&self) -> Option<Box<dyn Random>> {
        Some(Box::new(SystemRandom))
    }

    fn resolve_dh(&self, choice: &DHChoice) -> Option<Box<dyn Dh>> {
        match choice {
            DHChoice::Curve25519 => Some(Box::new(X25519(None))),
            _ => None,
        }
    }

    fn resolve_hash(&self, choice: &HashChoice) -> Option<Box<dyn Hash>> {
        let (name, algorithm, block_len) = match choice {
            HashChoice::SHA256 => ("SHA256", &digest::SHA256, 64),
            HashChoice::SHA512 => ("SHA512", &digest::SHA512, 128),
            _ => return None,
        };
        Some(Box::new(Hasher {
            name,
            algorithm,
            block_len,
            context: digest::Context::new(algorithm),
        }))
    }

    fn resolve_cipher(&self, choice: &CipherChoice) -> Option<Box<dyn Cipher>> {
        // Noise puts the 64-bit counter after four zero bytes: big-endian for
        // AES-GCM, little-endian for ChaCha20-Poly1305.
        let (name, algorithm, counter): (_, _, fn(u64) -> [u8; 8]) = match choice {
            CipherChoice::ChaChaPoly => ("ChaChaPoly", &aead::CHACHA20_POLY1305, u64::to_le_bytes),
            CipherChoice::AESGCM => ("AESGCM", &aead::AES_256_GCM, u64::to_be_bytes),
            // Reached only when another crate turns on snow's XChaChaPoly.
            #[allow(unreachable_patterns)]
            _ => return None,
        };
        // A random key until snow sets one, so a caller that seals before
        // `set` gets a message no one can open, rather than a panic or a
        // message under a known key. snow fails to build a session on `None`.
        let mut key = [0u8; 32];
        rind::rand::fill(&mut key).ok()?;
        Some(Box::new(Aead {
            name,
            algorithm,
            counter,
            key: aead::Key::new(algorithm, &key).ok()?,
        }))
    }
}

struct SystemRandom;

impl Random for SystemRandom {
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Error> {
        rind::rand::fill(dest).map_err(|_| Error::Rng)
    }
}

/// An X25519 key pair, or `None` until snow sets or generates one.
///
/// `set` cannot fail, so a key of the wrong length leaves `None`, and the
/// first DH that needs it fails with [`Error::Dh`]. Noise uses every static
/// key it sends in a DH, so the handshake fails before it completes.
struct X25519(Option<KeyPair>);

struct KeyPair {
    private: PrivateKey,
    // `privkey` returns a borrow, so the scalar is kept, and wiped on drop.
    scalar: Scalar,
    public: PublicKey,
}

impl Dh for X25519 {
    fn name(&self) -> &'static str {
        "25519"
    }

    fn pub_len(&self) -> usize {
        32
    }

    fn priv_len(&self) -> usize {
        32
    }

    fn set(&mut self, privkey: &[u8]) {
        self.0 = PrivateKey::from_scalar(&agreement::X25519, privkey)
            .ok()
            .map(|private| KeyPair {
                scalar: private.to_scalar(),
                public: private.public_key(),
                private,
            });
    }

    fn generate(&mut self, rng: &mut dyn Random) -> Result<(), Error> {
        // Drawn from snow's resolved source rather than rind's, as snow asks.
        let mut scalar = [0u8; 32];
        rng.try_fill_bytes(&mut scalar)?;
        self.set(&scalar);
        Ok(())
    }

    fn pubkey(&self) -> &[u8] {
        self.0.as_ref().map_or(&[], |key| key.public.as_ref())
    }

    fn privkey(&self) -> &[u8] {
        self.0.as_ref().map_or(&[], |key| key.scalar.as_ref())
    }

    fn dh(&self, pubkey: &[u8], out: &mut [u8]) -> Result<(), Error> {
        let key = self.0.as_ref().ok_or(Error::Dh)?;
        // snow passes its whole remote key buffer, sized for its largest
        // curve, so the key is its first 32 bytes.
        let peer = pubkey.get(..32).ok_or(Error::Dh)?;
        // Refuses X25519's all-zero output from a small-order point, as
        // aws-lc-rs does (RFC 7748 section 6.1).
        let secret = key.private.agree(peer).map_err(|_| Error::Dh)?;
        out.get_mut(..32)
            .ok_or(Error::Dh)?
            .copy_from_slice(secret.as_ref());
        Ok(())
    }
}

struct Aead {
    name: &'static str,
    algorithm: &'static aead::Algorithm,
    counter: fn(u64) -> [u8; 8],
    key: aead::Key,
}

impl Aead {
    fn nonce(&self, n: u64) -> aead::Nonce {
        let mut nonce = [0u8; 12];
        nonce[4..].copy_from_slice(&(self.counter)(n));
        aead::Nonce::assume_unique_for_key(nonce)
    }
}

impl Cipher for Aead {
    fn name(&self) -> &'static str {
        self.name
    }

    fn set(&mut self, key: &[u8; 32]) {
        self.key = aead::Key::new(self.algorithm, key).expect("both ciphers take 32-byte keys");
    }

    /// Panics if `out` is shorter than `plaintext` and its tag: snow checks
    /// that for every message but a handshake's static key, and this cannot
    /// return an error.
    fn encrypt(&self, nonce: u64, authtext: &[u8], plaintext: &[u8], out: &mut [u8]) -> usize {
        let (body, rest) = out.split_at_mut(plaintext.len());
        body.copy_from_slice(plaintext);
        // snow caps a message at 65535 bytes, far under either cipher's limit.
        let tag = self
            .key
            .seal_in_place_separate_tag(self.nonce(nonce), authtext, body)
            .expect("snow's messages fit the cipher's limits");
        rest[..16].copy_from_slice(tag.as_ref());
        plaintext.len() + 16
    }

    fn decrypt(
        &self,
        nonce: u64,
        authtext: &[u8],
        ciphertext: &[u8],
        out: &mut [u8],
    ) -> Result<usize, Error> {
        let (body, tag) = ciphertext.split_last_chunk::<16>().ok_or(Error::Decrypt)?;
        let out = out.get_mut(..body.len()).ok_or(Error::Decrypt)?;
        out.copy_from_slice(body);
        let tag = aead::Tag::try_from(&tag[..]).map_err(|_| Error::Decrypt)?;
        self.key
            .open_in_place_separate_tag(self.nonce(nonce), authtext, tag, out)
            .map_err(|_| Error::Decrypt)?;
        Ok(body.len())
    }
}

struct Hasher {
    name: &'static str,
    algorithm: &'static digest::Algorithm,
    block_len: usize,
    context: digest::Context,
}

impl Hash for Hasher {
    fn name(&self) -> &'static str {
        self.name
    }

    fn block_len(&self) -> usize {
        self.block_len
    }

    fn hash_len(&self) -> usize {
        self.algorithm.output_len()
    }

    fn reset(&mut self) {
        self.context = digest::Context::new(self.algorithm);
    }

    fn input(&mut self, data: &[u8]) {
        self.context.update(data);
    }

    /// Writes the digest and starts a new one, as snow's own resolver does.
    fn result(&mut self, out: &mut [u8]) {
        let digest = self.context.finish();
        out[..digest.as_ref().len()].copy_from_slice(digest.as_ref());
    }
}
