// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

use crate::Error;
use crate::cipher::{self, Aes, ChaCha20};
use crate::low::{Zeroable, zeroise_value};

/// The length of a header-protection sample, in bytes, for every algorithm.
pub const SAMPLE_LEN: usize = 16;

/// A header-protection cipher, which fixes the key length a key must have.
#[derive(Debug)]
pub struct Algorithm {
    id: AlgorithmId,
}

#[derive(Debug)]
enum AlgorithmId {
    Aes128,
    Aes256,
    ChaCha20,
}

impl Algorithm {
    /// The length of a key, in bytes.
    pub fn key_len(&self) -> usize {
        match self.id {
            AlgorithmId::Aes128 => 16,
            AlgorithmId::Aes256 | AlgorithmId::ChaCha20 => 32,
        }
    }
}

/// AES-128 header protection, which QUIC pairs with AES-128-GCM.
pub static AES_128: Algorithm = Algorithm {
    id: AlgorithmId::Aes128,
};

/// AES-256 header protection, which QUIC pairs with AES-256-GCM.
pub static AES_256: Algorithm = Algorithm {
    id: AlgorithmId::Aes256,
};

/// ChaCha20 header protection, which QUIC pairs with ChaCha20-Poly1305.
pub static CHACHA20: Algorithm = Algorithm {
    id: AlgorithmId::ChaCha20,
};

/// A header-protection key, expanded once for its algorithm and wiped on drop.
pub struct HeaderProtectionKey(Key);

impl HeaderProtectionKey {
    /// Expands `key` for `algorithm`, failing with [`Error::WrongLength`] if
    /// it is not [`Algorithm::key_len`] bytes.
    pub fn new(algorithm: &'static Algorithm, key: &[u8]) -> Result<Self, Error> {
        Ok(Self(match algorithm.id {
            AlgorithmId::Aes128 => Key::Aes(Aes::new(&cipher::AES_128, key)?),
            AlgorithmId::Aes256 => Key::Aes(Aes::new(&cipher::AES_256, key)?),
            AlgorithmId::ChaCha20 => Key::ChaCha20(ChaCha20::new(
                key.try_into().map_err(|_| Error::WrongLength)?,
            )),
        }))
    }

    /// Computes the mask for `sample`: its first byte masks the packet's first
    /// byte, and the rest mask the packet number.
    ///
    /// Unlike aws-lc-rs, which takes a slice and fails unless it is 16 bytes,
    /// the sample is an array, so this cannot fail.
    pub fn new_mask(&self, sample: &[u8; SAMPLE_LEN]) -> [u8; 5] {
        match &self.0 {
            // RFC 9001 section 5.4.3
            Key::Aes(key) => {
                let mut block = *sample;
                key.encrypt_block(&mut block);
                core::array::from_fn(|i| block[i])
            }
            Key::ChaCha20(key) => key.header_protection_mask(sample),
        }
    }
}

// All-zero is the `Aes` variant with an all-zero key, which `Zeroable` requires
// to be valid: every field is a plain integer or vector.
//
// Boxing the AES key schedule would allocate for every key to save space only
// on ChaCha20 keys; the 32-bit arm schedule is small, so the lint is allowed
// rather than expected.
#[allow(clippy::large_enum_variant)]
#[repr(u8)]
enum Key {
    Aes(Aes),
    ChaCha20(ChaCha20),
}

impl Drop for Key {
    fn drop(&mut self) {
        // Wipes the discriminant and the space a smaller variant leaves unused,
        // not only the variant's own key.
        zeroise_value(self);
    }
}

impl Zeroable for Key {}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    #[test]
    fn key_length_must_match_algorithm() {
        let key = [0u8; 33];
        for algorithm in [&AES_128, &AES_256, &CHACHA20] {
            for len in 0..=key.len() {
                assert_eq!(
                    HeaderProtectionKey::new(algorithm, &key[..len]).is_ok(),
                    len == algorithm.key_len(),
                    "{algorithm:?} len {len}"
                );
            }
        }
    }

    #[test]
    fn rfc9001() {
        // Appendices A.2 and A.3 (AES-128) and A.5 (ChaCha20).
        for (algorithm, key, sample, mask) in [
            (
                &AES_128,
                "9f50449e04a0e810283a1e9933adedd2",
                "d1b1c98dd7689fb8ec11d242b123dc9b",
                "437b9aec36",
            ),
            (
                &AES_128,
                "c206b8d9b9f0f37644430b490eeaa314",
                "2cd0991cd25b0aac406a5816b6394100",
                "2ec0d8356a",
            ),
            (
                &CHACHA20,
                "25a282b9e82f06f21f488917a4fc8f1b73573685608597d0efcb076b0ab7a7a4",
                "5e5cd55c41f69080575d7999c25a5bfb",
                "aefefe7d03",
            ),
        ] {
            let key = HeaderProtectionKey::new(algorithm, &hex::decode(key).unwrap()).unwrap();
            let sample = hex::decode(sample).unwrap().try_into().unwrap();
            assert_eq!(hex::encode(key.new_mask(&sample)), mask);
        }
    }
}
