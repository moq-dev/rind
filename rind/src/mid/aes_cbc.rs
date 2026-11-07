// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

use core::fmt;
use core::hint::black_box;

use super::aes::expand_key;
use crate::Error;
use crate::cipher::Algorithm;
use crate::low::{self, AesDecKey, AesKey, Entry, Zeroable, aes_cbc, zeroise_value};

/// An AES key that encrypts in CBC mode, as WebCrypto's AES-CBC, pyca's
/// `modes.CBC`, and Dart's `AesCbc` do; wiped on drop.
///
/// CBC is unauthenticated, so anyone who can alter a ciphertext and learn
/// whether it decrypted can decrypt it: Vaudenay's padding oracle needs only
/// that error, however it surfaces. Send a MAC over the IV and ciphertext
/// with each message, as encrypt-then-MAC and RFC 7518's `A128CBC-HS256`
/// do, or use [`crate::aead`] instead.
///
/// Each message needs a fresh random IV from [`crate::rand::fill`]: an IV
/// an attacker can predict, such as a counter, leaks whether a plaintext
/// block equals one they chose.
pub struct AesCbcEncryptingKey {
    key: AesKey,
    key_len: usize,
}

impl AesCbcEncryptingKey {
    /// Expands `key` for `algorithm`, failing with [`Error::WrongLength`] if
    /// it is not that algorithm's key length.
    pub fn new(algorithm: &'static Algorithm, key: &[u8]) -> Result<Self, Error> {
        let _entry = Entry::new_secret();
        if key.len() != algorithm.key_len {
            return Err(Error::WrongLength);
        }
        Ok(Self {
            key: expand_key(key),
            key_len: key.len(),
        })
    }

    /// Pads `in_out` with PKCS#7, 1 to 16 bytes each holding the count, and
    /// encrypts it in place under `iv`.
    pub fn encrypt<InOut>(&self, iv: &[u8; 16], in_out: &mut InOut)
    where
        InOut: AsMut<[u8]> + for<'a> Extend<&'a u8>,
    {
        let _entry = Entry::new_secret();
        let pad = 16 - in_out.as_mut().len() % 16;
        in_out.extend(&[pad as u8; 16][..pad]);
        self.encrypt_in_place(iv, in_out.as_mut().as_chunks_mut().0);
    }

    /// Encrypts `in_out` in place under `iv`, without padding.
    ///
    /// Fails with [`Error::WrongLength`], leaving `in_out` unchanged, if
    /// `in_out` is not a whole number of 16-byte blocks.
    pub fn encrypt_blocks(&self, iv: &[u8; 16], in_out: &mut [u8]) -> Result<(), Error> {
        let _entry = Entry::new_secret();
        let (blocks, []) = in_out.as_chunks_mut() else {
            return Err(Error::WrongLength);
        };
        self.encrypt_in_place(iv, blocks);
        Ok(())
    }

    fn encrypt_in_place(&self, iv: &[u8; 16], blocks: &mut [[u8; 16]]) {
        low::ct::secret_slice(blocks);
        aes_cbc::encrypt(&self.key, iv, blocks);
        low::ct::public_slice(blocks);
    }
}

/// An AES key that decrypts in CBC mode; wiped on drop.
///
/// Decryption is unauthenticated: check the MAC over the IV and ciphertext
/// before decrypting, and never let a sender learn that decryption failed,
/// or the error is a padding oracle. See [`AesCbcEncryptingKey`].
pub struct AesCbcDecryptingKey {
    key: AesDecKey,
    key_len: usize,
}

impl AesCbcDecryptingKey {
    /// Expands `key` for `algorithm`, failing with [`Error::WrongLength`] if
    /// it is not that algorithm's key length.
    pub fn new(algorithm: &'static Algorithm, key: &[u8]) -> Result<Self, Error> {
        let _entry = Entry::new_secret();
        if key.len() != algorithm.key_len {
            return Err(Error::WrongLength);
        }
        // Mark a copy, as `expand_key` does.
        let mut copy = [0u8; 32];
        let copy_key = &mut copy[..key.len()];
        copy_key.copy_from_slice(key);
        low::ct::secret_slice(copy_key);
        Ok(Self {
            key: AesDecKey::new(copy_key),
            key_len: key.len(),
        })
    }

    /// Decrypts `in_out` in place under `iv`, checks and removes its PKCS#7
    /// padding, and returns the plaintext at its front.
    ///
    /// Fails with [`Error::DecryptFailed`], leaving `in_out` unchanged, if it
    /// is empty or not a whole number of 16-byte blocks, and clearing it if
    /// its padding is malformed. The padding check runs in constant time.
    pub fn decrypt<'a>(&self, iv: &[u8; 16], in_out: &'a mut [u8]) -> Result<&'a mut [u8], Error> {
        let _entry = Entry::new_secret();
        let (blocks, []) = in_out.as_chunks_mut() else {
            return Err(Error::DecryptFailed);
        };
        if blocks.is_empty() {
            return Err(Error::DecryptFailed);
        }
        aes_cbc::decrypt(&self.key, iv, blocks);

        let last = blocks.last().unwrap();
        let pad = last[15];
        // Bad if `pad` is 0 or over 16, or any of the last `pad` bytes is not
        // `pad`, computed without a branch on them.
        let mut bad = ct_mask_lt(16, pad) | ct_mask_lt(pad, 1);
        for (i, byte) in (0u8..).zip(last.iter().rev()) {
            bad |= ct_mask_lt(i, pad) & (byte ^ pad);
        }

        if low::ct::into_public(black_box(bad)) != 0 {
            in_out.fill(0);
            return Err(Error::DecryptFailed);
        }
        // The plaintext, and so its length, is public once it is returned.
        let len = in_out.len() - usize::from(low::ct::into_public(pad));
        low::ct::public_slice(in_out);
        Ok(&mut in_out[..len])
    }

    /// Decrypts `in_out` in place under `iv`, without padding.
    ///
    /// Fails with [`Error::DecryptFailed`], leaving `in_out` unchanged, if
    /// `in_out` is not a whole number of 16-byte blocks.
    pub fn decrypt_blocks(&self, iv: &[u8; 16], in_out: &mut [u8]) -> Result<(), Error> {
        let _entry = Entry::new_secret();
        let (blocks, []) = in_out.as_chunks_mut() else {
            return Err(Error::DecryptFailed);
        };
        aes_cbc::decrypt(&self.key, iv, blocks);
        low::ct::public_slice(blocks);
        Ok(())
    }
}

// The key length is not secret, but is wiped with the key so that the whole
// value reads zero, as `AesCtr`'s counter width is.
impl Drop for AesCbcEncryptingKey {
    fn drop(&mut self) {
        zeroise_value(self);
    }
}

impl Zeroable for AesCbcEncryptingKey {}

impl Drop for AesCbcDecryptingKey {
    fn drop(&mut self) {
        zeroise_value(self);
    }
}

impl Zeroable for AesCbcDecryptingKey {}

impl fmt::Debug for AesCbcEncryptingKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AesCbcEncryptingKey")
            .field("algorithm", crate::cipher::aes(self.key_len))
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for AesCbcDecryptingKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AesCbcDecryptingKey")
            .field("algorithm", crate::cipher::aes(self.key_len))
            .finish_non_exhaustive()
    }
}

/// All ones if `a < b`, else zero, without a branch.
#[inline]
fn ct_mask_lt(a: u8, b: u8) -> u8 {
    (u32::from(black_box(a)).wrapping_sub(u32::from(b)) >> 8) as u8
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::cipher::{AES_128, AES_192, AES_256};

    fn keys(key: &[u8]) -> (AesCbcEncryptingKey, AesCbcDecryptingKey) {
        (
            AesCbcEncryptingKey::new(crate::cipher::aes(key.len()), key).unwrap(),
            AesCbcDecryptingKey::new(crate::cipher::aes(key.len()), key).unwrap(),
        )
    }

    #[test]
    fn sp800_38a() {
        // F.2.1 to F.2.6, CBC-AES128, CBC-AES192, and CBC-AES256, both ways
        let iv = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
        let iv: &[u8; 16] = iv[..].try_into().unwrap();
        let pt = hex::decode(
            "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51\
             30c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710",
        )
        .unwrap();
        for (key, ct) in [
            (
                "2b7e151628aed2a6abf7158809cf4f3c",
                "7649abac8119b246cee98e9b12e9197d5086cb9b507219ee95db113a917678b2\
                 73bed6b8e3c1743b7116e69e222295163ff1caa1681fac09120eca307586e1a7",
            ),
            (
                "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",
                "4f021db243bc633d7178183a9fa071e8b4d9ada9ad7dedf4e5e738763f69145a\
                 571b242012fb7ae07fa9baac3df102e008b0e27988598881d920a9e64f5615cd",
            ),
            (
                "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
                "f58c4c04d6e5f1ba779eabfb5f7bfbd69cfc4e967edb808d679f777bc6702c7d\
                 39f23369a9d9bacfa530e26304231461b2eb05e2c39be9fcda6c19078c6a9d1b",
            ),
        ] {
            let (enc, dec) = keys(&hex::decode(key).unwrap());
            let mut buf = pt.clone();
            enc.encrypt_blocks(iv, &mut buf).unwrap();
            assert_eq!(hex::encode(&buf), ct);
            dec.decrypt_blocks(iv, &mut buf).unwrap();
            assert_eq!(buf, pt);

            // padded, the same blocks then one of padding
            let mut buf = pt.clone();
            enc.encrypt(iv, &mut buf);
            assert_eq!(hex::encode(&buf[..64]), ct);
            assert_eq!(buf.len(), 80);
            assert_eq!(dec.decrypt(iv, &mut buf).unwrap(), pt);
        }
    }

    #[test]
    fn debug_shows_only_the_algorithm() {
        let (enc, dec) = keys(&[0x42; 32]);
        assert_eq!(
            format!("{enc:?}"),
            "AesCbcEncryptingKey { algorithm: Algorithm { key_len: 32 }, .. }"
        );
        assert_eq!(
            format!("{dec:?}"),
            "AesCbcDecryptingKey { algorithm: Algorithm { key_len: 32 }, .. }"
        );
    }

    #[test]
    fn key_length_must_match_algorithm() {
        let key = [0u8; 33];
        for algorithm in [&AES_128, &AES_192, &AES_256] {
            for len in 0..=key.len() {
                let supported = len == algorithm.key_len;
                assert_eq!(
                    AesCbcEncryptingKey::new(algorithm, &key[..len]).is_ok(),
                    supported
                );
                assert_eq!(
                    AesCbcDecryptingKey::new(algorithm, &key[..len]).is_ok(),
                    supported
                );
            }
        }
    }

    // Every length round trips, padded to the next whole block, and only a
    // whole number of blocks is accepted unpadded. The lengths cross the
    // backends' 2- and 8-block loops.
    #[test]
    fn lengths() {
        let (enc, dec) = keys(&[0x42; 32]);
        let iv = [0x24; 16];
        for len in 0..=150usize {
            let msg: Vec<u8> = (0..len as u8).collect();
            let mut buf = msg.clone();
            enc.encrypt(&iv, &mut buf);
            assert_eq!(buf.len(), (len / 16 + 1) * 16, "{len}");
            assert_eq!(dec.decrypt(&iv, &mut buf).unwrap(), msg, "{len}");

            let whole = len.is_multiple_of(16);
            let mut buf = msg.clone();
            let result = enc.encrypt_blocks(&iv, &mut buf);
            assert_eq!(result.is_ok(), whole, "{len}");
            if !whole {
                assert_eq!(buf, msg, "refused encrypt wrote");
            }
            let result = dec.decrypt_blocks(&iv, &mut buf);
            assert_eq!(result.is_ok(), whole, "{len}");
            assert_eq!(buf, msg, "{len}");

            // padded decryption refuses what no encryption makes, untouched
            if len == 0 || !whole {
                let mut buf = msg.clone();
                assert_eq!(dec.decrypt(&iv, &mut buf), Err(Error::DecryptFailed));
                assert_eq!(buf, msg, "refused decrypt wrote");
            }
        }
    }

    // Each way PKCS#7 padding can be malformed fails alike and clears the
    // buffer, and each well-formed padding length is removed.
    #[test]
    fn padding() {
        let (enc, dec) = keys(&[0x42; 16]);
        let iv = [0x24; 16];
        let check = |padded: &[u8]| {
            let mut buf = padded.to_vec();
            enc.encrypt_blocks(&iv, &mut buf).unwrap();
            let result = dec.decrypt(&iv, &mut buf).map(|pt| pt.len());
            if result.is_err() {
                assert!(buf.iter().all(|b| *b == 0), "failure left plaintext");
            }
            result
        };

        for pad in 1..=16u8 {
            let mut block = [0xaa; 32];
            block[32 - usize::from(pad)..].fill(pad);
            assert_eq!(check(&block), Ok(32 - usize::from(pad)), "pad {pad}");

            // each padding byte but the last altered
            for i in 1..pad {
                let mut bad = block;
                bad[31 - usize::from(i)] ^= 0x01;
                assert_eq!(check(&bad), Err(Error::DecryptFailed), "pad {pad} byte {i}");
            }
        }

        let mut block = [0x10; 32];
        for last in [0, 17, 0x20, 0x80, 0xff] {
            block[31] = last;
            assert_eq!(check(&block), Err(Error::DecryptFailed), "last byte {last}");
        }
    }

    // armv7's AES-CBC on the crypto extension, which valgrind hides, for each
    // key size, with a secret key and message, for `admin/ct-qemu`. The
    // message's 7 blocks take the decryption's 3-block loop and its tail.
    #[cfg(rind_backend = "arm")]
    #[test]
    #[ignore = "admin/ct-qemu runs it under qemu-arm"]
    fn ct_qemu_aes_cbc() {
        use crate::low::ct_qemu;

        let seed = ct_qemu::seed().to_le_bytes();
        let bytes = |n| seed.iter().cycle().take(n).copied().collect::<Vec<u8>>();
        for algorithm in [&AES_128, &AES_192, &AES_256] {
            let key = bytes(algorithm.key_len);
            let enc = ct_qemu::traced(|| AesCbcEncryptingKey::new(algorithm, &key).unwrap());
            let dec = ct_qemu::traced(|| AesCbcDecryptingKey::new(algorithm, &key).unwrap());
            assert!(matches!(enc.key, AesKey::Hw(_)), "the crypto extension");

            let iv = bytes(16).try_into().unwrap();
            let mut msg = bytes(6 * 16 + 5);
            ct_qemu::traced(|| enc.encrypt(&iv, &mut msg));
            ct_qemu::traced(|| dec.decrypt(&iv, &mut msg)).unwrap();
        }
    }
}
