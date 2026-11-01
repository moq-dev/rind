// Written for Graviola by Joe Birr-Pixton, 2024.
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

use super::aes::HwKey;
use super::aes128_gcm_dec::aes128_gcm_dec;
use super::aes128_gcm_enc::aes128_gcm_enc;
use super::aes256_gcm_dec::aes256_gcm_dec;
use super::aes256_gcm_dec_alt::aes256_gcm_dec_alt;
use super::aes256_gcm_enc::aes256_gcm_enc;
use super::aes256_gcm_enc_alt::aes256_gcm_enc_alt;
use crate::low::ghash::{Ghash, GhashTable};
use crate::low::{AesKey, aes_ctr};

pub(crate) fn encrypt(
    key: &AesKey,
    ghash: &mut Ghash<'_>,
    initial_counter: &[u8; 16],
    aad: &[u8],
    cipher_inout: &mut [u8],
) {
    cipher::<true>(key, ghash, initial_counter, aad, cipher_inout)
}

pub(crate) fn decrypt(
    key: &AesKey,
    ghash: &mut Ghash<'_>,
    initial_counter: &[u8; 16],
    aad: &[u8],
    cipher_inout: &mut [u8],
) {
    cipher::<false>(key, ghash, initial_counter, aad, cipher_inout)
}

// AES-GCM encrypt (if `ENC` is `true`) or decrypt.
fn cipher<const ENC: bool>(
    key: &AesKey,
    ghash: &mut Ghash<'_>,
    initial_counter: &[u8; 16],
    aad: &[u8],
    cipher_inout: &mut [u8],
) {
    ghash.add(aad);

    let mut counter = *initial_counter;
    inc32(&mut counter);

    let (AesKey::Hw(hw_key), GhashTable::Pmull(table)) = (key, ghash.table) else {
        return composed::<ENC>(key, ghash, &counter, cipher_inout);
    };

    let (blocks, remainder) = cipher_inout.as_chunks_mut::<16>();

    if !blocks.is_empty() {
        let mut tag = ghash.state();
        let htable = &table.htable;
        let [htable4 @ .., _, _, _, _, _, _] = htable;
        let (inout, len) = (blocks.as_mut_ptr(), blocks.len());
        // SAFETY: only a `HaveCryptoExt` token builds `AesKey128` and
        // `AesKey256`, proving the `aes` cpu feature, `eight_way` proves
        // `sha3`, and `inout` is valid for reads and writes of `len`
        // blocks. The kernels' proofs assume the input and output do not
        // overlap, but every path through them loads each input block before
        // storing its output block and never reads an output back, so in
        // place they compute the same, as `admin/parse-asm/inplace.py`
        // checks.
        unsafe {
            match (hw_key, ENC, table.eight_way) {
                (HwKey::Aes128(k), true, _) => {
                    aes128_gcm_enc(inout, len, &mut tag, &mut counter, k.round_keys(), htable4)
                }
                (HwKey::Aes128(k), false, _) => {
                    aes128_gcm_dec(inout, len, &mut tag, &mut counter, k.round_keys(), htable4)
                }
                (HwKey::Aes256(k), true, None) => {
                    aes256_gcm_enc(inout, len, &mut tag, &mut counter, k.round_keys(), htable4)
                }
                (HwKey::Aes256(k), false, None) => {
                    aes256_gcm_dec(inout, len, &mut tag, &mut counter, k.round_keys(), htable4)
                }
                (HwKey::Aes256(k), true, Some(_)) => {
                    aes256_gcm_enc_alt(inout, len, &mut tag, &mut counter, k.round_keys(), htable)
                }
                (HwKey::Aes256(k), false, Some(_)) => {
                    aes256_gcm_dec_alt(inout, len, &mut tag, &mut counter, k.round_keys(), htable)
                }
            }
        }

        ghash.set_state(tag);
    }

    if !remainder.is_empty() {
        if !ENC {
            ghash.add(remainder);
        }

        let mut keystream = counter;
        key.encrypt_block(&mut keystream);
        for (c, k) in remainder.iter_mut().zip(keystream) {
            *c ^= k;
        }

        if ENC {
            ghash.add(remainder);
        }
    }
}

/// AES-CTR and GHASH in separate passes over each eight blocks, for keys
/// without the stitched kernels, as aws-lc composes vpaes and NEON GHASH.
fn composed<const ENC: bool>(
    key: &AesKey,
    ghash: &mut Ghash<'_>,
    counter: &[u8; 16],
    cipher_inout: &mut [u8],
) {
    let (nonce, ctr) = counter.split_at(12);
    let nonce = nonce.try_into().unwrap();
    let mut ctr = u32::from_be_bytes(ctr.try_into().unwrap());

    let (chunks, remainder) = cipher_inout.as_chunks_mut::<128>();
    for chunk in chunks {
        if !ENC {
            ghash.add(chunk);
        }
        aes_ctr::apply_8(key, nonce, ctr, chunk);
        if ENC {
            ghash.add(chunk);
        }
        ctr = ctr.wrapping_add(8);
    }

    if !ENC {
        ghash.add(remainder);
    }
    for block in remainder.chunks_mut(16) {
        let mut keystream = [0u8; 16];
        keystream[..12].copy_from_slice(nonce);
        keystream[12..].copy_from_slice(&ctr.to_be_bytes());
        key.encrypt_block(&mut keystream);
        for (c, k) in block.iter_mut().zip(keystream) {
            *c ^= k;
        }
        ctr = ctr.wrapping_add(1);
    }
    if ENC {
        ghash.add(remainder);
    }
}

/// Increments the big-endian 32-bit counter in the last four bytes of `block`.
fn inc32(block: &mut [u8; 16]) {
    let b = u128::from_be_bytes(*block);
    let ctr = (b as u32).wrapping_add(1);
    *block = (b & !0xffff_ffff | ctr as u128).to_be_bytes();
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::low::aarch64::cpu::HaveCryptoExt;
    use crate::low::aarch64::ghash::PmullTable;
    use crate::low::aarch64::ghash_neon_armv8::NeonTable;
    use crate::low::aarch64::vpaes_armv8::VpaesKey;

    // Every other test sees only the path the CPU picks, so the stitched
    // kernels are checked against vpaes and NEON GHASH here: each key size,
    // and AAD and message lengths around the block and eight-block
    // boundaries, both ways.
    #[test]
    fn kernels_match_composed() {
        let Some(token) = HaveCryptoExt::check() else {
            return;
        };
        let bytes = |n: usize, seed: u32| -> Vec<u8> {
            (0..n as u32)
                .map(|i| (i.wrapping_add(seed).wrapping_mul(0x9e3779b9) >> 24) as u8)
                .collect()
        };
        for key_len in [16, 32] {
            let key = bytes(key_len, 1);
            let hw = AesKey::new(&key);
            let vpaes = AesKey::Vpaes(VpaesKey::new(&key));
            let mut h = [0u8; 16];
            vpaes.encrypt_block(&mut h);
            let pmull = GhashTable::Pmull(PmullTable::new(u128::from_be_bytes(h), token));
            let neon = GhashTable::Neon(NeonTable::new(&h));

            for aad_len in [0, 1, 16, 17] {
                for msg_len in [0, 1, 15, 16, 17, 112, 127, 128, 129, 255, 256, 1000] {
                    // As GCM's: a 96-bit nonce, then a counter of 1.
                    let mut counter = [0u8; 16];
                    counter[..12].copy_from_slice(&bytes(12, msg_len as u32));
                    counter[15] = 1;
                    let aad = bytes(aad_len, 2);
                    let plain = bytes(msg_len, 3);

                    let (mut want, mut want_ghash) = (plain.clone(), Ghash::new(&pmull));
                    encrypt(&hw, &mut want_ghash, &counter, &aad, &mut want);
                    let (mut got, mut got_ghash) = (plain.clone(), Ghash::new(&neon));
                    encrypt(&vpaes, &mut got_ghash, &counter, &aad, &mut got);
                    let what = format!("{key_len} {aad_len} {msg_len}");
                    assert_eq!(got, want, "{what}");
                    assert_eq!(got_ghash.state(), want_ghash.state(), "{what}");

                    let mut ghash = Ghash::new(&neon);
                    decrypt(&vpaes, &mut ghash, &counter, &aad, &mut got);
                    assert_eq!(got, plain, "{what}");
                    assert_eq!(ghash.state(), want_ghash.state(), "{what}");
                }
            }
        }
    }
}
