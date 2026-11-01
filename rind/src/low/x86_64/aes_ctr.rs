// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

use core::arch::x86_64::*;

use super::aes::{AesKey, HwKey};
use super::cpu::HaveAvx;
use crate::low::generic::ctr;

/// XORs AES-CTR keystream into `inout`.
///
/// The counter blocks are `nonce` followed by the big-endian `counter`,
/// `counter + 1`, and so on, wrapping within 32 bits.
pub(crate) fn apply(key: &AesKey, nonce: &[u8; 12], counter: u32, inout: &mut [u8]) {
    match (key, HaveAvx::check()) {
        (AesKey::Hw(key), Some(token)) => ctr::by8(counter, inout, |counter, chunk| {
            apply_8_avx(key, nonce, counter, chunk, token)
        }),
        (AesKey::Hw(key), None) => ctr::blocks(nonce, counter, inout, |ivec, blocks| {
            hw_ctr32(key, ivec, blocks)
        }),
        (AesKey::Vpaes(key), _) => ctr::blocks(nonce, counter, inout, |ivec, blocks| {
            key.ctr32(ivec, blocks)
        }),
    }
}

fn apply_8_avx(key: &HwKey, nonce: &[u8; 12], counter: u32, inout: &mut [u8; 128], _: HaveAvx) {
    let (rk_first, rks, rk_last) = key.round_keys();
    // SAFETY: only a `HaveAesHardware` token builds `key`, and the `HaveAvx`
    // token proves AVX.
    unsafe { _apply_8(rk_first, rks, rk_last, nonce, counter, inout) }
}

/// XORs counter-mode keystream into whole blocks with aws-lc's AES-NI
/// routine, the fastest without AVX.
///
/// The counter blocks are `ivec`, then `ivec` with its last four bytes, a
/// big-endian counter, incremented with 32-bit wrapping.
fn hw_ctr32(key: &HwKey, ivec: &[u8; 16], inout: &mut [[u8; 16]]) {
    // SAFETY: `inout` is `inout.len()` readable and writable blocks, which
    // aws-lc allows to alias, and `key` an `AES_KEY`. Only a `HaveAesHardware`
    // token builds `key`, proving the AES-NI and SSE4.1 the routine uses. It
    // returns at once for zero blocks.
    unsafe {
        aes_hw_ctr32_encrypt_blocks(
            inout.as_ptr().cast(),
            inout.as_mut_ptr().cast(),
            inout.len(),
            key.as_aes_key(),
            ivec,
        )
    }
}

// It takes the System V ABI on every OS, since its text is aws-lc's ELF and
// Mach-O flavors, which read their arguments from its registers.
#[unsafe(naked)]
unsafe extern "sysv64" fn aes_hw_ctr32_encrypt_blocks(
    input: *const u8,
    output: *mut u8,
    blocks: usize,
    key: *const u8,
    ivec: *const [u8; 16],
) {
    #[cfg(not(target_vendor = "apple"))]
    core::arch::naked_asm!(
        include_str!("aws_lc/aes_hw_ctr32_encrypt_blocks.linux.s"),
        options(att_syntax),
    );
    #[cfg(target_vendor = "apple")]
    core::arch::naked_asm!(
        include_str!("aws_lc/aes_hw_ctr32_encrypt_blocks.apple.s"),
        options(att_syntax),
    );
}

#[target_feature(enable = "aes,avx")]
fn _apply_8(
    rk_first: __m128i,
    rks: &[__m128i],
    rk_last: __m128i,
    nonce: &[u8; 12],
    counter: u32,
    inout: &mut [u8; 128],
) {
    let mut base = [0u8; 16];
    base[..12].copy_from_slice(nonce);
    // SAFETY: `base` is 16 bytes and readable
    let base = unsafe { _mm_loadu_si128(base.as_ptr().cast()) };
    // lane 3 holds bytes 12..16 little-endian, so swap to store big-endian
    let block = |i: u32| {
        let c = _mm_insert_epi32::<3>(base, counter.wrapping_add(i).swap_bytes() as i32);
        _mm_xor_si128(c, rk_first)
    };

    let mut b0 = block(0);
    let mut b1 = block(1);
    let mut b2 = block(2);
    let mut b3 = block(3);
    let mut b4 = block(4);
    let mut b5 = block(5);
    let mut b6 = block(6);
    let mut b7 = block(7);

    for rk in rks {
        b0 = _mm_aesenc_si128(b0, *rk);
        b1 = _mm_aesenc_si128(b1, *rk);
        b2 = _mm_aesenc_si128(b2, *rk);
        b3 = _mm_aesenc_si128(b3, *rk);
        b4 = _mm_aesenc_si128(b4, *rk);
        b5 = _mm_aesenc_si128(b5, *rk);
        b6 = _mm_aesenc_si128(b6, *rk);
        b7 = _mm_aesenc_si128(b7, *rk);
    }

    let b0 = _mm_aesenclast_si128(b0, rk_last);
    let b1 = _mm_aesenclast_si128(b1, rk_last);
    let b2 = _mm_aesenclast_si128(b2, rk_last);
    let b3 = _mm_aesenclast_si128(b3, rk_last);
    let b4 = _mm_aesenclast_si128(b4, rk_last);
    let b5 = _mm_aesenclast_si128(b5, rk_last);
    let b6 = _mm_aesenclast_si128(b6, rk_last);
    let b7 = _mm_aesenclast_si128(b7, rk_last);

    // SAFETY: `inout` is 128 bytes and readable
    let (p0, p1, p2, p3, p4, p5, p6, p7) = unsafe {
        (
            _mm_loadu_si128(inout.as_ptr().add(0).cast()),
            _mm_loadu_si128(inout.as_ptr().add(16).cast()),
            _mm_loadu_si128(inout.as_ptr().add(32).cast()),
            _mm_loadu_si128(inout.as_ptr().add(48).cast()),
            _mm_loadu_si128(inout.as_ptr().add(64).cast()),
            _mm_loadu_si128(inout.as_ptr().add(80).cast()),
            _mm_loadu_si128(inout.as_ptr().add(96).cast()),
            _mm_loadu_si128(inout.as_ptr().add(112).cast()),
        )
    };

    // SAFETY: `inout` is 128 bytes and writable
    unsafe {
        _mm_storeu_si128(inout.as_mut_ptr().add(0).cast(), _mm_xor_si128(b0, p0));
        _mm_storeu_si128(inout.as_mut_ptr().add(16).cast(), _mm_xor_si128(b1, p1));
        _mm_storeu_si128(inout.as_mut_ptr().add(32).cast(), _mm_xor_si128(b2, p2));
        _mm_storeu_si128(inout.as_mut_ptr().add(48).cast(), _mm_xor_si128(b3, p3));
        _mm_storeu_si128(inout.as_mut_ptr().add(64).cast(), _mm_xor_si128(b4, p4));
        _mm_storeu_si128(inout.as_mut_ptr().add(80).cast(), _mm_xor_si128(b5, p5));
        _mm_storeu_si128(inout.as_mut_ptr().add(96).cast(), _mm_xor_si128(b6, p6));
        _mm_storeu_si128(inout.as_mut_ptr().add(112).cast(), _mm_xor_si128(b7, p7));
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::low::x86_64::cpu::HaveAesHardware;
    use crate::low::x86_64::vpaes_x86_64::VpaesKey;

    // Every other test sees only the path the CPU picks, so the three are
    // compared here: rind's AVX intrinsics, aws-lc's AES-NI routine, and
    // vpaes, for each key size, across the 32-bit counter's wrap, at lengths
    // that take aws-lc's single-block shortcut and each of its tails.
    #[test]
    fn paths_match() {
        let Some(_) = HaveAesHardware::check() else {
            return;
        };
        let bytes = |n: usize, seed: u32| -> Vec<u8> {
            (0..n as u32)
                .map(|i| (i.wrapping_add(seed).wrapping_mul(0x9e3779b9) >> 24) as u8)
                .collect()
        };
        for (key_len, seed) in [16, 32].into_iter().zip(1..) {
            let key = bytes(key_len, seed);
            let aes_key = AesKey::new(&key);
            let AesKey::Hw(hw) = &aes_key else {
                unreachable!("the CPU has AES-NI")
            };
            let vpaes = VpaesKey::new(&key);
            let nonce: [u8; 12] = bytes(12, seed).try_into().unwrap();
            for counter in [0, 1, u32::MAX - 3, u32::MAX] {
                for len in [1, 15, 16, 17, 32, 48, 64, 80, 96, 112, 127, 128, 129, 300] {
                    let what = format!("{key_len}-byte key, counter {counter}, {len} bytes");
                    let mut want = bytes(len, counter);
                    ctr::blocks(&nonce, counter, &mut want, |ivec, blocks| {
                        vpaes.ctr32(ivec, blocks)
                    });

                    let mut got = bytes(len, counter);
                    ctr::blocks(&nonce, counter, &mut got, |ivec, blocks| {
                        hw_ctr32(hw, ivec, blocks)
                    });
                    assert_eq!(got, want, "{what}");

                    if let Some(token) = HaveAvx::check() {
                        let mut got = bytes(len, counter);
                        ctr::by8(counter, &mut got, |counter, chunk| {
                            apply_8_avx(hw, &nonce, counter, chunk, token)
                        });
                        assert_eq!(got, want, "{what}");
                    }
                }
            }
        }
    }
}
