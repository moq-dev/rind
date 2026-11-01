// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

use super::aes::{AesKey, HwKey};
use crate::low::generic::ctr;

/// XORs AES-CTR keystream into `inout`.
///
/// The counter blocks are `nonce` followed by the big-endian `counter`,
/// `counter + 1`, and so on, wrapping within 32 bits.
pub(crate) fn apply(key: &AesKey, nonce: &[u8; 12], counter: u32, inout: &mut [u8]) {
    match key {
        AesKey::Hw(key) => ctr::blocks(nonce, counter, inout, |ivec, blocks| {
            hw_ctr32(key, ivec, blocks)
        }),
        AesKey::Vpaes(key) => ctr::blocks(nonce, counter, inout, |ivec, blocks| {
            key.ctr32(ivec, blocks)
        }),
    }
}

/// XORs counter-mode keystream into whole blocks with aws-lc's AES-NI
/// routine, the fastest with or without AVX.
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

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::low::x86_64::cpu::HaveAesHardware;
    use crate::low::x86_64::vpaes_x86_64::VpaesKey;

    // Every other test sees only the path the CPU picks, so the two are
    // compared here: aws-lc's AES-NI routine and vpaes, for each key size,
    // across the 32-bit counter's wrap, at lengths that take aws-lc's
    // single-block shortcut and each of its tails.
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
                }
            }
        }
    }
}
