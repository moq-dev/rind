// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

//! GHASH on NEON alone, using aws-lc's `ghash-neon-armv8` routines, for CPUs
//! without PMULL's 64-bit carry-less multiply.
//!
//! The assembly is aws-lc's, imported by `admin/import-aws-lc`. It builds the
//! 128-bit product from NEON's 8-bit polynomial multiplies, so its timing is
//! independent of the key and data. It is not formally verified: its
//! correctness rests on its use and testing in OpenSSL, BoringSSL, and aws-lc,
//! and on rind's tests of it against PMULL, the portable model, Wycheproof,
//! and aws-lc-rs.

use crate::low;

/// A GHASH key, twisted as the routines read it: the first entry of aws-lc's
/// `u128 Htable[16]`, the only one they use.
#[repr(C, align(16))]
pub(crate) struct NeonTable([u64; 2]);

impl NeonTable {
    /// Precomputes for the GHASH key `h`, AES's encryption of the zero block.
    pub(crate) fn new(h: &[u8; 16]) -> Self {
        let (hi, lo) = h.split_at(8);
        let h = [
            u64::from_be_bytes(hi.try_into().unwrap()),
            u64::from_be_bytes(lo.try_into().unwrap()),
        ];
        let mut r = Self([0; 2]);
        // SAFETY: `r` is one `u128` of `Htable` and `h` two words. The
        // routine needs only NEON, which rind requires.
        unsafe { gcm_init_neon(&mut r, &h) };
        r
    }

    /// Folds whole blocks of `input` into the GHASH state `xi`, held in the
    /// byte order of a block.
    pub(crate) fn ghash(&self, xi: &mut [u8; 16], input: &[[u8; 16]]) {
        // aws-lc loads the first block before checking the length.
        if input.is_empty() {
            return;
        }
        // SAFETY: `input` is `size_of_val(input)` readable bytes, a multiple
        // of 16, and `self` a twisted key.
        unsafe { gcm_ghash_neon(xi, self, input.as_ptr().cast(), size_of_val(input)) }
    }
}

impl Drop for NeonTable {
    fn drop(&mut self) {
        low::zeroise_value(self);
    }
}

impl low::generic::zeroise::Zeroable for NeonTable {}

/// The masks the multiply splits its partial products with.
#[repr(C, align(16))]
struct Masks([u64; 4]);

static MASKS: Masks = Masks(include!("aws_lc/ghash-neon-armv8.masks.rs"));

#[unsafe(naked)]
unsafe extern "C" fn gcm_init_neon(htable: *mut NeonTable, h: *const [u64; 2]) {
    #[cfg(not(target_vendor = "apple"))]
    core::arch::naked_asm!(include_str!("aws_lc/gcm_init_neon.linux.s"));
    #[cfg(target_vendor = "apple")]
    core::arch::naked_asm!(include_str!("aws_lc/gcm_init_neon.apple.s"));
}

#[unsafe(naked)]
unsafe extern "C" fn gcm_ghash_neon(
    xi: *mut [u8; 16],
    htable: *const NeonTable,
    input: *const u8,
    len: usize,
) {
    #[cfg(not(target_vendor = "apple"))]
    core::arch::naked_asm!(
        include_str!("aws_lc/gcm_ghash_neon.linux.s"),
        masks = sym MASKS,
    );
    #[cfg(target_vendor = "apple")]
    core::arch::naked_asm!(
        include_str!("aws_lc/gcm_ghash_neon.apple.s"),
        masks = sym MASKS,
    );
}
