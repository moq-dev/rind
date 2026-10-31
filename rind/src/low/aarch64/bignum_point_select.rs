// Written for Graviola by Joe Birr-Pixton, 2024.
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

use core::arch::aarch64::*;
use core::mem;

/// Viewing table as rows of 12 words width, copy the 12 words at
/// table[idx - 1] into z.  If `idx` is zero or larger than `height`,
/// `z` is set to zero (ie, the affine point at infinity).
///
/// This is useful to select an affine p384 point from a table of
/// precomputed points.
pub(crate) fn bignum_aff_point_select_p384(z: &mut [u64; 12], table: &[u64], index: u8) {
    select::<12, 6>(z, table, index)
}

/// As [`bignum_aff_point_select_p384`], for an affine p521 point of 18 words.
pub(crate) fn bignum_aff_point_select_p521(z: &mut [u64; 18], table: &[u64], index: u8) {
    select::<18, 9>(z, table, index)
}

/// Selects a row of `N` words, held in `V` 128-bit vectors.
fn select<const N: usize, const V: usize>(z: &mut [u64; N], table: &[u64], index: u8) {
    const { assert!(N == 2 * V) };
    // SAFETY: crate requires `neon` cpu feature
    unsafe { _select::<N, V>(z, table, index) }
}

#[target_feature(enable = "neon")]
fn _select<const N: usize, const V: usize>(z: &mut [u64; N], table: &[u64], index: u8) {
    // SAFETY: uint32x4_t and u128 have the same number and meaning of bits
    let mut acc: [uint32x4_t; V] = [unsafe { mem::transmute::<u128, uint32x4_t>(0) }; V];

    let desired_index = vdupq_n_u32(index as u32);
    let ones = vdupq_n_u32(1);
    let mut index = ones;

    let (rows, _) = table.as_chunks::<N>();
    for row in rows {
        let mask = vceqq_u32(index, desired_index);
        index = vaddq_u32(index, ones);

        for (i, acc) in acc.iter_mut().enumerate() {
            // SAFETY: `row` is `N` readable words, and `2 * i + 2 <= N`
            let word = unsafe { vld1q_u32(row.as_ptr().add(2 * i).cast()) };
            *acc = veorq_u32(*acc, vandq_u32(word, mask));
        }
    }

    for (i, acc) in acc.iter().enumerate() {
        // SAFETY: `z` is `N` writable words, and `2 * i + 2 <= N`
        unsafe { vst1q_u32(z.as_mut_ptr().add(2 * i).cast(), *acc) };
    }
}
