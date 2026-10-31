// Written for Graviola by Joe Birr-Pixton, 2024.
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

use core::arch::x86_64::*;

/// Viewing table as rows of 12 words width, copy the 12 words at
/// table[idx - 1] into z.  If `idx` is zero or larger than `height`,
/// `z` is set to zero (ie, the affine point at infinity).
///
/// This is useful to select an affine p384 point from a table of
/// precomputed points.
pub(crate) fn bignum_aff_point_select_p384(z: &mut [u64; 12], table: &[u64], index: u8) {
    select::<12, 3>(z, table, index)
}

/// As [`bignum_aff_point_select_p384`], for an affine p521 point of 18 words.
pub(crate) fn bignum_aff_point_select_p521(z: &mut [u64; 18], table: &[u64], index: u8) {
    select::<18, 4>(z, table, index)
}

/// Selects a row of `N` words, held in `V` 256-bit vectors and, if `N` is
/// not a multiple of 4, a 128-bit tail.
fn select<const N: usize, const V: usize>(z: &mut [u64; N], table: &[u64], index: u8) {
    const { assert!(N == 4 * V || N == 4 * V + 2) };
    // SAFETY: this crate requires the `avx` and `avx2` cpu features
    unsafe { _select::<N, V>(z, table, index) }
}

#[target_feature(enable = "avx,avx2")]
fn _select<const N: usize, const V: usize>(z: &mut [u64; N], table: &[u64], index: u8) {
    super::cpu::prefetch(table, N);

    let mut acc = [_mm256_setzero_si256(); V];
    let mut tail = _mm_setzero_si128();

    let desired_index = _mm256_set1_epi32(index as i32);
    let ones = _mm256_set1_epi32(1);
    let mut index = ones;

    let (rows, _) = table.as_chunks::<N>();
    for row in rows {
        let mask = _mm256_cmpeq_epi32(index, desired_index);
        index = _mm256_add_epi32(index, ones);

        for (i, acc) in acc.iter_mut().enumerate() {
            // SAFETY: `row` is `N` readable words, and `4 * i + 4 <= N`
            let word = unsafe { _mm256_loadu_si256(row.as_ptr().add(4 * i).cast()) };
            *acc = _mm256_xor_si256(*acc, _mm256_and_si256(word, mask));
        }
        if N > 4 * V {
            // SAFETY: `row` is `N` readable words, and `N == 4 * V + 2`
            let word = unsafe { _mm_loadu_si128(row.as_ptr().add(4 * V).cast()) };
            tail = _mm_xor_si128(tail, _mm_and_si128(word, _mm256_castsi256_si128(mask)));
        }
    }

    for (i, acc) in acc.iter().enumerate() {
        // SAFETY: `z` is `N` writable words, and `4 * i + 4 <= N`
        unsafe { _mm256_storeu_si256(z.as_mut_ptr().add(4 * i).cast(), *acc) };
    }
    if N > 4 * V {
        // SAFETY: `z` is `N` writable words, and `N == 4 * V + 2`
        unsafe { _mm_storeu_si128(z.as_mut_ptr().add(4 * V).cast(), tail) };
    }
}
