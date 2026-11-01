// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

use core::arch::x86_64::*;

/// Viewing `table` as `height` rows of `width` words, copies row `index`
/// into `z`, reading every row, with the SSE2 every x86_64 CPU has. `width`
/// is even.
pub(crate) fn bignum_copy_row_from_table_sse2(
    z: &mut [u64],
    table: &[u64],
    _height: u64,
    width: u64,
    index: u64,
) {
    debug_assert!(z.len() as u64 == width);
    debug_assert!(width.is_multiple_of(2));
    debug_assert!(table.len() as u64 == _height * width);

    // SAFETY: every x86_64 CPU has SSE2
    unsafe { _bignum_copy_row_from_table_sse2(z, table, width, index) }
}

#[target_feature(enable = "sse2")]
fn _bignum_copy_row_from_table_sse2(z: &mut [u64], table: &[u64], width: u64, index: u64) {
    super::cpu::prefetch(table, 16);

    z.fill(0);

    // SSE2 compares 32-bit lanes at most, which suffices: a window indexes
    // fewer than 2^32 rows.
    let desired_index = _mm_set1_epi32(index as i32);
    let ones = _mm_set1_epi32(1);
    let mut index = _mm_setzero_si128();

    for row in table.chunks_exact(width as usize) {
        let mask = _mm_cmpeq_epi32(index, desired_index);
        index = _mm_add_epi32(index, ones);

        let (chunks, _) = z.as_chunks_mut::<2>();
        for (i, zz) in chunks.iter_mut().enumerate() {
            // SAFETY: `row` is `width` words, and `2 * i + 2 <= width`
            let word = unsafe { _mm_loadu_si128(row.as_ptr().add(2 * i).cast()) };
            // SAFETY: `zz` is exactly 2 words, readable and writable
            unsafe {
                let acc = _mm_loadu_si128(zz.as_ptr().cast());
                _mm_storeu_si128(
                    zz.as_mut_ptr().cast(),
                    _mm_xor_si128(acc, _mm_and_si128(word, mask)),
                );
            }
        }
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    // Every even width up to two 8n blocks and a tail, at every index
    // including past the end, against s2n-bignum's scalar routine.
    #[test]
    fn matches_scalar() {
        for width in (2..=34u64).step_by(2) {
            let table: Vec<u64> = (0..16 * width)
                .map(|i| i.wrapping_mul(0x9e3779b97f4a7c15))
                .collect();
            for index in 0..=16 {
                let mut want = vec![1; width as usize];
                let mut got = vec![2; width as usize];
                super::super::bignum_copy_row_from_table::bignum_copy_row_from_table(
                    &mut want, &table, 16, width, index,
                );
                bignum_copy_row_from_table_sse2(&mut got, &table, 16, width, index);
                assert_eq!(got, want, "width {width}, index {index}");
            }
        }
    }
}
