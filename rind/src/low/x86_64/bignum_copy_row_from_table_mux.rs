// Written for Graviola by Joe Birr-Pixton, 2024.
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

use super::cpu::HaveAvx2;

/// Multiplex between specialisations of `bignum_copy_row_from_table`
#[inline]
pub(crate) fn bignum_copy_row_from_table(
    z: &mut [u64],
    table: &[u64],
    height: u64,
    width: u64,
    index: u64,
) {
    match (HaveAvx2::check(), width) {
        (Some(token), 16) => {
            super::bignum_copy_row_from_table_16_avx2::bignum_copy_row_from_table_16_avx2(
                z, table, height, index, token,
            )
        }
        (Some(token), width) if width.is_multiple_of(8) => {
            super::bignum_copy_row_from_table_8n_avx2::bignum_copy_row_from_table_8n_avx2(
                z, table, height, width, index, token,
            )
        }
        (_, width) => super::bignum_copy_row_from_table::bignum_copy_row_from_table(
            z, table, height, width, index,
        ),
    }
}
