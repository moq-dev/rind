// Written for Graviola by Joe Birr-Pixton, 2024.
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

use crate::low::x86_64;
use crate::low::x86_64::cpu::{HaveAvx, HaveAvx2, HaveSha256, is_intel};

pub(crate) fn sha256_compress_blocks(state: &mut [u32; 8], blocks: &[u8]) {
    if let Some(token) = HaveSha256::check() {
        x86_64::sha256::sha256_compress_blocks_shaext(state, blocks, token)
    } else if let Some(token) = HaveAvx::check().filter(|_| is_intel()) {
        x86_64::sha256::sha256_compress_blocks_avx(state, blocks, token)
    } else if let Some(token) = HaveAvx2::check() {
        x86_64::sha256::sha256_compress_blocks_avx2(state, blocks, token)
    } else {
        x86_64::sha256::sha256_compress_blocks_ssse3(state, blocks)
    }
}
