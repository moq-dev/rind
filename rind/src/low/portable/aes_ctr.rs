// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

use super::aes::AesKey;
use crate::low::generic::ctr;

/// XORs AES-CTR keystream into `inout`.
///
/// The counter blocks are `nonce` followed by the big-endian `counter`,
/// `counter + 1`, and so on, wrapping within 32 bits.
pub(crate) fn apply(key: &AesKey, nonce: &[u8; 12], counter: u32, inout: &mut [u8]) {
    ctr::blocks(nonce, counter, inout, |ivec, blocks| {
        let counter = u32::from_be_bytes(ivec[12..].try_into().unwrap());
        for (i, block) in (0u32..).zip(blocks) {
            let mut keystream = *ivec;
            keystream[12..].copy_from_slice(&counter.wrapping_add(i).to_be_bytes());
            for (b, k) in block.iter_mut().zip(key.encrypt_block(&keystream)) {
                *b ^= k;
            }
        }
    })
}
