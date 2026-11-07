// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

use super::aes::AesKey;
use crate::low::generic::ctr;
use crate::low::portable::aes_ctr as portable;

/// XORs AES-CTR keystream into `inout`.
///
/// The counter blocks are `nonce` followed by the big-endian `counter`,
/// `counter + 1`, and so on, wrapping within 32 bits.
pub(crate) fn apply(key: &AesKey, nonce: &[u8; 12], counter: u32, inout: &mut [u8]) {
    match key {
        AesKey::Hw(key) => ctr::blocks(nonce, counter, inout, |ivec, blocks| {
            key.ctr32(ivec, blocks)
        }),
        AesKey::Portable(key) => portable::apply(key, nonce, counter, inout),
    }
}
