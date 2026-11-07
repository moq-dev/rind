// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

//! X25519 on curve25519-dalek's serial backend, which clamps the scalar and
//! masks the point's top bit as RFC7748 requires. dalek's precomputed Edwards
//! table serves the fixed base.

use curve25519_dalek::montgomery::MontgomeryPoint;

/// res := X25519(scalar, point), in little-endian words.
pub(crate) fn curve25519_x25519(res: &mut [u64; 4], scalar: &[u64; 4], point: &[u64; 4]) {
    *res = from_bytes(
        &MontgomeryPoint(to_bytes(point))
            .mul_clamped(to_bytes(scalar))
            .0,
    );
}

/// res := X25519(scalar, 9), in little-endian words.
pub(crate) fn curve25519_x25519base(res: &mut [u64; 4], scalar: &[u64; 4]) {
    *res = from_bytes(&MontgomeryPoint::mul_base_clamped(to_bytes(scalar)).0);
}

pub(crate) fn to_bytes(words: &[u64; 4]) -> [u8; 32] {
    let mut r = [0u8; 32];
    for (chunk, word) in r.as_chunks_mut::<8>().0.iter_mut().zip(words) {
        *chunk = word.to_le_bytes();
    }
    r
}

pub(crate) fn from_bytes(bytes: &[u8; 32]) -> [u64; 4] {
    let mut r = [0u64; 4];
    for (word, chunk) in r.iter_mut().zip(bytes.as_chunks::<8>().0) {
        *word = u64::from_le_bytes(*chunk);
    }
    r
}
