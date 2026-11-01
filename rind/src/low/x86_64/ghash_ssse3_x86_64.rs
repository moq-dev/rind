// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

//! GHASH on SSSE3 alone, using aws-lc's `ghash-ssse3-x86_64` routine, for
//! CPUs without PCLMULQDQ.
//!
//! The assembly is aws-lc's, imported by `admin/import-aws-lc`, and the table
//! setup ports aws-lc's `gcm_init_ssse3` from `crypto/fipsmodule/modes/gcm.c`.
//! The routine multiplies by H four bits at a time, selecting each multiple
//! with `pshufb` from rows it reads in a fixed order, so its timing is
//! independent of the key and data. It is not formally verified: its
//! correctness rests on its use and testing in BoringSSL and aws-lc, and on
//! rind's tests of it against PCLMULQDQ, the portable model, Wycheproof, and
//! aws-lc-rs.

use super::cpu::HaveSsse3;
use crate::low;

/// A GHASH key as the routine reads it: aws-lc's `u128 Htable[16]`, holding
/// the multiples 0, H, 2H, ... 15H transposed, so row `i` holds byte `i` of
/// each multiple.
#[repr(C, align(16))]
pub(crate) struct Ssse3Table([[u8; 16]; 16]);

impl Ssse3Table {
    /// Precomputes for the GHASH key `h`, AES's encryption of the zero block.
    pub(crate) fn new(h: &[u8; 16], _: HaveSsse3) -> Self {
        let (hi, lo) = h.split_at(8);
        // aws-lc's `u128` is `{ hi, lo }`, and `gcm_init_ssse3` starts from
        // `{ H[1], H[0] }`, with the key's halves read big-endian as `H`.
        let mut v = [
            u64::from_be_bytes(lo.try_into().unwrap()),
            u64::from_be_bytes(hi.try_into().unwrap()),
        ];
        // Multiplying by x three times gives the multiples for single bits,
        // and their sums the rest.
        let mut multiples = [[0u64; 2]; 16];
        for i in [8, 4, 2, 1] {
            multiples[i] = v;
            v = times_x(v);
        }
        for i in 3..16usize {
            multiples[i] = xor(multiples[i & (i - 1)], multiples[i & i.wrapping_neg()]);
        }

        let mut rows = [[0u8; 16]; 16];
        for (j, [hi, lo]) in multiples.into_iter().enumerate() {
            for (i, b) in hi
                .to_le_bytes()
                .into_iter()
                .chain(lo.to_le_bytes())
                .enumerate()
            {
                rows[i][j] = b;
            }
        }
        Self(rows)
    }

    /// Folds whole blocks of `input` into the GHASH state `xi`, held in the
    /// byte order of a block.
    pub(crate) fn ghash(&self, xi: &mut [u8; 16], input: &[[u8; 16]]) {
        // aws-lc's loop runs at least once.
        if input.is_empty() {
            return;
        }
        // SAFETY: `input` is `size_of_val(input)` readable bytes, a multiple
        // of 16, and `self` an aligned table. The routine needs only SSSE3,
        // and only a `HaveSsse3` token builds `self`.
        unsafe { gcm_ghash_ssse3(xi, self, input.as_ptr().cast(), size_of_val(input)) }
    }
}

impl Drop for Ssse3Table {
    fn drop(&mut self) {
        low::zeroise_value(self);
    }
}

impl low::generic::zeroise::Zeroable for Ssse3Table {}

/// aws-lc's `gcm_reduce_1bit`: `v` times x in GHASH's bit-reflected field.
fn times_x([hi, lo]: [u64; 2]) -> [u64; 2] {
    let carry = 0xe100_0000_0000_0000 & 0u64.wrapping_sub(hi & 1);
    [(lo << 63) | (hi >> 1), (lo >> 1) ^ carry]
}

fn xor([a0, a1]: [u64; 2], [b0, b1]: [u64; 2]) -> [u64; 2] {
    [a0 ^ b0, a1 ^ b1]
}

#[repr(C, align(16))]
struct Bytes([u8; 16]);

#[repr(C, align(16))]
struct Words([u64; 2]);

static REVERSE_BYTES: Bytes = Bytes(include!("aws_lc/ghash-ssse3-x86_64.reverse_bytes.rs"));
static LOW4_MASK: Words = Words(include!("aws_lc/ghash-ssse3-x86_64.low4_mask.rs"));

// It takes the System V ABI on every OS, since its text is aws-lc's ELF and
// Mach-O flavors, which read their arguments from its registers.
#[unsafe(naked)]
unsafe extern "sysv64" fn gcm_ghash_ssse3(
    xi: *mut [u8; 16],
    htable: *const Ssse3Table,
    input: *const u8,
    len: usize,
) {
    #[cfg(not(target_vendor = "apple"))]
    core::arch::naked_asm!(
        include_str!("aws_lc/gcm_ghash_ssse3.linux.s"),
        reverse_bytes = sym REVERSE_BYTES,
        low4_mask = sym LOW4_MASK,
        options(att_syntax),
    );
    #[cfg(target_vendor = "apple")]
    core::arch::naked_asm!(
        include_str!("aws_lc/gcm_ghash_ssse3.apple.s"),
        reverse_bytes = sym REVERSE_BYTES,
        low4_mask = sym LOW4_MASK,
        options(att_syntax),
    );
}
