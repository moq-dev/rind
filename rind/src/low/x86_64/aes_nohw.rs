// Copyright (c) 2019, Google Inc.
// SPDX-License-Identifier: ISC

//! AES on SSE2 alone, for CPUs without SSSE3: aws-lc's
//! `crypto/fipsmodule/aes/aes_nohw.c` at commit
//! 91c93a8eb860e51482a871a8772cb9b1b310baea, in Rust, in its SSE2
//! configuration and encrypting only.
//!
//! It bitslices eight blocks into eight 128-bit words and computes the S-box
//! as a circuit of ANDs and XORs, so no branch or memory index depends on the
//! key or data. It is not formally verified: its correctness rests on its use
//! and testing in BoringSSL and aws-lc, and on rind's tests of it against
//! vpaes, FIPS-197, Wycheproof, and aws-lc-rs. It follows <https://bearssl.org/constanttime.html#aes>,
//! <https://eprint.iacr.org/2009/129.pdf>, and
//! <https://eprint.iacr.org/2009/191.pdf>.
//!
//! Bits and bytes are ordered little-endian, though "left" and "right" shifts
//! match the operations themselves. A word's 16 bytes stand for a block's 16
//! bytes in AES's column-major order. In a bitsliced batch, word `j` holds bit
//! `j` of each block byte, and bit `i` of each of its bytes comes from block
//! `i`. aws-lc calls the form around the transpose, where word `i` is block
//! `i`, "compact"; with 128-bit words it is the block's bytes unchanged.

use core::arch::x86_64::*;

use crate::low;

/// An expanded AES-128 or AES-256 encryption key: aws-lc's `AES_KEY`, the
/// compact round keys and the round count.
///
/// Each call bitslices the round keys again, as aws-lc does: holding them
/// bitsliced would take 1.9 KiB, which every `AesKey` would then occupy, on
/// every CPU.
pub(crate) struct NohwKey {
    rd_key: [__m128i; 15],
    rounds: usize,
}

impl NohwKey {
    /// Expands a 16- or 32-byte key.
    pub(crate) fn new(key: &[u8]) -> Self {
        // SAFETY: every x86_64 CPU has SSE2
        unsafe { set_encrypt_key(key) }
    }

    /// Encrypts one block in place.
    pub(crate) fn encrypt_block(&self, inout: &mut [u8; 16]) {
        // SAFETY: every x86_64 CPU has SSE2
        unsafe { encrypt(self, inout) }
    }

    /// XORs counter-mode keystream into whole blocks.
    ///
    /// The counter blocks are `ivec`, then `ivec` with its last four bytes,
    /// a big-endian counter, incremented with 32-bit wrapping.
    pub(crate) fn ctr32(&self, ivec: &[u8; 16], inout: &mut [[u8; 16]]) {
        // SAFETY: every x86_64 CPU has SSE2
        unsafe { ctr32_encrypt_blocks(self, ivec, inout) }
    }
}

impl Drop for NohwKey {
    fn drop(&mut self) {
        low::zeroise_value(self);
    }
}

impl low::generic::zeroise::Zeroable for NohwKey {}

/// Blocks per batch: one bit of each logical byte per block.
const BATCH_SIZE: usize = 8;

/// `BATCH_SIZE` blocks, bitsliced unless said otherwise: aws-lc's
/// `AES_NOHW_BATCH`.
#[derive(Clone, Copy)]
struct Batch {
    w: [__m128i; 8],
}

// Word operations, which keep the circuits below as aws-lc writes them.

#[target_feature(enable = "sse2")]
#[inline]
fn and(a: __m128i, b: __m128i) -> __m128i {
    _mm_and_si128(a, b)
}

#[target_feature(enable = "sse2")]
#[inline]
fn or(a: __m128i, b: __m128i) -> __m128i {
    _mm_or_si128(a, b)
}

#[target_feature(enable = "sse2")]
#[inline]
fn xor(a: __m128i, b: __m128i) -> __m128i {
    _mm_xor_si128(a, b)
}

#[target_feature(enable = "sse2")]
#[inline]
fn not(a: __m128i) -> __m128i {
    _mm_xor_si128(a, _mm_set1_epi32(-1))
}

// Block representations.

/// A block in compact form, which with 128-bit words is its bytes.
#[target_feature(enable = "sse2")]
#[inline]
fn compact_block(input: &[u8; 16]) -> __m128i {
    // SAFETY: `input` is 16 readable bytes
    unsafe { _mm_loadu_si128(input.as_ptr().cast()) }
}

#[target_feature(enable = "sse2")]
#[inline]
fn uncompact_block(out: &mut [u8; 16], input: __m128i) {
    // SAFETY: `out` is 16 writable bytes
    unsafe { _mm_storeu_si128(out.as_mut_ptr().cast(), input) }
}

/// Swaps the bits in `a & (mask << SHIFT)` with those in `b & mask`, `mask`
/// repeated in every 32-bit lane. `mask` and `mask << SHIFT` must not
/// overlap.
#[target_feature(enable = "sse2")]
#[inline]
fn swap_bits<const SHIFT: i32>(a: __m128i, b: __m128i, mask: u32) -> (__m128i, __m128i) {
    let swap = and(
        xor(_mm_srli_epi32::<SHIFT>(a), b),
        _mm_set1_epi32(mask as i32),
    );
    (xor(a, _mm_slli_epi32::<SHIFT>(swap)), xor(b, swap))
}

/// Converts `batch` to and from bitsliced form, transposing each 8 by 8
/// square of bits.
#[target_feature(enable = "sse2")]
fn transpose(batch: &mut Batch) {
    let w = &mut batch.w;
    // Swap bits with index 0 and 1 mod 2 (0x55 = 0b01010101).
    (w[0], w[1]) = swap_bits::<1>(w[0], w[1], 0x55555555);
    (w[2], w[3]) = swap_bits::<1>(w[2], w[3], 0x55555555);
    (w[4], w[5]) = swap_bits::<1>(w[4], w[5], 0x55555555);
    (w[6], w[7]) = swap_bits::<1>(w[6], w[7], 0x55555555);

    // Swap bits with index 0-1 and 2-3 mod 4 (0x33 = 0b00110011).
    (w[0], w[2]) = swap_bits::<2>(w[0], w[2], 0x33333333);
    (w[1], w[3]) = swap_bits::<2>(w[1], w[3], 0x33333333);
    (w[4], w[6]) = swap_bits::<2>(w[4], w[6], 0x33333333);
    (w[5], w[7]) = swap_bits::<2>(w[5], w[7], 0x33333333);

    // Swap bits with index 0-3 and 4-7 mod 8 (0x0f = 0b00001111).
    (w[0], w[4]) = swap_bits::<4>(w[0], w[4], 0x0f0f0f0f);
    (w[1], w[5]) = swap_bits::<4>(w[1], w[5], 0x0f0f0f0f);
    (w[2], w[6]) = swap_bits::<4>(w[2], w[6], 0x0f0f0f0f);
    (w[3], w[7]) = swap_bits::<4>(w[3], w[7], 0x0f0f0f0f);
}

/// Bitslices up to `BATCH_SIZE` blocks, leaving the rest zero.
#[target_feature(enable = "sse2")]
fn to_batch(input: &[[u8; 16]]) -> Batch {
    debug_assert!(input.len() <= BATCH_SIZE);
    let mut out = Batch {
        w: [_mm_setzero_si128(); 8],
    };
    for (w, block) in out.w.iter_mut().zip(input) {
        *w = compact_block(block);
    }
    transpose(&mut out);
    out
}

/// Writes the first `out.len()` blocks of `batch`.
#[target_feature(enable = "sse2")]
fn from_batch(out: &mut [[u8; 16]], batch: &Batch) {
    debug_assert!(out.len() <= BATCH_SIZE);
    let mut copy = *batch;
    transpose(&mut copy);
    for (block, w) in out.iter_mut().zip(copy.w) {
        uncompact_block(block, w);
    }
}

// AES round steps.

#[target_feature(enable = "sse2")]
fn add_round_key(batch: &mut Batch, key: &Batch) {
    for (w, k) in batch.w.iter_mut().zip(key.w) {
        *w = xor(*w, k);
    }
}

#[target_feature(enable = "sse2")]
fn sub_bytes(batch: &mut Batch) {
    // See https://eprint.iacr.org/2009/191.pdf, Appendix C.
    let x0 = batch.w[7];
    let x1 = batch.w[6];
    let x2 = batch.w[5];
    let x3 = batch.w[4];
    let x4 = batch.w[3];
    let x5 = batch.w[2];
    let x6 = batch.w[1];
    let x7 = batch.w[0];

    // Figure 2, the top linear transformation.
    let y14 = xor(x3, x5);
    let y13 = xor(x0, x6);
    let y9 = xor(x0, x3);
    let y8 = xor(x0, x5);
    let t0 = xor(x1, x2);
    let y1 = xor(t0, x7);
    let y4 = xor(y1, x3);
    let y12 = xor(y13, y14);
    let y2 = xor(y1, x0);
    let y5 = xor(y1, x6);
    let y3 = xor(y5, y8);
    let t1 = xor(x4, y12);
    let y15 = xor(t1, x5);
    let y20 = xor(t1, x1);
    let y6 = xor(y15, x7);
    let y10 = xor(y15, t0);
    let y11 = xor(y20, y9);
    let y7 = xor(x7, y11);
    let y17 = xor(y10, y11);
    let y19 = xor(y10, y8);
    let y16 = xor(t0, y11);
    let y21 = xor(y13, y16);
    let y18 = xor(x0, y16);

    // Figure 3, the middle non-linear section.
    let t2 = and(y12, y15);
    let t3 = and(y3, y6);
    let t4 = xor(t3, t2);
    let t5 = and(y4, x7);
    let t6 = xor(t5, t2);
    let t7 = and(y13, y16);
    let t8 = and(y5, y1);
    let t9 = xor(t8, t7);
    let t10 = and(y2, y7);
    let t11 = xor(t10, t7);
    let t12 = and(y9, y11);
    let t13 = and(y14, y17);
    let t14 = xor(t13, t12);
    let t15 = and(y8, y10);
    let t16 = xor(t15, t12);
    let t17 = xor(t4, t14);
    let t18 = xor(t6, t16);
    let t19 = xor(t9, t14);
    let t20 = xor(t11, t16);
    let t21 = xor(t17, y20);
    let t22 = xor(t18, y19);
    let t23 = xor(t19, y21);
    let t24 = xor(t20, y18);
    let t25 = xor(t21, t22);
    let t26 = and(t21, t23);
    let t27 = xor(t24, t26);
    let t28 = and(t25, t27);
    let t29 = xor(t28, t22);
    let t30 = xor(t23, t24);
    let t31 = xor(t22, t26);
    let t32 = and(t31, t30);
    let t33 = xor(t32, t24);
    let t34 = xor(t23, t33);
    let t35 = xor(t27, t33);
    let t36 = and(t24, t35);
    let t37 = xor(t36, t34);
    let t38 = xor(t27, t36);
    let t39 = and(t29, t38);
    let t40 = xor(t25, t39);
    let t41 = xor(t40, t37);
    let t42 = xor(t29, t33);
    let t43 = xor(t29, t40);
    let t44 = xor(t33, t37);
    let t45 = xor(t42, t41);
    let z0 = and(t44, y15);
    let z1 = and(t37, y6);
    let z2 = and(t33, x7);
    let z3 = and(t43, y16);
    let z4 = and(t40, y1);
    let z5 = and(t29, y7);
    let z6 = and(t42, y11);
    let z7 = and(t45, y17);
    let z8 = and(t41, y10);
    let z9 = and(t44, y12);
    let z10 = and(t37, y3);
    let z11 = and(t33, y4);
    let z12 = and(t43, y13);
    let z13 = and(t40, y5);
    let z14 = and(t29, y2);
    let z15 = and(t42, y9);
    let z16 = and(t45, y14);
    let z17 = and(t41, y8);

    // Figure 4, bottom linear transformation.
    let t46 = xor(z15, z16);
    let t47 = xor(z10, z11);
    let t48 = xor(z5, z13);
    let t49 = xor(z9, z10);
    let t50 = xor(z2, z12);
    let t51 = xor(z2, z5);
    let t52 = xor(z7, z8);
    let t53 = xor(z0, z3);
    let t54 = xor(z6, z7);
    let t55 = xor(z16, z17);
    let t56 = xor(z12, t48);
    let t57 = xor(t50, t53);
    let t58 = xor(z4, t46);
    let t59 = xor(z3, t54);
    let t60 = xor(t46, t57);
    let t61 = xor(z14, t57);
    let t62 = xor(t52, t58);
    let t63 = xor(t49, t58);
    let t64 = xor(z4, t59);
    let t65 = xor(t61, t62);
    let t66 = xor(z1, t63);
    let s0 = xor(t59, t63);
    let s6 = xor(t56, not(t62));
    let s7 = xor(t48, not(t60));
    let t67 = xor(t64, t65);
    let s3 = xor(t53, t66);
    let s4 = xor(t51, t66);
    let s5 = xor(t47, t65);
    let s1 = xor(t64, not(s3));
    let s2 = xor(t55, not(t67));

    batch.w[0] = s7;
    batch.w[1] = s6;
    batch.w[2] = s5;
    batch.w[3] = s4;
    batch.w[4] = s3;
    batch.w[5] = s2;
    batch.w[6] = s1;
    batch.w[7] = s0;
}

/// Rotates the columns in each row of `v` right by `n`. A macro because the
/// byte shifts take constant counts.
macro_rules! rotate_cols_right {
    ($v:expr, $n:literal) => {
        or(
            _mm_srli_si128::<{ $n * 4 }>($v),
            _mm_slli_si128::<{ 16 - $n * 4 }>($v),
        )
    };
}

#[target_feature(enable = "sse2")]
fn shift_rows(batch: &mut Batch) {
    for w in &mut batch.w {
        let row0 = and(*w, _mm_set1_epi32(0x000000ff));
        let row1 = and(*w, _mm_set1_epi32(0x0000ff00));
        let row2 = and(*w, _mm_set1_epi32(0x00ff0000));
        let row3 = and(*w, _mm_set1_epi32(0xff000000u32 as i32));
        let row1 = rotate_cols_right!(row1, 1);
        let row2 = rotate_cols_right!(row2, 2);
        let row3 = rotate_cols_right!(row3, 3);
        *w = or(or(row0, row1), or(row2, row3));
    }
}

/// Rotates the rows in each column of `v` down by one.
#[target_feature(enable = "sse2")]
#[inline]
fn rotate_rows_down(v: __m128i) -> __m128i {
    or(_mm_srli_epi32::<8>(v), _mm_slli_epi32::<24>(v))
}

/// Rotates the rows in each column of `v` by two.
#[target_feature(enable = "sse2")]
#[inline]
fn rotate_rows_twice(v: __m128i) -> __m128i {
    or(_mm_srli_epi32::<16>(v), _mm_slli_epi32::<16>(v))
}

#[target_feature(enable = "sse2")]
fn mix_columns(batch: &mut Batch) {
    // See https://eprint.iacr.org/2009/129.pdf, section 4.4 and appendix A.
    let a0 = batch.w[0];
    let a1 = batch.w[1];
    let a2 = batch.w[2];
    let a3 = batch.w[3];
    let a4 = batch.w[4];
    let a5 = batch.w[5];
    let a6 = batch.w[6];
    let a7 = batch.w[7];

    let r0 = rotate_rows_down(a0);
    let a0_r0 = xor(a0, r0);
    let r1 = rotate_rows_down(a1);
    let a1_r1 = xor(a1, r1);
    let r2 = rotate_rows_down(a2);
    let a2_r2 = xor(a2, r2);
    let r3 = rotate_rows_down(a3);
    let a3_r3 = xor(a3, r3);
    let r4 = rotate_rows_down(a4);
    let a4_r4 = xor(a4, r4);
    let r5 = rotate_rows_down(a5);
    let a5_r5 = xor(a5, r5);
    let r6 = rotate_rows_down(a6);
    let a6_r6 = xor(a6, r6);
    let r7 = rotate_rows_down(a7);
    let a7_r7 = xor(a7, r7);

    batch.w[0] = xor(xor(a7_r7, r0), rotate_rows_twice(a0_r0));
    batch.w[1] = xor(xor(a0_r0, a7_r7), xor(r1, rotate_rows_twice(a1_r1)));
    batch.w[2] = xor(xor(a1_r1, r2), rotate_rows_twice(a2_r2));
    batch.w[3] = xor(xor(a2_r2, a7_r7), xor(r3, rotate_rows_twice(a3_r3)));
    batch.w[4] = xor(xor(a3_r3, a7_r7), xor(r4, rotate_rows_twice(a4_r4)));
    batch.w[5] = xor(xor(a4_r4, r5), rotate_rows_twice(a5_r5));
    batch.w[6] = xor(xor(a5_r5, r6), rotate_rows_twice(a6_r6));
    batch.w[7] = xor(xor(a6_r6, r7), rotate_rows_twice(a7_r7));
}

#[target_feature(enable = "sse2")]
fn encrypt_batch(keys: &[Batch], batch: &mut Batch) {
    let (first, rest) = keys.split_first().unwrap();
    let (last, middle) = rest.split_last().unwrap();
    add_round_key(batch, first);
    for round_key in middle {
        sub_bytes(batch);
        shift_rows(batch);
        mix_columns(batch);
        add_round_key(batch, round_key);
    }
    sub_bytes(batch);
    shift_rows(batch);
    add_round_key(batch, last);
}

// Key schedule.

/// Bitslices `key`'s round keys, aws-lc's `AES_NOHW_SCHEDULE`, into the
/// first `key.rounds + 1` entries of the result.
#[target_feature(enable = "sse2")]
fn expand_round_keys(key: &NohwKey) -> [Batch; 15] {
    let mut keys = [Batch {
        w: [_mm_setzero_si128(); 8],
    }; 15];
    for (out, round_key) in keys.iter_mut().zip(&key.rd_key[..=key.rounds]) {
        // Copy the round key into each block in the batch.
        out.w = [*round_key; BATCH_SIZE];
        transpose(out);
    }
    keys
}

const RCON: [u8; 10] = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36];

/// `rcon` as a compact word: with 128-bit words, its bits all fit in the
/// first logical byte.
#[target_feature(enable = "sse2")]
#[inline]
fn rcon_slice(rcon: u8) -> __m128i {
    _mm_set_epi32(0, 0, 0, rcon.into())
}

/// Applies the S-box to each byte of a compact block.
#[target_feature(enable = "sse2")]
fn sub_block(input: __m128i) -> __m128i {
    let mut batch = Batch {
        w: [_mm_setzero_si128(); 8],
    };
    batch.w[0] = input;
    transpose(&mut batch);
    sub_bytes(&mut batch);
    transpose(&mut batch);
    batch.w[0]
}

#[target_feature(enable = "sse2")]
fn setup_key_128(rd_key: &mut [__m128i; 15], input: &[u8; 16]) {
    let mut block = compact_block(input);
    rd_key[0] = block;

    for i in 1..=10 {
        let sub = sub_block(block);
        // Incorporate `rcon` and the transformed word into the first word.
        block = xor(block, rcon_slice(RCON[i - 1]));
        block = xor(block, _mm_srli_si128::<12>(rotate_rows_down(sub)));
        // Propagate to the remaining words. Note this is reordered from the
        // usual formulation to avoid needing masks.
        let v = block;
        block = xor(block, _mm_slli_si128::<4>(v));
        block = xor(block, _mm_slli_si128::<8>(v));
        block = xor(block, _mm_slli_si128::<12>(v));
        rd_key[i] = block;
    }
}

#[target_feature(enable = "sse2")]
fn setup_key_256(rd_key: &mut [__m128i; 15], input: &[u8; 32]) {
    // Each key schedule iteration produces two round keys.
    let (lo, hi) = input.split_at(16);
    let mut block1 = compact_block(lo.try_into().unwrap());
    rd_key[0] = block1;
    let mut block2 = compact_block(hi.try_into().unwrap());
    rd_key[1] = block2;

    for i in (2..=14).step_by(2) {
        let sub = sub_block(block2);
        // Incorporate `rcon` and the transformed word into the first word.
        block1 = xor(block1, rcon_slice(RCON[i / 2 - 1]));
        block1 = xor(block1, _mm_srli_si128::<12>(rotate_rows_down(sub)));
        // Propagate to the remaining words.
        let v = block1;
        block1 = xor(block1, _mm_slli_si128::<4>(v));
        block1 = xor(block1, _mm_slli_si128::<8>(v));
        block1 = xor(block1, _mm_slli_si128::<12>(v));
        rd_key[i] = block1;

        if i == 14 {
            break;
        }

        let sub = sub_block(block1);
        // Incorporate the transformed word into the first word.
        block2 = xor(block2, _mm_srli_si128::<12>(sub));
        // Propagate to the remaining words.
        let v = block2;
        block2 = xor(block2, _mm_slli_si128::<4>(v));
        block2 = xor(block2, _mm_slli_si128::<8>(v));
        block2 = xor(block2, _mm_slli_si128::<12>(v));
        rd_key[i + 1] = block2;
    }
}

// External API.

#[target_feature(enable = "sse2")]
fn set_encrypt_key(key: &[u8]) -> NohwKey {
    let mut rd_key = [_mm_setzero_si128(); 15];
    let rounds = match key.len() {
        16 => {
            setup_key_128(&mut rd_key, key.try_into().unwrap());
            10
        }
        32 => {
            setup_key_256(&mut rd_key, key.try_into().unwrap());
            14
        }
        _ => unreachable!("callers check the AES key length"),
    };
    NohwKey { rd_key, rounds }
}

#[target_feature(enable = "sse2")]
fn encrypt(key: &NohwKey, inout: &mut [u8; 16]) {
    let sched = expand_round_keys(key);
    let mut batch = to_batch(core::slice::from_ref(inout));
    encrypt_batch(&sched[..=key.rounds], &mut batch);
    from_batch(core::slice::from_mut(inout), &batch);
}

#[target_feature(enable = "sse2")]
fn ctr32_encrypt_blocks(key: &NohwKey, ivec: &[u8; 16], inout: &mut [[u8; 16]]) {
    if inout.is_empty() {
        return;
    }
    let sched = expand_round_keys(key);
    let sched = &sched[..=key.rounds];

    // Make `BATCH_SIZE` copies of `ivec`.
    let mut ivs = [*ivec; BATCH_SIZE];
    let mut enc_ivs = [[0u8; 16]; BATCH_SIZE];

    let mut ctr = u32::from_be_bytes(ivec[12..].try_into().unwrap());
    for blocks in inout.chunks_mut(BATCH_SIZE) {
        // Update counters.
        for (i, iv) in (0..).zip(&mut ivs) {
            iv[12..].copy_from_slice(&ctr.wrapping_add(i).to_be_bytes());
        }

        let todo = blocks.len();
        let mut batch = to_batch(&ivs[..todo]);
        encrypt_batch(sched, &mut batch);
        from_batch(&mut enc_ivs[..todo], &batch);

        for (block, enc_iv) in blocks.iter_mut().zip(&enc_ivs) {
            for (b, e) in block.iter_mut().zip(enc_iv) {
                *b ^= e;
            }
        }

        ctr = ctr.wrapping_add(BATCH_SIZE as u32);
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::low::x86_64::cpu::HaveSsse3;
    use crate::low::x86_64::vpaes_x86_64::VpaesKey;

    // vpaes is the arm above this one, so the two must agree for both key
    // sizes: on single blocks, and on CTR runs around the batch size and
    // across the counter's 32-bit wrap, which lands mid-batch and then wraps
    // the batch counter too.
    #[test]
    fn matches_vpaes() {
        let Some(token) = HaveSsse3::check() else {
            return;
        };
        let bytes = |n: usize, seed: u32| -> Vec<u8> {
            (0..n as u32)
                .map(|i| (i.wrapping_add(seed).wrapping_mul(0x9e3779b9) >> 24) as u8)
                .collect()
        };
        for (key_len, seed) in [16, 32].into_iter().zip(1..) {
            let key = bytes(key_len, seed);
            let nohw = NohwKey::new(&key);
            let vpaes = VpaesKey::new(&key, token);

            let mut want: [u8; 16] = bytes(16, seed).try_into().unwrap();
            let mut got = want;
            vpaes.encrypt_block(&mut want);
            nohw.encrypt_block(&mut got);
            assert_eq!(got, want, "{key_len}-byte key, one block");

            for counter in [0, u32::MAX - 3] {
                let mut ivec: [u8; 16] = bytes(16, counter).try_into().unwrap();
                ivec[12..].copy_from_slice(&counter.to_be_bytes());
                for blocks in [0, 1, 7, 8, 9, 17] {
                    let input: Vec<[u8; 16]> = bytes(16 * blocks, seed).as_chunks().0.to_vec();
                    let mut want = input.clone();
                    vpaes.ctr32(&ivec, &mut want);
                    let mut got = input;
                    nohw.ctr32(&ivec, &mut got);
                    assert_eq!(
                        got, want,
                        "{key_len}-byte key, counter {counter}, {blocks} blocks"
                    );
                }
            }
        }
    }

    // FIPS-197 Appendix C.1 and C.3, which hold the circuit to AES itself
    // rather than to another implementation.
    #[test]
    fn fips197() {
        let plaintext = 0x00112233_44556677_8899aabb_ccddeeffu128.to_be_bytes();
        for (key, ciphertext) in [
            (
                &(0..16).collect::<Vec<u8>>(),
                0x69c4e0d8_6a7b0430_d8cdb780_70b4c55au128,
            ),
            (
                &(0..32).collect::<Vec<u8>>(),
                0x8ea2b7ca_516745bf_eafc4990_4b496089u128,
            ),
        ] {
            let mut block = plaintext;
            NohwKey::new(key).encrypt_block(&mut block);
            assert_eq!(block, ciphertext.to_be_bytes(), "{}-byte key", key.len());
        }
    }
}
