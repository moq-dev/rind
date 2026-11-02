// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

//! Montgomery multiplication modulo an RSA modulus or prime: s2n-bignum's
//! Karatsuba routines and 8n reduction for 16 and 32 words, and otherwise,
//! from two words, aws-lc's `bn_mul_mont`, which picks its own squaring or 4x
//! routine by the width as aws-lc does. On a Neoverse-N2 it measured twice
//! as fast as s2n-bignum's generic `bignum_montmul` and `bignum_montsqr` at
//! 24, 48, and 64 words; those run only below two words.

/// `z = x * y / 2^(64k) mod m`, for `x` and `y` below `m`, where `k` is the
/// length of each and `n0` is `-m^-1 mod 2^64`.
pub(crate) fn mont_mul(z: &mut [u64], x: &[u64], y: &[u64], m: &[u64], n0: u64) {
    debug_assert!(z.len() == m.len() && x.len() == m.len() && y.len() == m.len());
    match m.len() {
        16 | 32 => karatsuba_mul(z, x, y, m, n0),
        k if k >= 2 => mul_mont(z, x, y, m, n0),
        _ => super::bignum_montmul::bignum_montmul(z, x, y, m),
    }
}

/// `z = x^2 / 2^(64k) mod m`, for `x` below `m`, where `k` is the length of
/// each and `n0` is `-m^-1 mod 2^64`.
pub(crate) fn mont_sqr(z: &mut [u64], x: &[u64], m: &[u64], n0: u64) {
    debug_assert!(z.len() == m.len() && x.len() == m.len());
    match m.len() {
        16 | 32 => karatsuba_sqr(z, x, m, n0),
        k if k >= 2 => mul_mont(z, x, x, m, n0),
        _ => super::bignum_montsqr::bignum_montsqr(z, x, m),
    }
}

/// `mont_mul` for 16 or 32 words.
fn karatsuba_mul(z: &mut [u64], x: &[u64], y: &[u64], m: &[u64], n0: u64) {
    if m.len() == 16 {
        let mut product = [0; 32];
        super::bignum_kmul_16_32::bignum_kmul_16_32(&mut product, x, y, &mut [0; 32]);
        redc_8n(z, &mut product, m, n0);
    } else {
        let mut product = [0; 64];
        super::bignum_kmul_32_64::bignum_kmul_32_64(&mut product, x, y, &mut [0; 96]);
        redc_8n(z, &mut product, m, n0);
    }
}

/// `mont_sqr` for 16 or 32 words.
fn karatsuba_sqr(z: &mut [u64], x: &[u64], m: &[u64], n0: u64) {
    if m.len() == 16 {
        let mut product = [0; 32];
        super::bignum_ksqr_16_32::bignum_ksqr_16_32(&mut product, x, &mut [0; 24]);
        redc_8n(z, &mut product, m, n0);
    } else {
        let mut product = [0; 64];
        super::bignum_ksqr_32_64::bignum_ksqr_32_64(&mut product, x, &mut [0; 72]);
        redc_8n(z, &mut product, m, n0);
    }
}

/// Reduces the `2k`-word `product` into the `k`-word `z`, fully, modulo `m`.
fn redc_8n(z: &mut [u64], product: &mut [u64], m: &[u64], n0: u64) {
    let carry = super::bignum_emontredc_8n::bignum_emontredc_8n(product, m, n0);
    let (_, reduced) = product.split_at(m.len());
    let carry = carry | super::bignum_cmp_lt::bignum_cmp_lt(m, reduced);
    super::bignum_optsub::bignum_optsub(z, reduced, m, carry);
}

/// `mont_mul` for any width from two words. It squares by its own routine
/// when `x` and `y` are the same slice and the width is a multiple of eight.
fn mul_mont(z: &mut [u64], x: &[u64], y: &[u64], m: &[u64], n0: u64) {
    let k = m.len();
    assert!(k >= 2 && z.len() == k && x.len() == k && y.len() == k);
    // SAFETY: `z`, `x`, `y`, and `m` are each `k` words, as `bn_mul_mont`
    // reads and writes for such a `k`, and it reads `n0` as one word.
    unsafe { bn_mul_mont(z.as_mut_ptr(), x.as_ptr(), y.as_ptr(), m.as_ptr(), &n0, k) };
}

/// Returns 1, which tells aws-lc's C it ran.
#[unsafe(naked)]
unsafe extern "C" fn bn_mul_mont(
    rp: *mut u64,
    ap: *const u64,
    bp: *const u64,
    np: *const u64,
    n0: *const u64,
    num: usize,
) -> i32 {
    #[cfg(not(target_vendor = "apple"))]
    core::arch::naked_asm!(include_str!("aws_lc/bn_mul_mont.linux.s"));
    #[cfg(target_vendor = "apple")]
    core::arch::naked_asm!(include_str!("aws_lc/bn_mul_mont.apple.s"));
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::super::{bignum_montmul, bignum_negmodinv};
    use super::*;

    /// xorshift64, so the moduli need no dependency.
    struct Rng(u64);

    impl Rng {
        fn words(&mut self, k: usize) -> [u64; 128] {
            let mut out = [0; 128];
            for word in &mut out[..k] {
                self.0 ^= self.0 << 13;
                self.0 ^= self.0 >> 7;
                self.0 ^= self.0 << 17;
                *word = self.0;
            }
            out
        }
    }

    // Every other test runs only the routine each width picks, so here
    // aws-lc's are checked against s2n-bignum's generic `bignum_montmul` at
    // widths that take each of its three paths, multiplying and squaring, and
    // so are the Karatsuba routines.
    #[test]
    fn matches_generic() {
        let mut rng = Rng(0x2545_f491_4f6c_dd1d);
        for k in [
            2, 3, 5, 8, 9, 12, 16, 17, 18, 24, 32, 33, 36, 48, 64, 96, 128,
        ] {
            for case in 0..16 {
                let mut m = rng.words(k);
                let m = &mut m[..k];
                // The widest modulus, the narrowest with its top word set,
                // and random ones.
                match case {
                    0 => m.fill(u64::MAX),
                    1 => {
                        m.fill(0);
                        m[k - 1] = 1;
                    }
                    _ => m[k - 1] |= 1 << 63,
                }
                m[0] |= 1;
                let mut n0 = [0];
                bignum_negmodinv::bignum_negmodinv(&mut n0, &m[..1]);
                let n0 = n0[0];

                // Operands below `m`, with its extremes: zero, and `m - 1`
                // for both.
                let below = |rng: &mut Rng| {
                    let mut x = rng.words(k);
                    x[k - 1] %= m[k - 1];
                    x
                };
                let (mut x, mut y) = (below(&mut rng), below(&mut rng));
                match case {
                    2 => x[..k].fill(0),
                    3 => {
                        x[..k].copy_from_slice(m);
                        x[0] -= 1;
                        y = x;
                    }
                    _ => {}
                }
                let (x, y) = (&x[..k], &y[..k]);

                let mut want = [0; 128];
                let want = &mut want[..k];
                let mut got = [0; 128];
                let got = &mut got[..k];

                bignum_montmul::bignum_montmul(want, x, y, m);
                mul_mont(got, x, y, m, n0);
                assert_eq!(want, got, "mul_mont, {k} words, case {case}");
                if k == 16 || k == 32 {
                    karatsuba_mul(got, x, y, m, n0);
                    assert_eq!(want, got, "karatsuba_mul, {k} words, case {case}");
                }

                bignum_montmul::bignum_montmul(want, x, x, m);
                mul_mont(got, x, x, m, n0);
                assert_eq!(want, got, "mul_mont squaring, {k} words, case {case}");
                if k == 16 || k == 32 {
                    karatsuba_sqr(got, x, m, n0);
                    assert_eq!(want, got, "karatsuba_sqr, {k} words, case {case}");
                }
            }
        }
    }
}
