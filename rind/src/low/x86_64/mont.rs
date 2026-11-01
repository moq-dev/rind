// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

//! Montgomery multiplication modulo an RSA modulus or prime.
//!
//! With BMI2 and ADX, 1024- and 2048-bit moduli run s2n-bignum's Karatsuba
//! routines and its 8n reduction. Otherwise, moduli of a multiple of four
//! words from eight run aws-lc's `bn_mul4x_mont`, and of a multiple of eight
//! its `bn_sqr8x_mont` for squaring, as aws-lc's `bn_mul_mont` picks them
//! without BMI2 and ADX; `admin/import-aws-lc` drops `bn_sqr8x_mont`'s branch
//! for those. They measured 1.5 to 1.9 times as fast as s2n-bignum's generic
//! `bignum_montmul` and `bignum_montsqr`, which run the other sizes.

use super::cpu::HaveBmi2Adx;

/// `z = x * y / 2^(64k) mod m`, for `x` and `y` below `m`, where `k` is the
/// length of each and `n0` is `-m^-1 mod 2^64`.
pub(crate) fn mont_mul(z: &mut [u64], x: &[u64], y: &[u64], m: &[u64], n0: u64) {
    debug_assert!(z.len() == m.len() && x.len() == m.len() && y.len() == m.len());
    match (HaveBmi2Adx::check(), m.len()) {
        (Some(_), 16 | 32) => karatsuba_mul(z, x, y, m, n0),
        (_, k) if k >= 8 && k.is_multiple_of(4) => mul4x(z, x, y, m, n0),
        _ => super::bignum_montmul::bignum_montmul(z, x, y, m),
    }
}

/// `z = x^2 / 2^(64k) mod m`, for `x` below `m`, where `k` is the length of
/// each and `n0` is `-m^-1 mod 2^64`.
pub(crate) fn mont_sqr(z: &mut [u64], x: &[u64], m: &[u64], n0: u64) {
    debug_assert!(z.len() == m.len() && x.len() == m.len());
    match (HaveBmi2Adx::check(), m.len()) {
        (Some(_), 16 | 32) => karatsuba_sqr(z, x, m, n0),
        (_, k) if k >= 8 && k.is_multiple_of(8) => sqr8x(z, x, m, n0),
        (_, k) if k >= 8 && k.is_multiple_of(4) => mul4x(z, x, x, m, n0),
        _ => super::bignum_montsqr::bignum_montsqr(z, x, m),
    }
}

/// `mont_mul` for 16 or 32 words, with BMI2 and ADX.
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

/// `mont_sqr` for 16 or 32 words, with BMI2 and ADX.
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

/// `mont_mul` for a multiple of four words from eight.
fn mul4x(z: &mut [u64], x: &[u64], y: &[u64], m: &[u64], n0: u64) {
    let k = m.len();
    assert!(k >= 8 && k.is_multiple_of(4) && z.len() == k && x.len() == k && y.len() == k);
    // SAFETY: `z`, `x`, `y`, and `m` are each `k` words, as `bn_mul4x_mont`
    // reads and writes for such a `k`, and it reads `n0` as one word.
    unsafe { bn_mul4x_mont(z.as_mut_ptr(), x.as_ptr(), y.as_ptr(), m.as_ptr(), &n0, k) };
}

/// `mont_sqr` for a multiple of eight words.
fn sqr8x(z: &mut [u64], x: &[u64], m: &[u64], n0: u64) {
    let k = m.len();
    assert!(k >= 8 && k.is_multiple_of(8) && z.len() == k && x.len() == k);
    // SAFETY: `z`, `x`, and `m` are each `k` words, as `bn_sqr8x_mont` reads
    // and writes for such a `k`, and it reads `n0` as one word.
    unsafe { bn_sqr8x_mont(z.as_mut_ptr(), x.as_ptr(), 0, m.as_ptr(), &n0, k) };
}

// The routines take the System V ABI on every OS, since their text is
// aws-lc's ELF and Mach-O flavors, which read their arguments from its
// registers. Both return 1, which tells aws-lc's C they ran.

#[unsafe(naked)]
unsafe extern "sysv64" fn bn_mul4x_mont(
    rp: *mut u64,
    ap: *const u64,
    bp: *const u64,
    np: *const u64,
    n0: *const u64,
    num: usize,
) -> i32 {
    #[cfg(not(target_vendor = "apple"))]
    core::arch::naked_asm!(
        include_str!("aws_lc/bn_mul4x_mont.linux.s"),
        options(att_syntax)
    );
    #[cfg(target_vendor = "apple")]
    core::arch::naked_asm!(
        include_str!("aws_lc/bn_mul4x_mont.apple.s"),
        options(att_syntax)
    );
}

/// `mulx_adx_capable` selects nothing: the import drops that branch.
#[unsafe(naked)]
unsafe extern "sysv64" fn bn_sqr8x_mont(
    rp: *mut u64,
    ap: *const u64,
    mulx_adx_capable: u64,
    np: *const u64,
    n0: *const u64,
    num: usize,
) -> i32 {
    #[cfg(not(target_vendor = "apple"))]
    core::arch::naked_asm!(
        include_str!("aws_lc/bn_sqr8x_mont.linux.s"),
        bn_sqr8x_internal = sym bn_sqr8x_internal,
        options(att_syntax)
    );
    #[cfg(target_vendor = "apple")]
    core::arch::naked_asm!(
        include_str!("aws_lc/bn_sqr8x_mont.apple.s"),
        bn_sqr8x_internal = sym bn_sqr8x_internal,
        options(att_syntax)
    );
}

/// `bn_sqr8x_mont`'s squaring and reduction, which takes its arguments in
/// registers and a stack frame of that routine's making, so only it calls
/// this.
#[unsafe(naked)]
unsafe extern "sysv64" fn bn_sqr8x_internal() {
    #[cfg(not(target_vendor = "apple"))]
    core::arch::naked_asm!(
        include_str!("aws_lc/bn_sqr8x_internal.linux.s"),
        options(att_syntax)
    );
    #[cfg(target_vendor = "apple")]
    core::arch::naked_asm!(
        include_str!("aws_lc/bn_sqr8x_internal.apple.s"),
        options(att_syntax)
    );
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::super::adx_mux::tests::Rng;
    use super::super::{bignum_montmul, bignum_montsqr, bignum_negmodinv};
    use super::*;

    // Every other test runs only the routines this CPU picks, so here aws-lc's
    // are checked against s2n-bignum's generic ones at each size they take,
    // and so are the Karatsuba routines where the CPU has BMI2 and ADX.
    #[test]
    fn matches_generic() {
        let adx = HaveBmi2Adx::check().is_some();
        let mut rng = Rng(0x2545_f491_4f6c_dd1d);
        for k in [8, 12, 16, 24, 32, 48, 64] {
            for case in 0..16 {
                let mut m = rng.words::<64>(64 * k as u32);
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
                    let mut x = rng.words::<64>(64 * k as u32);
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

                let mut want = [0; 64];
                let want = &mut want[..k];
                let mut got = [0; 64];
                let got = &mut got[..k];

                bignum_montmul::bignum_montmul(want, x, y, m);
                mul4x(got, x, y, m, n0);
                assert_eq!(want, got, "mul4x, {k} words, case {case}");
                if adx && (k == 16 || k == 32) {
                    karatsuba_mul(got, x, y, m, n0);
                    assert_eq!(want, got, "karatsuba_mul, {k} words, case {case}");
                }

                bignum_montsqr::bignum_montsqr(want, x, m);
                mul4x(got, x, x, m, n0);
                assert_eq!(want, got, "mul4x squaring, {k} words, case {case}");
                if k.is_multiple_of(8) {
                    sqr8x(got, x, m, n0);
                    assert_eq!(want, got, "sqr8x, {k} words, case {case}");
                }
                if adx && (k == 16 || k == 32) {
                    karatsuba_sqr(got, x, m, n0);
                    assert_eq!(want, got, "karatsuba_sqr, {k} words, case {case}");
                }
            }
        }
    }
}
