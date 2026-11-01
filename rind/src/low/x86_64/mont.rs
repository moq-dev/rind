// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

//! Montgomery multiplication modulo an RSA modulus or prime, by the fastest
//! routine for its width in words, as measured against each other:
//!
//! - With BMI2 and ADX, s2n-bignum's Karatsuba routines and its 8n
//!   reduction for 16 and 32 words.
//! - Otherwise, from eight words, aws-lc's `bn_mul4x_mont` for a multiple of
//!   four, by `mulx`, `adcx`, and `adox` with BMI2 and ADX, and without them
//!   its `bn_sqr8x_mont` for squaring a multiple of eight.
//! - Otherwise, aws-lc's `bn_mul_mont_nohw`.
//!
//! These are what aws-lc's `bn_mul_mont` picks, but for the Karatsuba
//! routines, which measured faster than `bn_mulx4x_mont`, and squaring with
//! BMI2 and ADX: `admin/import-aws-lc` drops `bn_sqr8x_mont`'s branch for
//! those, whose scratch memcheck cannot follow. The aws-lc routines measured
//! 1.1 to 2.5 times as fast as s2n-bignum's generic `bignum_montmul` and
//! `bignum_montsqr`, and `bignum_montmul` runs only below two words, which
//! `bn_mul_mont_nohw` does not take.

use super::cpu::HaveBmi2Adx;

/// `z = x * y / 2^(64k) mod m`, for `x` and `y` below `m`, where `k` is the
/// length of each and `n0` is `-m^-1 mod 2^64`.
pub(crate) fn mont_mul(z: &mut [u64], x: &[u64], y: &[u64], m: &[u64], n0: u64) {
    debug_assert!(z.len() == m.len() && x.len() == m.len() && y.len() == m.len());
    match (HaveBmi2Adx::check(), m.len()) {
        (Some(_), 16 | 32) => karatsuba_mul(z, x, y, m, n0),
        (adx, k) if k >= 8 && k.is_multiple_of(4) => mul4x(z, x, y, m, n0, adx),
        (_, k) if k >= 2 => nohw(z, x, y, m, n0),
        _ => super::bignum_montmul::bignum_montmul(z, x, y, m),
    }
}

/// `z = x^2 / 2^(64k) mod m`, for `x` below `m`, where `k` is the length of
/// each and `n0` is `-m^-1 mod 2^64`.
pub(crate) fn mont_sqr(z: &mut [u64], x: &[u64], m: &[u64], n0: u64) {
    debug_assert!(z.len() == m.len() && x.len() == m.len());
    match (HaveBmi2Adx::check(), m.len()) {
        (Some(_), 16 | 32) => karatsuba_sqr(z, x, m, n0),
        (None, k) if k >= 8 && k.is_multiple_of(8) => sqr8x(z, x, m, n0),
        (adx, k) if k >= 8 && k.is_multiple_of(4) => mul4x(z, x, x, m, n0, adx),
        (_, k) if k >= 2 => nohw(z, x, x, m, n0),
        _ => super::bignum_montmul::bignum_montmul(z, x, x, m),
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

/// `mont_mul` for a multiple of four words from eight, by `mulx`, `adcx`,
/// and `adox` given the proof of BMI2 and ADX.
fn mul4x(z: &mut [u64], x: &[u64], y: &[u64], m: &[u64], n0: u64, adx: Option<HaveBmi2Adx>) {
    let k = m.len();
    assert!(k >= 8 && k.is_multiple_of(4) && z.len() == k && x.len() == k && y.len() == k);
    let (z, x, y, m) = (z.as_mut_ptr(), x.as_ptr(), y.as_ptr(), m.as_ptr());
    // SAFETY: `z`, `x`, `y`, and `m` are each `k` words, as each routine
    // reads and writes for such a `k`, and each reads `n0` as one word. The
    // token proves the CPU has the BMI2 and ADX `bn_mulx4x_mont` runs.
    unsafe {
        match adx {
            Some(_) => bn_mulx4x_mont(z, x, y, m, &n0, k),
            None => bn_mul4x_mont(z, x, y, m, &n0, k),
        }
    };
}

/// `mont_sqr` for a multiple of eight words.
fn sqr8x(z: &mut [u64], x: &[u64], m: &[u64], n0: u64) {
    let k = m.len();
    assert!(k >= 8 && k.is_multiple_of(8) && z.len() == k && x.len() == k);
    // SAFETY: `z`, `x`, and `m` are each `k` words, as `bn_sqr8x_mont` reads
    // and writes for such a `k`, and it reads `n0` as one word.
    unsafe { bn_sqr8x_mont(z.as_mut_ptr(), x.as_ptr(), 0, m.as_ptr(), &n0, k) };
}

/// `mont_mul` for any width from two words.
fn nohw(z: &mut [u64], x: &[u64], y: &[u64], m: &[u64], n0: u64) {
    let k = m.len();
    assert!(k >= 2 && z.len() == k && x.len() == k && y.len() == k);
    // SAFETY: `z`, `x`, `y`, and `m` are each `k` words, as
    // `bn_mul_mont_nohw` reads and writes for such a `k`, and it reads `n0`
    // as one word.
    unsafe { bn_mul_mont_nohw(z.as_mut_ptr(), x.as_ptr(), y.as_ptr(), m.as_ptr(), &n0, k) };
}

// The routines take the System V ABI on every OS, since their text is
// aws-lc's ELF and Mach-O flavors, which read their arguments from its
// registers. Each returns 1, which tells aws-lc's C it ran.

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

#[unsafe(naked)]
unsafe extern "sysv64" fn bn_mulx4x_mont(
    rp: *mut u64,
    ap: *const u64,
    bp: *const u64,
    np: *const u64,
    n0: *const u64,
    num: usize,
) -> i32 {
    #[cfg(not(target_vendor = "apple"))]
    core::arch::naked_asm!(
        include_str!("aws_lc/bn_mulx4x_mont.linux.s"),
        options(att_syntax)
    );
    #[cfg(target_vendor = "apple")]
    core::arch::naked_asm!(
        include_str!("aws_lc/bn_mulx4x_mont.apple.s"),
        options(att_syntax)
    );
}

#[unsafe(naked)]
unsafe extern "sysv64" fn bn_mul_mont_nohw(
    rp: *mut u64,
    ap: *const u64,
    bp: *const u64,
    np: *const u64,
    n0: *const u64,
    num: usize,
) -> i32 {
    #[cfg(not(target_vendor = "apple"))]
    core::arch::naked_asm!(
        include_str!("aws_lc/bn_mul_mont_nohw.linux.s"),
        options(att_syntax)
    );
    #[cfg(target_vendor = "apple")]
    core::arch::naked_asm!(
        include_str!("aws_lc/bn_mul_mont_nohw.apple.s"),
        options(att_syntax)
    );
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::super::adx_mux::tests::Rng;
    use super::super::{bignum_montmul, bignum_negmodinv};
    use super::*;

    // Every other test runs only the routines this CPU picks, so here aws-lc's
    // are checked against s2n-bignum's generic `bignum_montmul` at each width
    // they take, with and without `mulx` where the CPU has BMI2 and ADX, and
    // so are the Karatsuba routines there.
    #[test]
    fn matches_generic() {
        let adx = HaveBmi2Adx::check();
        let mut rng = Rng(0x2545_f491_4f6c_dd1d);
        for k in [2, 3, 5, 8, 9, 12, 16, 17, 18, 24, 32, 33, 36, 48, 64] {
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
                let mut want_sqr = [0; 64];
                let want_sqr = &mut want_sqr[..k];
                bignum_montmul::bignum_montmul(want, x, y, m);
                bignum_montmul::bignum_montmul(want_sqr, x, x, m);

                let mut got = [0; 64];
                let got = &mut got[..k];
                let mut check = |name: &str, f: &dyn Fn(&mut [u64])| {
                    f(got);
                    assert_eq!(want, got, "{name}, {k} words, case {case}");
                };
                check("nohw", &|z| nohw(z, x, y, m, n0));
                if k >= 8 && k.is_multiple_of(4) {
                    check("mul4x", &|z| mul4x(z, x, y, m, n0, None));
                    if adx.is_some() {
                        check("mulx4x", &|z| mul4x(z, x, y, m, n0, adx));
                    }
                }
                if let (Some(_), 16 | 32) = (adx, k) {
                    check("karatsuba_mul", &|z| karatsuba_mul(z, x, y, m, n0));
                }

                let mut check = |name: &str, f: &dyn Fn(&mut [u64])| {
                    f(got);
                    assert_eq!(want_sqr, got, "{name}, {k} words, case {case}");
                };
                check("nohw squaring", &|z| nohw(z, x, x, m, n0));
                if k >= 8 && k.is_multiple_of(4) {
                    check("mul4x squaring", &|z| mul4x(z, x, x, m, n0, None));
                    if adx.is_some() {
                        check("mulx4x squaring", &|z| mul4x(z, x, x, m, n0, adx));
                    }
                }
                if k >= 8 && k.is_multiple_of(8) {
                    check("sqr8x", &|z| sqr8x(z, x, m, n0));
                }
                if let (Some(_), 16 | 32) = (adx, k) {
                    check("karatsuba_sqr", &|z| karatsuba_sqr(z, x, m, n0));
                }
            }
        }
    }
}
