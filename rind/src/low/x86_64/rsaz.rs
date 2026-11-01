// Copyright 2013-2016 The OpenSSL Project Authors. All Rights Reserved.
// Copyright (c) 2012, Intel Corporation. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Exponentiation modulo a 1024-bit prime by aws-lc's RSAZ: Montgomery
//! products on AVX2 over 36 limbs of 29 bits, and a 5-bit fixed window whose
//! table entry is gathered by masking every entry.
//!
//! This ports aws-lc's `RSAZ_1024_mod_exp_avx2`, from `rsaz_exp.c` at the
//! commit `admin/import-aws-lc` names, over its `rsaz-avx2` assembly, which
//! Shay Gueron and Vlad Krasnov wrote for OpenSSL. aws-lc runs it for
//! RSA-2048's CRT on CPUs with AVX2 but without BMI2 and ADX, where it signed
//! 1.6 times as fast as rind's 4-bit window over `bn_mul4x_mont` and
//! `bn_sqr8x_mont`. With them, s2n-bignum's Karatsuba routines are faster,
//! as aws-lc's `mulx` ones are there.
//!
//! It is not formally verified: its correctness rests on its use in OpenSSL
//! and aws-lc, and on rind's tests of it against the 4-bit window,
//! Wycheproof, and aws-lc-rs. Each product is below `2m` given inputs below
//! `2m`, since `4m` is below RSAZ's `R`, so it holds for any odd modulus
//! below 2^1024, where aws-lc also asks for the top bit set.

use super::cpu::{HaveAvx2, HaveBmi2Adx};
use crate::low;

/// Proof that RSAZ is this CPU's fastest exponentiation for 1024-bit moduli:
/// it has AVX2, and lacks the BMI2 and ADX that the faster routines need, as
/// aws-lc's `rsaz_avx2_preferred` decides.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Rsaz(HaveAvx2);

impl Rsaz {
    pub(crate) fn check() -> Option<Self> {
        match HaveBmi2Adx::check() {
            Some(_) => None,
            None => HaveAvx2::check().map(Self),
        }
    }

    /// `z = x^e mod m`, for an odd `m` and `x` below it, where `rr` is
    /// `2^2048 mod m` and `n0` is `-m^-1 mod 2^64`.
    ///
    /// The instruction trace and memory addresses depend on none of their
    /// values.
    pub(crate) fn mod_exp(
        self,
        z: &mut [u64; 16],
        x: &[u64; 16],
        e: &[u64; 16],
        m: &[u64; 16],
        rr: &[u64; 16],
        n0: u64,
    ) {
        mod_exp(self.0, z, x, e, m, rr, n0);
    }
}

/// A value in RSAZ's redundant form: 36 limbs of 29 bits, each in a word,
/// padded to 40. Products are almost Montgomery: below `2m`, not `m`.
type Red = [u64; 40];

/// `table[i]` for `i` below 32 is the base to the `i`, in RSAZ's Montgomery
/// form: two limbs to a word, in 9 rows of 32 entries, so a gather reads the
/// same rows whichever entry it takes.
#[repr(C, align(64))]
struct Table([u64; 32 * 18]);

/// Everything secret that the exponentiation writes, so it is wiped as one,
/// as aws-lc wipes its `storage`.
#[repr(C, align(64))]
struct Storage {
    red: [Red; 3],
    rr: Red,
    table: Table,
}

impl low::Zeroable for Storage {}

/// 1 and 2^80 in RSAZ's form: limb 2 is `2^58`, times `2^22`.
static ONE: Red = limb(0, 1);
static TWO80: Red = limb(2, 1 << 22);

const fn limb(i: usize, v: u64) -> Red {
    let mut r = [0; 40];
    r[i] = v;
    r
}

fn mod_exp(
    token: HaveAvx2,
    z: &mut [u64; 16],
    x: &[u64; 16],
    e: &[u64; 16],
    m: &[u64; 16],
    rr: &[u64; 16],
    n0: u64,
) {
    let mut storage = Storage {
        red: [[0; 40]; 3],
        rr: [0; 40],
        table: Table([0; 32 * 18]),
    };
    let crosses_page = (&raw const storage as usize & 4095) + 320 > 4095;
    let Storage {
        red: [r0, r1, r2],
        rr: r2_red,
        table,
    } = &mut storage;
    // As aws-lc does, keep the modulus from crossing a page, which slows the
    // routines' loads: it goes first unless that crosses one, and otherwise
    // third, which then cannot.
    let (m_red, result, base) = match crosses_page {
        true => (r2, r0, r1),
        false => (r0, r1, r2),
    };
    norm2red(token, m_red, m);
    norm2red(token, base, x);
    norm2red(token, r2_red, rr);
    let rsaz = Routines {
        _token: token,
        m: m_red,
        n0,
    };

    // `rr` is R^2 for R = 2^1024; RSAZ's R is 2^(36 * 29) = 2^1044. This
    // takes it to 2^4096 / 2^1044 = 2^3052, then 2^3052 * 2^80 / 2^1044 =
    // 2^2088, RSAZ's R^2.
    rsaz.mul_self(r2_red);
    rsaz.mul_by(r2_red, &TWO80);

    // table[0] = 1, and table[1] = the base, each in Montgomery form.
    rsaz.mul(result, r2_red, &ONE);
    rsaz.mul_by(base, r2_red);
    scatter(token, table, result, 0);
    scatter(token, table, base, 1);
    // table[2^i] = table[2^(i-1)]^2.
    rsaz.sqr(result, base, 1);
    scatter(token, table, result, 2);
    for i in [4, 8, 16] {
        rsaz.sqr_by(result, 1);
        scatter(token, table, result, i);
    }
    // Each odd entry is the even one before times the base, and then each
    // entry at twice it is its square.
    for i in (3..32).step_by(2) {
        gather(token, result, table, i - 1);
        rsaz.mul_by(result, base);
        scatter(token, table, result, i);
        let mut j = 2 * i;
        while j < 32 {
            rsaz.sqr_by(result, 1);
            scatter(token, table, result, j);
            j *= 2;
        }
    }

    // The exponent's bits from `bit`, through `bit + 4`, at public `bit`.
    let window = |bit: usize| {
        let (w, s) = (bit / 64, bit % 64);
        let pair = u128::from(e[w]) | e.get(w + 1).map_or(0, |&above| u128::from(above) << 64);
        (pair >> s) as u32 & 31
    };

    // The top 5 bits, then each 5 below, then the last 4: 1024 bits.
    gather(token, result, table, window(1019));
    for bit in (4..=1014).rev().step_by(5) {
        rsaz.sqr_by(result, 5);
        gather(token, base, table, window(bit));
        rsaz.mul_by(result, base);
    }
    rsaz.sqr_by(result, 4);
    gather(token, base, table, window(0) & 15);
    rsaz.mul_by(result, base);

    // Out of Montgomery form, which leaves it at most `m`.
    rsaz.mul_by(result, &ONE);
    let mut norm = [0; 16];
    red2norm(token, &mut norm, result);
    let ge = 1 - low::bignum_cmp_lt(&norm, m);
    low::bignum_optsub(z, &norm, m, ge);

    low::zeroise_value(&mut storage);
}

/// The Montgomery products, modulo `m` in RSAZ's form, with `n0` as
/// `-m^-1 mod 2^64`.
struct Routines<'a> {
    _token: HaveAvx2,
    m: &'a Red,
    n0: u64,
}

impl Routines<'_> {
    /// `r = a * b / R`.
    fn mul(&self, r: &mut Red, a: &Red, b: &Red) {
        self.mul_raw(r, a, b);
    }

    /// `r = r * b / R`.
    fn mul_by(&self, r: &mut Red, b: &Red) {
        let r: *mut Red = r;
        self.mul_raw(r, r, b);
    }

    /// `r = r * r / R`.
    fn mul_self(&self, r: &mut Red) {
        let r: *mut Red = r;
        self.mul_raw(r, r, r);
    }

    /// `r = a * b / R`, where `a` and `b` may be `r`, as aws-lc calls it.
    fn mul_raw(&self, r: *mut Red, a: *const Red, b: *const Red) {
        // SAFETY: each pointer is to 40 words, which the routine reads and
        // writes, and it takes `a` and `b` as `r` too, as aws-lc calls it;
        // the token proves the AVX2 it uses.
        unsafe { rsaz_1024_mul_avx2(r.cast(), a.cast(), b.cast(), self.m.as_ptr(), self.n0) };
    }

    /// `r = a` squared `count` times, each over `R`.
    fn sqr(&self, r: &mut Red, a: &Red, count: i32) {
        self.sqr_raw(r, a, count);
    }

    /// `r = r` squared `count` times, each over `R`.
    fn sqr_by(&self, r: &mut Red, count: i32) {
        let r: *mut Red = r;
        self.sqr_raw(r, r, count);
    }

    fn sqr_raw(&self, r: *mut Red, a: *const Red, count: i32) {
        // SAFETY: as `mul_raw`, and `count` is positive.
        unsafe { rsaz_1024_sqr_avx2(r.cast(), a.cast(), self.m.as_ptr(), self.n0, count) };
    }
}

fn norm2red(_: HaveAvx2, red: &mut Red, norm: &[u64; 16]) {
    // SAFETY: reads 16 words and writes 40, and the token proves AVX2.
    unsafe { rsaz_1024_norm2red_avx2(red.as_mut_ptr(), norm.as_ptr()) };
}

fn red2norm(_: HaveAvx2, norm: &mut [u64; 16], red: &Red) {
    // SAFETY: reads 40 words and writes 16, and the token proves AVX2.
    unsafe { rsaz_1024_red2norm_avx2(norm.as_mut_ptr(), red.as_ptr()) };
}

/// Stores `val` as `table[i]`, for a public `i` below 32.
fn scatter(_: HaveAvx2, table: &mut Table, val: &Red, i: u32) {
    assert!(i < 32);
    // SAFETY: `i` is below 32, so the routine writes 16 bytes in each of the
    // table's 9 rows of 512, and it reads 36 words of `val`; the token proves
    // AVX2.
    unsafe { rsaz_1024_scatter5_avx2(table.0.as_mut_ptr(), val.as_ptr(), i) };
}

/// Loads `table[i]` into `val`, for a secret `i` below 32, reading every
/// entry.
fn gather(_: HaveAvx2, val: &mut Red, table: &Table, i: u32) {
    // SAFETY: the routine reads the whole 32-byte aligned table whatever `i`
    // is, and writes 40 words; the token proves AVX2.
    unsafe { rsaz_1024_gather5_avx2(val.as_mut_ptr(), table.0.as_ptr(), i) };
}

/// The limb mask, which the products load.
#[repr(C, align(64))]
struct AndMask([u64; 4]);

/// The scatter's permutation, then the gather's and its index increments,
/// which the gather reads as one: 32-byte aligned.
#[repr(C, align(64))]
struct ScatterPermd([u32; 40]);

static AND_MASK: AndMask = AndMask(include!("aws_lc/rsaz-avx2.and_mask.rs"));
static SCATTER_PERMD: ScatterPermd = ScatterPermd(include!("aws_lc/rsaz-avx2.scatter_permd.rs"));

// The routines take the System V ABI on every OS, since their text is
// aws-lc's ELF and Mach-O flavors, which read their arguments from its
// registers.

macro_rules! rsaz_routine {
    ($name:ident ($($arg:ident: $ty:ty),*) $(, $table:ident = $sym:ident)*) => {
        #[unsafe(naked)]
        unsafe extern "sysv64" fn $name($($arg: $ty),*) {
            #[cfg(not(target_vendor = "apple"))]
            core::arch::naked_asm!(
                include_str!(concat!("aws_lc/", stringify!($name), ".linux.s")),
                $($table = sym $sym,)*
                options(att_syntax)
            );
            #[cfg(target_vendor = "apple")]
            core::arch::naked_asm!(
                include_str!(concat!("aws_lc/", stringify!($name), ".apple.s")),
                $($table = sym $sym,)*
                options(att_syntax)
            );
        }
    };
}

rsaz_routine!(rsaz_1024_sqr_avx2(r: *mut u64, a: *const u64, m: *const u64, n0: u64, count: i32), and_mask = AND_MASK);
rsaz_routine!(rsaz_1024_mul_avx2(r: *mut u64, a: *const u64, b: *const u64, m: *const u64, n0: u64), and_mask = AND_MASK);
rsaz_routine!(rsaz_1024_norm2red_avx2(red: *mut u64, norm: *const u64));
rsaz_routine!(rsaz_1024_red2norm_avx2(norm: *mut u64, red: *const u64));
rsaz_routine!(rsaz_1024_scatter5_avx2(table: *mut u64, val: *const u64, i: u32), scatter_permd = SCATTER_PERMD);
rsaz_routine!(rsaz_1024_gather5_avx2(val: *mut u64, table: *const u64, i: u32), scatter_permd = SCATTER_PERMD);

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::super::adx_mux::tests::Rng;
    use super::*;
    use crate::low::PosInt;

    // Only CPUs without ADX run RSAZ, so on any with AVX2 this checks it
    // against the exponentiation the others run.
    #[test]
    fn matches_mont_exp() {
        let Some(token) = HaveAvx2::check() else {
            return;
        };
        let mut rng = Rng(0x6a09_e667_f3bc_c908);
        let int = |words: &[u64; 16]| {
            let bytes: Vec<u8> = words.iter().rev().flat_map(|w| w.to_be_bytes()).collect();
            PosInt::<16>::from_bytes(&bytes).unwrap()
        };
        let words = |int: &PosInt<16>| {
            let mut bytes = [0; 128];
            let bytes = int.to_bytes(&mut bytes).unwrap();
            let mut words = [0; 16];
            for (word, chunk) in words.iter_mut().zip(bytes.rchunks(8)) {
                *word = u64::from_be_bytes(chunk.try_into().unwrap());
            }
            words
        };
        for case in 0..24 {
            // The widest modulus, the narrowest with its top word set, and
            // random 1024-bit ones.
            let mut m: [u64; 16] = rng.words(1024);
            match case {
                0 => m.fill(u64::MAX),
                1 => {
                    m.fill(0);
                    m[15] = 1;
                }
                _ => m[15] |= 1 << 63,
            }
            m[0] |= 1;

            // Bases below `m`: zero, one, and `m - 1` too.
            let mut x: [u64; 16] = rng.words(1024);
            x[15] %= m[15];
            match case {
                2 => x = [0; 16],
                3 => x = [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                4 => {
                    x = m;
                    x[0] -= 1;
                }
                _ => {}
            }

            // Exponents of every width: zero, one, all ones, and only the
            // top bit, which each window reaches.
            let mut e: [u64; 16] = rng.words(64 * (1 + case % 16));
            match case {
                5 => e = [0; 16],
                6 => e = [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                7 => e = [u64::MAX; 16],
                8 => {
                    e = [0; 16];
                    e[15] = 1 << 63;
                }
                _ => {}
            }

            let (n, x_int, mut e_int) = (int(&m), int(&x), int(&e));
            // As wide as RSAZ takes it, which the other needs for zero.
            e_int.expand(&n);
            let rr = n.montifier();
            let n0 = n.mont_neg_inverse();
            let one = n.fixed_one().mont_mul(&rr, &n, n0);
            let want = x_int
                .to_montgomery(&rr, &n)
                .mont_exp(one, &e_int, &n, n0)
                .from_montgomery(&n);

            let mut got = [0; 16];
            mod_exp(token, &mut got, &x, &e, &m, &words(&rr), n0);
            assert_eq!(got, words(&want), "case {case}");
        }
    }
}
