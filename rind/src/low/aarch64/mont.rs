// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

//! Montgomery multiplication modulo an RSA modulus or prime: s2n-bignum's
//! Karatsuba routines and 8n reduction for 1024- and 2048-bit moduli, and
//! its generic `bignum_montmul` and `bignum_montsqr` for other sizes.

/// `z = x * y / 2^(64k) mod m`, for `x` and `y` below `m`, where `k` is the
/// length of each and `n0` is `-m^-1 mod 2^64`.
pub(crate) fn mont_mul(z: &mut [u64], x: &[u64], y: &[u64], m: &[u64], n0: u64) {
    debug_assert!(z.len() == m.len() && x.len() == m.len() && y.len() == m.len());
    match m.len() {
        16 => {
            let mut product = [0; 32];
            super::bignum_kmul_16_32::bignum_kmul_16_32(&mut product, x, y, &mut [0; 32]);
            redc_8n(z, &mut product, m, n0);
        }
        32 => {
            let mut product = [0; 64];
            super::bignum_kmul_32_64::bignum_kmul_32_64(&mut product, x, y, &mut [0; 96]);
            redc_8n(z, &mut product, m, n0);
        }
        _ => super::bignum_montmul::bignum_montmul(z, x, y, m),
    }
}

/// `z = x^2 / 2^(64k) mod m`, for `x` below `m`, where `k` is the length of
/// each and `n0` is `-m^-1 mod 2^64`.
pub(crate) fn mont_sqr(z: &mut [u64], x: &[u64], m: &[u64], n0: u64) {
    debug_assert!(z.len() == m.len() && x.len() == m.len());
    match m.len() {
        16 => {
            let mut product = [0; 32];
            super::bignum_ksqr_16_32::bignum_ksqr_16_32(&mut product, x, &mut [0; 24]);
            redc_8n(z, &mut product, m, n0);
        }
        32 => {
            let mut product = [0; 64];
            super::bignum_ksqr_32_64::bignum_ksqr_32_64(&mut product, x, &mut [0; 72]);
            redc_8n(z, &mut product, m, n0);
        }
        _ => super::bignum_montsqr::bignum_montsqr(z, x, m),
    }
}

/// Reduces the `2k`-word `product` into the `k`-word `z`, fully, modulo `m`.
fn redc_8n(z: &mut [u64], product: &mut [u64], m: &[u64], n0: u64) {
    let carry = super::bignum_emontredc_8n::bignum_emontredc_8n(product, m, n0);
    let (_, reduced) = product.split_at(m.len());
    let carry = carry | super::bignum_cmp_lt::bignum_cmp_lt(m, reduced);
    super::bignum_optsub::bignum_optsub(z, reduced, m, carry);
}
