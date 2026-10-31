// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

//! s2n-bignum's routines that are generic over an odd modulus, for the
//! group orders armv7 has fiat-crypto arithmetic for, told apart by their
//! length: n_384 and n_521.  Each refuses any other modulus.

use super::{p384, p521};

/// z := x * y / 2^(64k) mod m, for m = n_384 or n_521 of k words
pub(crate) fn bignum_montmul(z: &mut [u64], x: &[u64], y: &[u64], m: &[u64]) {
    match m.len() {
        6 => p384::bignum_montmul(z, x, y, m),
        _ => p521::bignum_montmul(z, x, y, m),
    }
}

/// z := x / 2^(64k) mod m, for m = n_384 or n_521 of k words
pub(crate) fn bignum_demont(z: &mut [u64], x: &[u64], m: &[u64]) {
    match m.len() {
        6 => p384::bignum_demont(z, x, m),
        _ => p521::bignum_demont(z, x, m),
    }
}

/// z := (x + y) mod m, for m = n_384 or n_521
pub(crate) fn bignum_modadd(z: &mut [u64], x: &[u64], y: &[u64], m: &[u64]) {
    match m.len() {
        6 => p384::bignum_modadd(z, x, y, m),
        _ => p521::bignum_modadd(z, x, y, m),
    }
}

/// z := a^-1 mod b, for b = n_384 or n_521
pub(crate) fn bignum_modinv(z: &mut [u64], a: &[u64], b: &[u64], t: &mut [u64]) {
    match b.len() {
        6 => p384::bignum_modinv(z, a, b, t),
        _ => p521::bignum_modinv(z, a, b, t),
    }
}

/// z := 2^(128k) mod m, for m = n_384 or n_521 of k words
#[cfg(test)]
pub(crate) fn bignum_montifier(z: &mut [u64], m: &[u64], t: &mut [u64]) {
    match m.len() {
        6 => p384::bignum_montifier(z, m, t),
        _ => p521::bignum_montifier(z, m, t),
    }
}
