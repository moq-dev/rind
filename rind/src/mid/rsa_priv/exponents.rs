// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

//! The private exponents of a generated key, derived from its primes in
//! constant time on every backend.
//!
//! References to FIPS186-5 are to:
//! <https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-5.pdf>

use super::MAX_PRIVATE_MODULUS_WORDS;
use crate::low::ct;

/// We only support F4 for the public exponent.
pub(super) const PUBLIC_EXPONENT: u32 = 0x10001;

const E: u64 = PUBLIC_EXPONENT as u64;

/// `d`, `dp`, and `dq` for a pair of primes.
pub(super) struct Exponents {
    pub(super) d: [u64; MAX_PRIVATE_MODULUS_WORDS * 2],
    pub(super) dp: [u64; MAX_PRIVATE_MODULUS_WORDS],
    pub(super) dq: [u64; MAX_PRIVATE_MODULUS_WORDS],
}

impl Exponents {
    /// Derives the exponents from odd primes `p` and `q` of equal width,
    /// or returns `None` if the key must be discarded.
    ///
    /// `d` is `e ^ -1 mod lcm(p - 1, q - 1)`, as FIPS186-5 A.1.1 and aws-lc
    /// have it, and like aws-lc this discards a key whose `d` is at most
    /// `2 ^ (nlen / 2)`. Only that verdict, and whether `e` divides
    /// `p - 1` or `q - 1`, is revealed.
    pub(super) fn derive(p: &[u64], q: &[u64]) -> Option<Self> {
        let len = p.len();
        let mut k = Self {
            d: [0; MAX_PRIVATE_MODULUS_WORDS * 2],
            dp: [0; MAX_PRIVATE_MODULUS_WORDS],
            dq: [0; MAX_PRIVATE_MODULUS_WORDS],
        };

        // p and q are odd, so subtracting one clears bit 0.
        let mut p_1 = [0u64; MAX_PRIVATE_MODULUS_WORDS];
        let p_1 = &mut p_1[..len];
        p_1.copy_from_slice(p);
        p_1[0] ^= 1;
        let mut q_1 = [0u64; MAX_PRIVATE_MODULUS_WORDS];
        let q_1 = &mut q_1[..len];
        q_1.copy_from_slice(q);
        q_1[0] ^= 1;

        // lcm(p - 1, q - 1) = (p - 1) * ((q - 1) / gcd(p - 1, q - 1)).
        let mut cofactor = [0u64; MAX_PRIVATE_MODULUS_WORDS];
        let cofactor = &mut cofactor[..len];
        divide_by_gcd(q_1, p_1, cofactor);
        let mut lcm = [0u64; MAX_PRIVATE_MODULUS_WORDS * 2];
        let lcm = &mut lcm[..len * 2];
        mul(p_1, cofactor, lcm);

        // As e is prime, it divides lcm(p - 1, q - 1) exactly when it
        // divides p - 1 or q - 1, so the three inversions succeed or fail
        // together.
        let ok = invert_e(lcm, &mut k.d[..len * 2])
            & invert_e(p_1, &mut k.dp[..len])
            & invert_e(q_1, &mut k.dq[..len]);

        // d > 2 ^ (64 * len) exactly when d - 1 has a bit at or above
        // 64 * len, and d is at least one.
        let mut borrow = 1;
        let mut high = 0;
        for (i, word) in k.d[..len * 2].iter().enumerate() {
            let (word, b) = word.overflowing_sub(borrow);
            borrow = u64::from(b);
            if i >= len {
                high |= word;
            }
        }
        match ok && ct::into_public(high != 0) {
            true => Some(k),
            false => None,
        }
    }
}

/// Writes `x >> shift` to `out`, as wide as `x`, without revealing `shift`,
/// which must be below `64 * x.len()`.
///
/// This shifts by each power of two below the width in turn, keeping the
/// result only where `shift` has that bit set.
pub(super) fn shift_right_secret(x: &[u64], shift: usize, out: &mut [u64]) {
    out.copy_from_slice(x);
    let len = out.len();
    let mut bit = 0;
    while 1 << bit < len * 64 {
        let keep = mask(((shift >> bit) & 1) as u64);
        let (words, bits) = ((1 << bit) / 64, (1 << bit) % 64);
        // Ascending, each word reads only words at or above itself, which
        // this pass has not written yet.
        for i in 0..len {
            let lo = out.get(i + words).copied().unwrap_or(0);
            let hi = out.get(i + words + 1).copied().unwrap_or(0);
            let shifted = match bits {
                0 => lo,
                _ => (lo >> bits) | (hi << (64 - bits)),
            };
            out[i] ^= (out[i] ^ shifted) & keep;
        }
        bit += 1;
    }
}

/// Writes `x / gcd(x, y)` to `out`, for even `x` and `y` of the same width,
/// without revealing either.
///
/// The GCD is aws-lc's `bn_gcd_consttime`: a binary GCD run for the
/// iterations its worst case needs, counting the factors of two common to
/// both. `x` then loses those factors by a secret shift, and the odd rest
/// of the GCD by `divide_exact_odd`.
fn divide_by_gcd(x: &[u64], y: &[u64], out: &mut [u64]) {
    let len = x.len();
    let mut s = Scratch::default();
    let (u, v, t) = (&mut s.u[..len], &mut s.v[..len], &mut s.t[..len]);
    u.copy_from_slice(x);
    v.copy_from_slice(y);

    // Each iteration halves at least one of u and v until one is zero, so
    // their combined width bounds the iterations.
    let mut shift = 0;
    for _ in 0..len * 128 {
        // If both are odd, subtract the smaller from the larger.
        let both_odd = mask(u[0] & v[0] & 1);
        let u_less = mask(sub(t, u, v));
        select(u, t, both_odd & !u_less);
        sub(t, v, u);
        select(v, t, both_odd & u_less);

        // Now at least one is even: halve it, counting a factor of the
        // GCD when both are.
        let (u_even, v_even) = (mask(!u[0] & 1), mask(!v[0] & 1));
        shift += (u_even & v_even & 1) as usize;
        shift_right_1(u, u_even);
        shift_right_1(v, v_even);
    }

    // One of u and v is zero, and the other the GCD's odd part.
    for (u, v) in u.iter_mut().zip(v.iter()) {
        *u |= v;
    }
    shift_right_secret(x, shift, t);
    divide_exact_odd(t, u, out);
}

/// u, v, and a temporary for `divide_by_gcd`.
struct Scratch {
    u: [u64; MAX_PRIVATE_MODULUS_WORDS],
    v: [u64; MAX_PRIVATE_MODULUS_WORDS],
    t: [u64; MAX_PRIVATE_MODULUS_WORDS],
}

impl Default for Scratch {
    fn default() -> Self {
        Self {
            u: [0; MAX_PRIVATE_MODULUS_WORDS],
            v: [0; MAX_PRIVATE_MODULUS_WORDS],
            t: [0; MAX_PRIVATE_MODULUS_WORDS],
        }
    }
}

/// Writes `x / g` to `out`, for an odd `g` that divides `x`, consuming `x`.
///
/// This is exact (Hensel) division a bit at a time, lowest first: where
/// `x` is odd, so is the quotient, and subtracting `g` makes `x` even
/// before it halves (Jebelean, "An algorithm for exact division", 1993).
fn divide_exact_odd(x: &mut [u64], g: &[u64], out: &mut [u64]) {
    out.fill(0);
    for i in 0..x.len() * 64 {
        let bit = x[0] & 1;
        let odd = mask(bit);
        let mut borrow = 0;
        for (x, g) in x.iter_mut().zip(g) {
            let (r, b1) = x.overflowing_sub(g & odd);
            let (r, b2) = r.overflowing_sub(borrow);
            *x = r;
            borrow = u64::from(b1 | b2);
        }
        shift_right_1(x, u64::MAX);
        out[i / 64] |= bit << (i % 64);
    }
}

/// Writes `e ^ -1 mod m` to `out`, as wide as `m`, or returns false if `e`
/// divides `m`.
///
/// This inverts `m` modulo the prime `e` instead, which works for an even
/// `m`: with `t = -m ^ -1 mod e`, `e` divides `t * m + 1`, and the quotient
/// `d` has `d * e = t * m + 1 = 1 (mod m)`, with `d < m` because `t < e`.
fn invert_e(m: &[u64], out: &mut [u64]) -> bool {
    // 2 ^ 64 = 1 (mod e), so m is congruent to the sum of its words.
    let x = reduce_e(m.iter().map(|w| reduce_e(*w)).sum());
    if ct::into_public(x == 0) {
        return false;
    }

    // m ^ -1 = m ^ (e - 2) = m ^ (2 ^ 16 - 1) mod e, by Fermat's little
    // theorem: each step takes x ^ (2 ^ i - 1) to x ^ (2 ^ (i + 1) - 1).
    let mut inv = x;
    for _ in 1..16 {
        inv = reduce_e(reduce_e(inv * inv) * x);
    }

    // The quotient fits `m`'s width, so only the low words of `t * m + 1`
    // determine it.
    let t = E - inv;
    let mut carry = 1;
    for (out, m) in out.iter_mut().zip(m) {
        let wide = u128::from(*m) * u128::from(t) + u128::from(carry);
        *out = wide as u64;
        carry = (wide >> 64) as u64;
    }
    divide_exact_e(out);
    true
}

/// Divides `x` by `e` in place, for an `x` that `e` divides with a quotient
/// that fits `x`.
///
/// As `divide_exact_odd`, but a word at a time: the quotient is
/// `x * e ^ -1` modulo `2 ^ (64 * len)`, carrying the part of each `q * e`
/// above its word into the next (GMP's `mpn_divexact_1`).
fn divide_exact_e(x: &mut [u64]) {
    // Newton's iteration doubles the correct low bits from the three of
    // `e * e = 1 (mod 8)`, so five steps reach 64.
    const E_INV: u64 = {
        let mut inv = E;
        let mut i = 0;
        while i < 5 {
            inv = inv.wrapping_mul(2u64.wrapping_sub(E.wrapping_mul(inv)));
            i += 1;
        }
        assert!(inv.wrapping_mul(E) == 1);
        inv
    };

    let mut borrow = 0u64;
    for x in x.iter_mut() {
        let (s, b) = x.overflowing_sub(borrow);
        *x = s.wrapping_mul(E_INV);
        borrow = ((u128::from(*x) * u128::from(E)) >> 64) as u64 + u64::from(b);
    }
}

/// `v mod e`, without division, whose time varies with its operands on
/// some CPUs: `2 ^ 16 = -1 (mod e)`, so `v`'s 16-bit digits alternate in
/// sign.
fn reduce_e(v: u64) -> u64 {
    let digit = |v: u64, i: u32| (v >> (16 * i)) & 0xffff;
    // Positive, as 2e exceeds the two digits subtracted, and at most 2 ^ 18.
    let v = digit(v, 0) + digit(v, 2) + 2 * E - digit(v, 1) - digit(v, 3);
    // Below 2e, as v's second digit is below 8.
    let v = digit(v, 0) + E - digit(v, 1);
    let (r, borrow) = v.overflowing_sub(E);
    r.wrapping_add(E & mask(u64::from(borrow)))
}

/// Writes `x - y` to `out`, returning the borrow.
fn sub(out: &mut [u64], x: &[u64], y: &[u64]) -> u64 {
    let mut borrow = 0;
    for ((out, x), y) in out.iter_mut().zip(x).zip(y) {
        let (r, b1) = x.overflowing_sub(*y);
        let (r, b2) = r.overflowing_sub(borrow);
        *out = r;
        borrow = u64::from(b1 | b2);
    }
    borrow
}

/// Copies `x` into `out` where `keep` is all ones.
fn select(out: &mut [u64], x: &[u64], keep: u64) {
    for (out, x) in out.iter_mut().zip(x) {
        *out ^= (*out ^ x) & keep;
    }
}

/// Halves `x` where `keep` is all ones.
fn shift_right_1(x: &mut [u64], keep: u64) {
    let len = x.len();
    for i in 0..len {
        let hi = x.get(i + 1).copied().unwrap_or(0);
        x[i] ^= (x[i] ^ ((x[i] >> 1) | (hi << 63))) & keep;
    }
}

/// All ones for one and zero for zero, through `black_box` so the compiler
/// cannot turn the select it feeds into a branch.
fn mask(bit: u64) -> u64 {
    core::hint::black_box(0u64.wrapping_sub(bit))
}

/// Writes `a * b` to `out`, as wide as both.
fn mul(a: &[u64], b: &[u64], out: &mut [u64]) {
    #[cfg(target_arch = "arm")]
    libcrux_hacl_rs::bignum::bignum64::mul(a.len() as u32, a, b, out);
    #[cfg(not(target_arch = "arm"))]
    crate::low::bignum_mul(out, a, b);
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    fn to_u128(x: &[u64]) -> u128 {
        (u128::from(x[1]) << 64) | u128::from(x[0])
    }

    fn words(x: u128) -> [u64; 2] {
        [x as u64, (x >> 64) as u64]
    }

    #[test]
    fn reduces_e() {
        for v in [
            0,
            1,
            E - 1,
            E,
            E + 1,
            2 * E,
            u64::MAX,
            u64::MAX - E,
            0xffff_0000_ffff_0000,
        ] {
            assert_eq!(reduce_e(v), v % E, "{v:#x}");
        }
    }

    #[test]
    fn inverts_e() {
        // Odd and even moduli, across the word boundary.
        for m in [
            [3u64, 0],
            [6, 0],
            [u64::MAX - 3, 1],
            [0x1234_5678_9abc_def0, 0xf_ffff_ffff],
        ] {
            let mut d = [0u64; 2];
            assert!(invert_e(&m, &mut d));
            let (m, d) = (to_u128(&m), to_u128(&d));
            assert!(d < m);
            assert_eq!(d * u128::from(E) % m, 1);
        }
        assert!(!invert_e(&[E * 7, 0], &mut [0; 2]));
    }

    #[test]
    fn shifts_right_secret() {
        let x = 0x8000_0000_0000_0001_8000_0000_0000_0001u128;
        for shift in [0, 1, 63, 64, 65, 127] {
            let mut out = [0u64; 2];
            shift_right_secret(&words(x), shift, &mut out);
            assert_eq!(to_u128(&out), x >> shift, "{shift}");
        }
    }

    #[test]
    fn divides_by_gcd() {
        // Common factors of two above and below the word boundary, and
        // coprime odd parts.
        for (x, y) in [
            (2u128, 2u128),
            (6, 4),
            (0x1_0000_0000_0000_0000 * 6, 0x1_0000_0000_0000_0000 * 10),
            (2 * 3 * 5 * 7 * 11 * 13, 2 * 2 * 7 * 13 * 17),
            (u128::MAX - 1, (u128::MAX - 1) / 3 * 2),
        ] {
            let mut out = [0u64; 2];
            divide_by_gcd(&words(x), &words(y), &mut out);
            let (mut a, mut b) = (x, y);
            while b != 0 {
                (a, b) = (b, a % b);
            }
            assert_eq!(to_u128(&out), x / a, "{x:#x} {y:#x}");
        }
    }
}
