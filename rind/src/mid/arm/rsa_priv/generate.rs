// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

//! RSA key generation over HACL*'s `Bignum64`.
//!
//! It makes the same decisions as the other backends' `generate.rs`
//! (FIPS186-5 A.1.3 and B.3.1, with the same small-prime sieve and witness
//! draws), so the same random input yields the same key. It runs in constant
//! time in the secret primes, revealing only whether each candidate is
//! discarded.
//!
//! References to FIPS186-5 are to:
//! <https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-5.pdf>

use core::ops::Range;

use libcrux_hacl_rs::bignum::bignum64;

use super::exponents::{Exponents, PUBLIC_EXPONENT, shift_right_secret};
use super::{MAX_PRIVATE_MODULUS_BYTES, MAX_PRIVATE_MODULUS_WORDS, Mont, RsaPrivateKey};
use crate::Error;
use crate::low::{self, PosInt, ct};
use crate::mid::rng::RandomSource;
use crate::mid::rsa_key_size::RsaKeySize;

pub(super) fn generate_key(
    size: RsaKeySize,
    candidate_random: &mut dyn RandomSource,
    checks_random: &mut dyn RandomSource,
) -> Result<RsaPrivateKey, Error> {
    let len = size.prime_bits() / 64;
    let sieve = Sieve::new();

    // 2 ^ (nlen / 2 - 100), the closest p and q may be.
    let mut min_distance = [0u64; MAX_PRIVATE_MODULUS_WORDS];
    let bit = size.prime_bits() - 100;
    min_distance[bit / 64] = 1 << (bit % 64);

    loop {
        let mut p = random_prime(size, &sieve, candidate_random, checks_random)?;
        let mut q = loop {
            let q = random_prime(size, &sieve, candidate_random, checks_random)?;
            let (p, q_words) = (&p.0[..len], &q.0[..len]);

            if public(bignum64::eq_mask(len as u32, p, q_words)) != 0 {
                // for the set of `RsaSizes` supported here, choosing p == q
                // means `random` is hosed.
                return Err(Error::RngFailed);
            }

            // A.1.3 step 5.4: draw q again if |p - q| <= 2 ^ (nlen / 2 - 100).
            let swap = bignum64::lt_mask(len as u32, p, q_words);
            let mut distance = [[0u64; MAX_PRIVATE_MODULUS_WORDS]; 2];
            let [p_q, q_p] = &mut distance;
            bignum64::sub(len as u32, p, q_words, &mut p_q[..len]);
            bignum64::sub(len as u32, q_words, p, &mut q_p[..len]);
            for (p_q, q_p) in p_q.iter_mut().zip(q_p.iter()) {
                *p_q ^= (*p_q ^ *q_p) & swap;
            }
            if public(bignum64::lt_mask(
                len as u32,
                &min_distance[..len],
                &p_q[..len],
            )) != 0
            {
                break q;
            }
        };
        let (p, q) = (&mut p.0[..len], &mut q.0[..len]);

        // arrange that q < p, without revealing which was drawn first.
        let swap = bignum64::lt_mask(len as u32, p, q);
        for (p, q) in p.iter_mut().zip(q.iter_mut()) {
            let t = (*p ^ *q) & swap;
            *p ^= t;
            *q ^= t;
        }

        let Some(k) = Exponents::derive(p, q) else {
            // e divides p - 1 or q - 1, or d is too small: throw away both
            // primes and start again.
            continue;
        };
        let mut s = Derivation::default();
        s.derive(p, q);

        // `new` checks only what the construction fixes (odd, full-length
        // primes of matching widths), so its branches reveal nothing.
        return RsaPrivateKey::new(
            public(PosInt::from_words(p)?),
            public(PosInt::from_words(q)?),
            public(PosInt::from_words(&k.d[..len * 2])?),
            public(PosInt::from_words(&k.dp[..len])?),
            public(PosInt::from_words(&k.dq[..len])?),
            public(PosInt::from_words(&s.iqmp[..len])?),
            public(PosInt::from_words(&s.n[..len * 2])?),
            PUBLIC_EXPONENT.into(),
        );
    }
}

/// `iqmp` and `n` for a pair of primes, zeroed on drop.
struct Derivation {
    p_2: [u64; MAX_PRIVATE_MODULUS_WORDS],
    iqmp: [u64; MAX_PRIVATE_MODULUS_WORDS],
    n: [u64; MAX_PRIVATE_MODULUS_WORDS * 2],
}

impl Derivation {
    /// Derives `iqmp` and `n` from primes `q < p`.
    fn derive(&mut self, p: &[u64], q: &[u64]) {
        let len = p.len();
        let w = len as u32;

        // iqmp = q ^ (p - 2) mod p, by Fermat's little theorem since p
        // is prime. HACL* requires the base below the modulus: q < p.
        let p_2 = &mut self.p_2[..len];
        bignum64::sub(w, p, &ONE_TWO[1][..len], p_2);
        let ctx = Mont::new_secret(p, len);
        bignum64::mod_exp_consttime_precomp(&ctx, q, w * 64, p_2, &mut self.iqmp[..len]);

        bignum64::mul(w, p, q, &mut self.n[..len * 2]);
    }
}

impl Default for Derivation {
    fn default() -> Self {
        Self {
            p_2: [0; MAX_PRIVATE_MODULUS_WORDS],
            iqmp: [0; MAX_PRIVATE_MODULUS_WORDS],
            n: [0; MAX_PRIVATE_MODULUS_WORDS * 2],
        }
    }
}

impl Drop for Derivation {
    fn drop(&mut self) {
        low::zeroise(&mut self.p_2);
        low::zeroise(&mut self.iqmp);
        low::zeroise(&mut self.n);
    }
}

/// A secret prime's words, zeroed on drop.
struct Prime([u64; MAX_PRIVATE_MODULUS_WORDS]);

impl Drop for Prime {
    fn drop(&mut self) {
        low::zeroise(&mut self.0);
    }
}

fn random_prime(
    size: RsaKeySize,
    sieve: &Sieve,
    candidate_random: &mut dyn RandomSource,
    checks_random: &mut dyn RandomSource,
) -> Result<Prime, Error> {
    let len = size.prime_bits() / 64;
    let mut buffer = [0u8; MAX_PRIVATE_MODULUS_BYTES];
    let mut candidate = Prime([0; MAX_PRIVATE_MODULUS_WORDS]);
    loop {
        candidate_random.fill(&mut buffer[..len * 8])?;

        // set top two bits to ensure the product of two primes, n, is the right size.
        buffer[0] |= 0b1100_0000;

        // set bottom bit: an even number (of given `size`) is never prime
        buffer[len * 8 - 1] |= 0b0000_0001;

        for (word, bytes) in candidate
            .0
            .iter_mut()
            .zip(buffer[..len * 8].rchunks_exact(8))
        {
            *word = u64::from_be_bytes(bytes.try_into().unwrap());
        }
        ct::secret_slice(&candidate.0[..len]);

        if is_prime(&candidate.0[..len], size, sieve, checks_random)? {
            return Ok(candidate);
        }
    }
}

fn is_prime(
    candidate: &[u64],
    size: RsaKeySize,
    sieve: &Sieve,
    rng: &mut dyn RandomSource,
) -> Result<bool, Error> {
    if !sieve.is_coprime(candidate) {
        return Ok(false);
    }

    miller_rabin(candidate, size, rng)
}

fn miller_rabin(w: &[u64], size: RsaKeySize, rng: &mut dyn RandomSource) -> Result<bool, Error> {
    let len = w.len();
    let ctx = Mont::new_secret(w, len);

    // See FIPS186-5 B.3.1:
    // 1. Let a be the largest integer such that 2 ^ a divides w - 1.
    //
    // w is odd, so w - 1 clears bit 0.
    let mut s = MillerRabinScratch::default();
    let w1 = &mut s.w1[..len];
    w1.copy_from_slice(w);
    w1[0] ^= 1;
    let a = trailing_zeros(w1);

    // 2. m = (w - 1) / 2 ^ a.
    shift_right_secret(&s.w1[..len], a, &mut s.m[..len]);

    // The base's range, w - 2 and w - 3.
    bignum64::sub(len as u32, w, &ONE_TWO[1][..len], &mut s.w2[..len]);
    bignum64::sub(
        len as u32,
        &s.w2[..len],
        &ONE_TWO[0][..len],
        &mut s.w3[..len],
    );

    // 4. For i = 1 to iterations do
    for _ in 0..size.miller_rabin_rounds() {
        // Steps 4.1-4.6 inclusive.
        s.random_base(len, rng)?;
        if !s.check_base(&ctx, len, a) {
            return Ok(false);
        }
        // 4.7. Continue
    }

    // 5. Return PROBABLY PRIME.
    Ok(true)
}

/// Miller-Rabin's working, zeroed on drop.
struct MillerRabinScratch {
    w1: [u64; MAX_PRIVATE_MODULUS_WORDS],
    w2: [u64; MAX_PRIVATE_MODULUS_WORDS],
    w3: [u64; MAX_PRIVATE_MODULUS_WORDS],
    m: [u64; MAX_PRIVATE_MODULUS_WORDS],
    b: [u64; MAX_PRIVATE_MODULUS_WORDS],
    z: [u64; MAX_PRIVATE_MODULUS_WORDS],
    wide: [u64; MAX_PRIVATE_MODULUS_WORDS * 2],
}

impl MillerRabinScratch {
    /// Steps 4.1 and 4.2: leaves in `b` a base with `1 < b < w - 1`, for a
    /// `w` of `len` words.
    ///
    /// Rather than draw `wlen` bits until they fall in range, which would
    /// reveal how far `w` is below a power of two, this draws 64 bits more
    /// and reduces them, so each base is within `2 ^ -64` of uniform.
    fn random_base(&mut self, len: usize, rng: &mut dyn RandomSource) -> Result<(), Error> {
        let bytes = len * 8 + 8;
        let mut buffer = [0u8; MAX_PRIVATE_MODULUS_BYTES + 8];
        rng.fill(&mut buffer[..bytes])?;
        let wide = PosInt::<{ MAX_PRIVATE_MODULUS_WORDS * 2 }>::from_bytes(&buffer[..bytes])?;

        // w - 2 - (wide mod (w - 3)) is in [2, w - 2].
        let r = &mut self.z[..len];
        super::reduce_even(wide.words_at_width(len + 1)?, &self.w3[..len], r);
        bignum64::sub(len as u32, &self.w2[..len], r, &mut self.b[..len]);
        Ok(())
    }

    /// Steps 4.3 to 4.6 for base `b`, returning false for COMPOSITE.
    ///
    /// As aws-lc's `bn_miller_rabin_iteration`, this squares until `wlen`
    /// rather than `a`, which is secret, and exits early only for a
    /// composite.
    fn check_base(&mut self, ctx: &Mont, len: usize, a: usize) -> bool {
        let w = len as u32;
        let (w1, z) = (&self.w1[..len], &mut self.z[..len]);
        let one = &ONE_TWO[0][..len];

        // 4.3. z = b ^ m mod w.
        bignum64::mod_exp_consttime_precomp(ctx, &self.b[..len], w * 64, &self.m[..len], z);

        // 4.4. If ((z = 1) or (z = w − 1)), then go to step 4.7.
        let mut possibly_prime = bignum64::eq_mask(w, z, one) | bignum64::eq_mask(w, z, w1);

        // 4.5. For j = 1 to a − 1 do.
        for j in 1..len * 64 {
            if public(mask_eq(j as u64, a as u64) & !possibly_prime) != 0 {
                break;
            }

            // 4.5.1. z = z ^ 2 mod w.
            let wide = &mut self.wide[..len * 2];
            bignum64::sqr(w, z, wide);
            bignum64::mod_precomp(ctx, wide, z);

            // 4.5.2. If (z = w − 1), then go to step 4.7.
            possibly_prime |= bignum64::eq_mask(w, z, w1);

            // 4.5.3 If (z = 1), then go to step 4.6.
            if public(bignum64::eq_mask(w, z, one) & !possibly_prime) != 0 {
                break;
            }
        }

        // 4.6. Return COMPOSITE, unless step 4.7 was reached.
        public(possibly_prime) != 0
    }
}

impl Default for MillerRabinScratch {
    fn default() -> Self {
        Self {
            w1: [0; MAX_PRIVATE_MODULUS_WORDS],
            w2: [0; MAX_PRIVATE_MODULUS_WORDS],
            w3: [0; MAX_PRIVATE_MODULUS_WORDS],
            m: [0; MAX_PRIVATE_MODULUS_WORDS],
            b: [0; MAX_PRIVATE_MODULUS_WORDS],
            z: [0; MAX_PRIVATE_MODULUS_WORDS],
            wide: [0; MAX_PRIVATE_MODULUS_WORDS * 2],
        }
    }
}

impl Drop for MillerRabinScratch {
    fn drop(&mut self) {
        low::zeroise(&mut self.w1);
        low::zeroise(&mut self.w2);
        low::zeroise(&mut self.w3);
        low::zeroise(&mut self.m);
        low::zeroise(&mut self.b);
        low::zeroise(&mut self.z);
        low::zeroise(&mut self.wide);
    }
}

/// The number of trailing zero bits of a nonzero `x`, without revealing
/// it: as aws-lc's `BN_count_low_zero_bits`, each word's count is kept only
/// for the lowest nonzero word, found by halving its width. The sums wrap:
/// a debug build's overflow check would branch on secret values.
fn trailing_zeros(x: &[u64]) -> usize {
    let mut count = 0;
    let mut seen = 0;
    for (i, word) in x.iter().enumerate() {
        let nonzero = !mask_eq(*word, 0);
        let (mut w, mut bits) = (*word, 0u64);
        for width in [32, 16, 8, 4, 2, 1] {
            let low_zero = mask_eq(w & ((1 << width) - 1), 0);
            bits = bits.wrapping_add(width & low_zero);
            w ^= (w ^ (w >> width)) & low_zero;
        }
        count |= nonzero & !seen & (i as u64 * 64).wrapping_add(bits);
        seen |= nonzero;
    }
    count as usize
}

/// All ones if `x == y`, and zero if not, without a branch.
fn mask_eq(x: u64, y: u64) -> u64 {
    let d = x ^ y;
    core::hint::black_box(((d | d.wrapping_neg()) >> 63).wrapping_sub(1))
}

/// Trial division by the odd primes below 743, whose product fits in 1024
/// bits, our smallest prime.
///
/// The other backends check that a candidate is coprime to that product
/// with `bignum_coprime`; `Bignum64` has no GCD, so this reduces the
/// candidate modulo word-sized products of those primes instead, then
/// tests each prime's divisibility of the remainder.
struct Sieve {
    /// A context for each product, with the range of `SMALL_PRIMES` in it.
    products: Vec<(Mont, Range<usize>)>,
}

impl Sieve {
    fn new() -> Self {
        let mut products = Vec::new();
        let mut start = 0;
        while start < SMALL_PRIMES.len() {
            let mut product = 1u64;
            let mut end = start;
            while let Some(next) = SMALL_PRIMES
                .get(end)
                .and_then(|prime| product.checked_mul(*prime))
            {
                product = next;
                end += 1;
            }
            products.push((Mont::new(&[product]), start..end));
            start = end;
        }
        Self { products }
    }

    /// Whether `candidate` has no factor in `SMALL_PRIMES`.
    fn is_coprime(&self, candidate: &[u64]) -> bool {
        for (ctx, primes) in &self.products {
            // candidate mod product, by Horner's rule over its words.
            let mut r = [0u64];
            for word in candidate.iter().rev() {
                bignum64::mod_precomp(ctx, &[*word, r[0]], &mut r);
            }

            // For odd s, s divides r exactly when r * s ^ -1 mod 2 ^ 64 is
            // at most (2 ^ 64 - 1) / s (Granlund and Montgomery, "Division
            // by invariant integers using multiplication", 1994, section 9).
            //
            // Each mask passes through `black_box`: inlined, `lt_mask`'s
            // one-word comparison became a branch on the remainder.
            let mut divisible = 0;
            for (inv, limit) in SMALL_PRIME_DIVISORS[primes.clone()].iter() {
                let (_, above) = limit.overflowing_sub(r[0].wrapping_mul(*inv));
                divisible |= core::hint::black_box(u64::from(above).wrapping_sub(1));
            }
            if public(divisible) != 0 {
                return false;
            }
        }
        true
    }
}

/// The odd primes below 743: the other backends' `PRODUCT_OF_SMALL_PRIMES`.
const SMALL_PRIMES: [u64; 130] = {
    let mut primes = [0; 130];
    let (mut found, mut n) = (0, 3);
    while n < 743 {
        let mut d = 3;
        while d * d <= n && n % d != 0 {
            d += 2;
        }
        if d * d > n {
            primes[found] = n;
            found += 1;
        }
        n += 2;
    }
    assert!(found == primes.len());
    primes
};

/// For each of `SMALL_PRIMES`, its inverse modulo `2 ^ 64` and the largest
/// quotient `(2 ^ 64 - 1) / s`.
const SMALL_PRIME_DIVISORS: [(u64, u64); 130] = {
    let mut divisors = [(0, 0); 130];
    let mut i = 0;
    while i < divisors.len() {
        let s = SMALL_PRIMES[i];
        // As in `divide_exact_e`: Newton's iteration from `s * s = 1 (mod 8)`.
        let mut inv = s;
        let mut j = 0;
        while j < 5 {
            inv = inv.wrapping_mul(2u64.wrapping_sub(s.wrapping_mul(inv)));
            j += 1;
        }
        assert!(inv.wrapping_mul(s) == 1);
        divisors[i] = (inv, u64::MAX / s);
        i += 1;
    }
    divisors
};

/// One and two, at every width.
const ONE_TWO: [[u64; MAX_PRIVATE_MODULUS_WORDS]; 2] = {
    let mut r = [[0; MAX_PRIVATE_MODULUS_WORDS]; 2];
    r[0][0] = 1;
    r[1][0] = 2;
    r
};

/// Declassifies a decision this module reveals by branching on it.
fn public<T>(v: T) -> T {
    ct::into_public(v)
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::high::hash::Sha256;
    use crate::high::hmac_drbg::HmacDrbg;
    use crate::mid::rng::{ChainRandomSource, SliceRandomSource, SystemRandom};

    fn read_hex(data: &str) -> Vec<u8> {
        data.split_whitespace()
            .flat_map(|line| {
                (0..line.len())
                    .step_by(2)
                    .map(|i| u8::from_str_radix(&line[i..i + 2], 16).unwrap())
            })
            .collect()
    }

    fn check_primes(data: &str, expected: bool) {
        let sieve = Sieve::new();
        for line in data.lines().filter(|line| !line.starts_with("#")) {
            let candidate =
                PosInt::<MAX_PRIVATE_MODULUS_WORDS>::from_bytes(&read_hex(line)).unwrap();
            assert_eq!(
                is_prime(
                    candidate.as_words(),
                    RsaKeySize::Rsa2048,
                    &sieve,
                    &mut HmacDrbg::<Sha256>::new(b"", b"", b"")
                ),
                Ok(expected),
                "{line}"
            );
        }
    }

    #[test]
    fn valid_primes() {
        check_primes(include_str!("../../../testdata/valid-primes.txt"), true);
    }

    #[test]
    fn invalid_primes() {
        check_primes(include_str!("../../../testdata/invalid-primes.txt"), false);
    }

    #[test]
    fn sieve_matches_remainder() {
        let sieve = Sieve::new();
        assert_eq!(sieve.products.last().unwrap().1.end, SMALL_PRIMES.len());

        // Each small prime, and its multiples either side of the top of two
        // words, where `r * s ^ -1` is closest to the limit.
        for s in SMALL_PRIMES.map(u128::from) {
            let top = u128::MAX / s * s;
            for x in [s, s * 743, top, top - 1, top - s + 1, s << 64] {
                let coprime = SMALL_PRIMES.iter().all(|s| x % u128::from(*s) != 0);
                let words = [x as u64, (x >> 64) as u64];
                assert_eq!(sieve.is_coprime(&words), coprime, "{x:#x}");
            }
        }
    }

    #[test]
    fn counts_trailing_zeros() {
        for (x, zeros) in [
            ([1u64, 0], 0),
            ([8, 1], 3),
            ([1 << 63, 0], 63),
            ([0, 1], 64),
            ([0, 1 << 63], 127),
        ] {
            assert_eq!(trailing_zeros(&x), zeros, "{x:x?}");
        }
    }

    #[test]
    fn hosed_rng() {
        // candidate rng
        assert_eq!(
            generate_key(
                RsaKeySize::Rsa2048,
                &mut SliceRandomSource(&[]),
                &mut SystemRandom
            )
            .err(),
            Some(Error::RngFailed)
        );
        // MR base rng
        assert_eq!(
            generate_key(
                RsaKeySize::Rsa2048,
                &mut SystemRandom,
                &mut SliceRandomSource(&[]),
            )
            .err(),
            Some(Error::RngFailed)
        );
    }

    #[test]
    fn p_q_equal() {
        // get one prime from this test vector and duplicate it.
        let mut bytes = read_hex(include_str!(
            "../../../testdata/rsa.phi-not-coprime-e.2048.txt"
        ));
        assert_eq!(bytes.len(), 256);
        bytes.drain(128..);
        bytes.extend_from_within(..);

        assert_eq!(
            generate_key(
                RsaKeySize::Rsa2048,
                &mut SliceRandomSource(&bytes),
                &mut SystemRandom
            )
            .err(),
            Some(Error::RngFailed),
        );
    }

    /// `x + step`, for a step that does not carry out of the last two bytes.
    fn offset(x: &[u8], step: u16) -> Vec<u8> {
        let (head, tail) = x.split_at(x.len() - 2);
        let tail = u16::from_be_bytes(tail.try_into().unwrap()) + step;
        [head, &tail.to_be_bytes()].concat()
    }

    #[test]
    fn p_q_close() {
        let mut p = read_hex(include_str!(
            "../../../testdata/rsa.phi-not-coprime-e.2048.txt"
        ));
        p.truncate(128);

        // The next prime after p, far within 2 ^ 924 of it.
        let close = offset(&p, 814);
        check_primes(
            &close.iter().map(|b| format!("{b:02x}")).collect::<String>(),
            true,
        );

        // A prime below p by about 2 ^ 1008, which completes a key with p.
        let mut far = p.clone();
        far[1] ^= 1;
        let far = offset(&far, 346);

        let candidates = [&p[..], &close, &far].concat();
        let key = generate_key(
            RsaKeySize::Rsa2048,
            &mut SliceRandomSource(&candidates),
            &mut SystemRandom,
        )
        .unwrap();

        // p is kept and only q is drawn again.
        let p = PosInt::<MAX_PRIVATE_MODULUS_WORDS>::from_bytes(&p).unwrap();
        let far = PosInt::<MAX_PRIVATE_MODULUS_WORDS>::from_bytes(&far).unwrap();
        let w = p.as_words().len() as u32;
        let kept = bignum64::eq_mask(w, key.p.as_words(), p.as_words())
            & bignum64::eq_mask(w, key.q.as_words(), far.as_words());
        assert_eq!(public(kept), u64::MAX);
    }

    #[test]
    fn phi_not_coprime_e() {
        let bytes = read_hex(include_str!(
            "../../../testdata/rsa.phi-not-coprime-e.2048.txt"
        ));

        let mut fixed_source = SliceRandomSource(&bytes);
        let mut retry_source = SystemRandom;
        let mut candidate_source = ChainRandomSource::First(&mut fixed_source, &mut retry_source);
        generate_key(
            RsaKeySize::Rsa2048,
            &mut candidate_source,
            &mut SystemRandom,
        )
        .unwrap();
    }
}
