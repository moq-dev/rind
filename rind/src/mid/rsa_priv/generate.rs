// Written for Graviola by Joe Birr-Pixton, 2025.
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

//! RSA key generation routines.
//!
//! These run in constant time in the secret primes, revealing only whether
//! each candidate is discarded.
//!
//! All references below are to FIPS186-5:
//! <https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-5.pdf>

use super::exponents::{Exponents, PUBLIC_EXPONENT, shift_right_secret};
use super::{MAX_PRIVATE_MODULUS_BYTES, MAX_PRIVATE_MODULUS_WORDS};
use crate::Error;
use crate::low::{self, PosInt, ct};
use crate::mid::rng::RandomSource;
use crate::mid::rsa_key_size::RsaKeySize;

pub(super) fn generate_key(
    size: RsaKeySize,
    candidate_random: &mut dyn RandomSource,
    checks_random: &mut dyn RandomSource,
) -> Result<super::RsaPrivateKey, Error> {
    let len = size.prime_bits() / 64;

    // 2 ^ (nlen / 2 - 100), the closest p and q may be.
    let mut min_distance = [0u64; MAX_PRIVATE_MODULUS_WORDS];
    let bit = size.prime_bits() - 100;
    min_distance[bit / 64] = 1 << (bit % 64);
    let min_distance: super::RsaPosIntModP = PosInt::from_words(&min_distance[..len])?;

    loop {
        let p = random_prime(size, candidate_random, checks_random)?;
        let (p, q) = loop {
            let q = random_prime(size, candidate_random, checks_random)?;

            if public(p.equals(&q)) {
                // for the set of `RsaSizes` supported here, choosing p == q
                // means `random` is hosed.
                return Err(Error::RngFailed);
            }

            // arrange that q < p, without revealing which was drawn first.
            let swap = u64::from(p.less_than(&q));
            let mut words = [[0u64; MAX_PRIVATE_MODULUS_WORDS]; 2];
            let [hi, lo] = &mut words;
            low::bignum_mux(swap, &mut hi[..len], q.as_words(), p.as_words());
            low::bignum_mux(swap, &mut lo[..len], p.as_words(), q.as_words());
            let hi: super::RsaPosIntModP = PosInt::from_words(&hi[..len])?;
            let lo: super::RsaPosIntModP = PosInt::from_words(&lo[..len])?;

            // A.1.3 step 5.4: draw q again if |p - q| <= 2 ^ (nlen / 2 - 100).
            if public(min_distance.less_than(&hi.sub(&lo))) {
                break (hi, lo);
            }
        };

        let Some(k) = Exponents::derive(p.as_words(), q.as_words()) else {
            // e divides p - 1 or q - 1, or d is too small: throw away both
            // primes and start again.
            continue;
        };

        let iqmp = q.mod_inverse(&p);
        let n: super::RsaPosIntModN = PosInt::mul(&p, &q);

        // `new` checks only what the construction fixes (odd, full-length
        // primes of matching widths), so its branches reveal nothing.
        return super::RsaPrivateKey::new(
            public(p),
            public(q),
            public(PosInt::from_words(&k.d[..len * 2])?),
            public(PosInt::from_words(&k.dp[..len])?),
            public(PosInt::from_words(&k.dq[..len])?),
            public(iqmp),
            public(n),
            PUBLIC_EXPONENT.into(),
        );
    }
}

fn random_prime(
    size: RsaKeySize,
    candidate_random: &mut dyn RandomSource,
    checks_random: &mut dyn RandomSource,
) -> Result<super::RsaPosIntModP, Error> {
    loop {
        match random_prime_one(size, candidate_random, checks_random) {
            Ok(Some(candidate)) => return Ok(candidate),
            Ok(None) => continue,
            Err(err) => return Err(err),
        }
    }
}

fn random_prime_one(
    size: RsaKeySize,
    candidate_random: &mut dyn RandomSource,
    checks_random: &mut dyn RandomSource,
) -> Result<Option<super::RsaPosIntModP>, Error> {
    let bytes = size.prime_bits() / 8;
    let mut buffer = [0u8; MAX_PRIVATE_MODULUS_BYTES];
    candidate_random.fill(&mut buffer[..bytes])?;

    // set top two bits to ensure the product of two primes, n, is the right size.
    buffer[0] |= 0b1100_0000;

    // set bottom bit: an even number (of given `size`) is never prime
    buffer[bytes - 1] |= 0b0000_0001;

    // The top byte is nonzero, so this is `bytes` wide.
    let candidate = PosInt::from_bytes(&buffer[..bytes])?;
    ct::secret_slice(candidate.as_words());

    if is_prime(&candidate, size, checks_random)? {
        Ok(Some(candidate))
    } else {
        Ok(None)
    }
}

fn is_prime(
    candidate: &MaxPosInt,
    size: RsaKeySize,
    rng: &mut dyn RandomSource,
) -> Result<bool, Error> {
    let small_primes = PosInt::from_bytes(PRODUCT_OF_SMALL_PRIMES).unwrap();

    if !public(candidate.is_coprime(&small_primes)) {
        return Ok(false);
    }

    miller_rabin(candidate, size, rng)
}

fn miller_rabin(
    w: &MaxPosInt,
    size: RsaKeySize,
    rng: &mut dyn RandomSource,
) -> Result<bool, Error> {
    // See FIPS186-5 B.3.1:
    // Steps 1 to 3.
    let mr = MillerRabinParams::new(w)?;

    // 4. For i = 1 to iterations do
    for _ in 0..size.miller_rabin_rounds() {
        // Steps 4.1-4.6 inclusive.
        if !mr.check_base(&mr.random_base(rng)?) {
            return Ok(false);
        }
        // 4.7. Continue
    }

    // 5. Return PROBABLY PRIME.
    Ok(true)
}

struct MillerRabinParams<'a> {
    w: &'a MaxPosInt,
    w2: MaxPosInt,
    w3: MaxPosInt,
    a: usize,
    m: MaxPosInt,
    w_0: u64,
    w_montifier: MaxPosInt,
    mont_w1: MaxPosInt,
    mont_one: MaxPosInt,
}

impl<'a> MillerRabinParams<'a> {
    fn new(w: &'a MaxPosInt) -> Result<Self, Error> {
        // 1. Let a be the largest integer such that 2 ^ a divides w - 1.
        let w1 = w.sub(&PosInt::word(1));
        let a = w1.count_trailing_zeroes();

        // 2. m = (w - 1) / 2 ^ a.
        let len = w.as_words().len();
        let mut m = [0u64; MAX_PRIVATE_MODULUS_WORDS];
        shift_right_secret(w1.as_words(), a, &mut m[..len]);
        let m = PosInt::from_words(&m[..len])?;

        // Main arithmetic below is done in montgomery form mod w.
        let w_montifier = w.montifier();
        let w_0 = w.mont_neg_inverse();
        let mont_w1 = w1.to_montgomery(&w_montifier, w);
        let mont_one = w.fixed_one().mont_mul(&w_montifier, w, w_0);

        Ok(Self {
            w,
            w2: w.sub(&PosInt::word(2)),
            w3: w.sub(&PosInt::word(3)),
            a,
            m,
            w_0,
            w_montifier,
            mont_w1,
            mont_one,
        })
    }

    /// Steps 4.1 and 4.2: a base `b` with `1 < b < w - 1`.
    ///
    /// Rather than draw `wlen` bits until they fall in range, which would
    /// reveal how far `w` is below a power of two, this draws 64 bits more
    /// and reduces them, so each base is within `2 ^ -64` of uniform.
    fn random_base(&self, rng: &mut dyn RandomSource) -> Result<MaxPosInt, Error> {
        let bytes = self.w.as_words().len() * 8 + 8;
        let mut buffer = [0u8; MAX_PRIVATE_MODULUS_BYTES + 8];
        rng.fill(&mut buffer[..bytes])?;
        let wide = PosInt::<{ MAX_PRIVATE_MODULUS_WORDS * 2 }>::from_bytes(&buffer[..bytes])?;
        // w - 2 - (wide mod (w - 3)) is in [2, w - 2].
        Ok(self.w2.sub(&wide.reduce_even(&self.w3)))
    }

    /// Steps 4.3 to 4.6, returning false for COMPOSITE.
    ///
    /// As aws-lc's `bn_miller_rabin_iteration`, this squares until `wlen`
    /// rather than `a`, which is secret, and exits early only for a
    /// composite.
    fn check_base(&self, b: &MaxPosInt) -> bool {
        // 4.3. z = b ^ m mod w.
        let mut z = b.to_montgomery(&self.w_montifier, self.w).mont_exp(
            self.mont_one.clone(),
            &self.m,
            self.w,
            self.w_0,
        );

        // 4.4. If ((z = 1) or (z = w − 1)), then go to step 4.7.
        let mut possibly_prime = z.equals(&self.mont_one) | z.equals(&self.mont_w1);

        // 4.5. For j = 1 to a − 1 do.
        for j in 1..self.w.as_words().len() * 64 {
            if public((j == self.a) & !possibly_prime) {
                break;
            }

            // 4.5.1. z = z ^ 2 mod w.
            z = z.mont_sqr(self.w, self.w_0);

            // 4.5.2. If (z = w − 1), then go to step 4.7.
            possibly_prime |= z.equals(&self.mont_w1);

            // 4.5.3 If (z = 1), then go to step 4.6.
            if public(z.equals(&self.mont_one) & !possibly_prime) {
                break;
            }
        }

        // 4.6. Return COMPOSITE, unless step 4.7 was reached.
        public(possibly_prime)
    }
}

/// Product of the primes from 3..743, such that the product fits in 1024-bits
/// -- our smallest allowed prime.
///
/// If a candidate is coprime to this it does not have any small factors.
///
/// It is traditional to do this check instead by trial division, but we'd
/// prefer to use the formally verified `bignum_coprime`.  That comes with
/// the expense of not being able to early-reject candidates that are (for
/// example) a multiple of 3 (which is a significant proportion).
const PRODUCT_OF_SMALL_PRIMES: &[u8] = &[
    0x02, 0xc8, 0x5f, 0xf8, 0x70, 0xf2, 0x4b, 0xe8, 0x0f, 0x62, 0xb1, 0xba, 0x6c, 0x20, 0xbd, 0x72,
    0xb8, 0x37, 0xef, 0xdf, 0x12, 0x12, 0x06, 0xd8, 0x7d, 0xb5, 0x6b, 0x7d, 0x69, 0xfa, 0x4c, 0x02,
    0x1c, 0x10, 0x7c, 0x3c, 0xa2, 0x06, 0xfe, 0x8f, 0xa7, 0x08, 0x0e, 0xf5, 0x76, 0xef, 0xfc, 0x82,
    0xf9, 0xb1, 0x0f, 0x57, 0x50, 0x65, 0x6b, 0x77, 0x94, 0xb1, 0x6a, 0xfd, 0x70, 0x99, 0x6e, 0x91,
    0xae, 0xf6, 0xe0, 0xad, 0x15, 0xe9, 0x1b, 0x07, 0x1a, 0xc9, 0xb2, 0x4d, 0x98, 0xb2, 0x33, 0xad,
    0x86, 0xee, 0x05, 0x55, 0x18, 0xe5, 0x8e, 0x56, 0x63, 0x8e, 0xf1, 0x8b, 0xac, 0x5c, 0x74, 0xcb,
    0x35, 0xbb, 0xb6, 0xe5, 0xda, 0xe2, 0x78, 0x3d, 0xd1, 0xc0, 0xce, 0x7d, 0xec, 0x4f, 0xc7, 0x0e,
    0x51, 0x86, 0xd4, 0x11, 0xdf, 0x36, 0x36, 0x8f, 0x06, 0x1a, 0xa3, 0x60, 0x11, 0xf3, 0x01, 0x79,
];

type MaxPosInt = PosInt<MAX_PRIVATE_MODULUS_WORDS>;

/// Declassifies a decision this module reveals by branching on it.
fn public<T>(v: T) -> T {
    ct::into_public(v)
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use core::time::Duration;
    use std::time::Instant;

    use super::*;
    use crate::high::hash::Sha256;
    use crate::high::hmac_drbg::HmacDrbg;
    use crate::mid::rng::{ChainRandomSource, SliceRandomSource, SystemRandom};

    fn read_hex_from_file(data: &str) -> Vec<u8> {
        data.split_whitespace()
            .flat_map(|line| {
                (0..line.len())
                    .step_by(2)
                    .map(|i| u8::from_str_radix(&line[i..i + 2], 16).unwrap())
            })
            .collect()
    }

    fn read_hex_lines_from_file(data: &str) -> impl Iterator<Item = Vec<u8>> + '_ {
        data.lines()
            .inspect(|line| println!("Processing line: {line}"))
            .filter(|line| !line.starts_with("#"))
            .map(|line| {
                (0..line.len())
                    .step_by(2)
                    .map(|i| u8::from_str_radix(&line[i..i + 2], 16).unwrap())
                    .collect()
            })
    }

    /// `testdata/rsa.bench.2048.txt` is a transcript of candidate primes, with one
    /// candidate per line.  see:
    /// <https://github.com/C2SP/CCTV/tree/main/keygen>
    ///
    /// The results from this should be comparable with the results of:
    ///
    /// ```
    /// $ go test crypto/rsa -bench BenchmarkGenerateKey/2048
    /// goos: linux
    /// goarch: amd64
    /// pkg: crypto/rsa
    /// cpu: AMD Ryzen 9 7940HS w/ Radeon 780M Graphics
    /// BenchmarkGenerateKey/2048-16    10    111795391 ns/op
    ///
    /// $ cargo test --release test_rsa_bench -- --nocapture
    /// running 1 test
    /// Results: min=31038596ns, mean=31920351ns, max=35448808ns
    /// test mid::rsa_priv::generate::tests::test_rsa_bench ... ok
    ///
    /// test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 102 filtered out; finished in 1.02s
    /// ```
    #[test]
    fn test_rsa_bench() {
        let bytes = read_hex_from_file(include_str!("../../testdata/rsa.bench.2048.txt"));
        let mut results = vec![];

        // If running under Valgrind, which is slow, do fewer iterations.
        #[cfg(feature = "__ctgrind")]
        const NUM_ITERATIONS: usize = 1;

        #[cfg(not(feature = "__ctgrind"))]
        const NUM_ITERATIONS: usize = 32;

        for _ in 0..NUM_ITERATIONS {
            let mut candidate_source = SliceRandomSource(&bytes);
            let mut witness_source = SystemRandom;

            let start = Instant::now();
            generate_key(
                RsaKeySize::Rsa2048,
                &mut candidate_source,
                &mut witness_source,
            )
            .unwrap();
            results.push(start.elapsed());
        }
        println!(
            "Results: min={}ns, mean={}ns, max={}ns",
            results.iter().min().unwrap().as_nanos(),
            results.iter().sum::<Duration>().as_nanos() / results.len() as u128,
            results.iter().max().unwrap().as_nanos(),
        )
    }

    #[test]
    fn test_hosed_rng() {
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
    fn test_p_q_equal() {
        // get one prime from this test vector and duplicate it.
        let mut bytes = read_hex_from_file(include_str!(
            "../../testdata/rsa.phi-not-coprime-e.2048.txt"
        ));

        assert_eq!(bytes.len(), 256);
        bytes.drain(128..);

        for i in 0..128 {
            bytes.push(bytes[i]);
        }

        let mut candidate_source = SliceRandomSource(&bytes);
        assert_eq!(
            generate_key(
                RsaKeySize::Rsa2048,
                &mut candidate_source,
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
    fn test_p_q_close() {
        let mut p = read_hex_from_file(include_str!(
            "../../testdata/rsa.phi-not-coprime-e.2048.txt"
        ));
        p.truncate(128);

        // The next prime after p, far within 2 ^ 924 of it.
        let close = offset(&p, 814);
        assert_eq!(
            is_prime(
                &PosInt::from_bytes(&close).unwrap(),
                RsaKeySize::Rsa2048,
                &mut HmacDrbg::<Sha256>::new(b"", b"", b"")
            ),
            Ok(true)
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
        let p = PosInt::from_bytes(&p).unwrap();
        let far = PosInt::from_bytes(&far).unwrap();
        assert!(public(key.p.equals(&p) & key.q.equals(&far)));
    }

    #[test]
    fn test_phi_not_coprime_e() {
        let bytes = read_hex_from_file(include_str!(
            "../../testdata/rsa.phi-not-coprime-e.2048.txt"
        ));

        let mut fixed_source = SliceRandomSource(&bytes);
        let mut retry_source = SystemRandom;
        let mut candidate_source = ChainRandomSource::First(&mut fixed_source, &mut retry_source);
        let mut witness_source = SystemRandom;

        generate_key(
            RsaKeySize::Rsa2048,
            &mut candidate_source,
            &mut witness_source,
        )
        .unwrap();
    }

    #[test]
    fn test_valid_primes() {
        for line in read_hex_lines_from_file(include_str!("../../testdata/valid-primes.txt")) {
            let candidate = PosInt::from_bytes(&line).unwrap();
            assert_eq!(
                is_prime(
                    &candidate,
                    RsaKeySize::Rsa2048,
                    &mut HmacDrbg::<Sha256>::new(b"", b"", b"")
                ),
                Ok(true)
            );
        }
    }

    #[test]
    fn test_invalid_primes() {
        for line in read_hex_lines_from_file(include_str!("../../testdata/invalid-primes.txt")) {
            let candidate = PosInt::from_bytes(&line).unwrap();
            assert_eq!(
                is_prime(
                    &candidate,
                    RsaKeySize::Rsa2048,
                    &mut HmacDrbg::<Sha256>::new(b"", b"", b"")
                ),
                Ok(false)
            );
        }
    }
}
