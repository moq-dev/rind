// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

//! RSA private operations over HACL*'s `Bignum64`, the arithmetic
//! libcrux's RSA-PSS uses, composed by the Chinese remainder theorem.

use core::ops::Deref;

use libcrux_hacl_rs::bignum::base::{self, bn_mont_ctx_u64};
use libcrux_hacl_rs::bignum::bignum64;

use super::rsa_pub::{MAX_PUBLIC_MODULUS_BYTES, RsaPublicKey};
use crate::error::{Error, KeyFormatError};
use crate::low;
use crate::mid::rng::RandomSource;
use crate::mid::rsa_key_size::RsaKeySize;

#[path = "rsa_priv/generate.rs"]
mod generate;

/// `public` comes first so its (non-secret) bytes form a prefix.
#[repr(C)]
pub(crate) struct RsaPrivateKey {
    public: RsaPublicKey,

    p: SecretRsaPosIntModP,
    q: SecretRsaPosIntModP,
    d: SecretRsaPosIntD,
    dp: SecretRsaPosIntModP,
    dq: SecretRsaPosIntModP,
    iqmp: SecretRsaPosIntModP,
}

impl Drop for RsaPrivateKey {
    fn drop(&mut self) {
        // Not secret, but wiping it lets `tests/zeroing.rs` check every byte.
        low::zeroise_value(&mut self.public);
    }
}

impl RsaPrivateKey {
    pub(crate) fn new(
        p: RsaPosIntModP,
        q: RsaPosIntModP,
        d: RsaPosIntD,
        dp: RsaPosIntModP,
        dq: RsaPosIntModP,
        iqmp: RsaPosIntModP,
        n: RsaPosIntModN,
        e: u32,
    ) -> Result<Self, Error> {
        let p_len = p.len_bytes();
        if n.len_bits() < MIN_MODULUS_BITS {
            return Err(KeyFormatError::RsaModulus.into());
        }
        if p.is_even()
            || q.is_even()
            || !(MIN_PRIVATE_MODULUS_BYTES..=MAX_PRIVATE_MODULUS_BYTES).contains(&p_len)
        {
            return Err(KeyFormatError::RsaPrimes.into());
        }

        let public = RsaPublicKey::new(n, e)?;

        // The CRT works at the width of the wider prime, so every
        // component must fit it, and `n` twice it. One that does not cannot
        // agree with the primes.
        let width = p.as_words().len().max(q.as_words().len());
        let mismatched = |_| KeyFormatError::MismatchedRsaComponents;
        for x in [&dp, &dq, &iqmp] {
            x.words_at_width(width).map_err(mismatched)?;
        }
        public.n.words_at_width(width * 2).map_err(mismatched)?;

        let p: SecretRsaPosIntModP = p.into();
        let q: SecretRsaPosIntModP = q.into();
        let d: SecretRsaPosIntD = d.into();
        let dp: SecretRsaPosIntModP = dp.into();
        let dq: SecretRsaPosIntModP = dq.into();
        let iqmp: SecretRsaPosIntModP = iqmp.into();

        // As aws-lc's `RSA_check_key`, so a key that cannot sign is refused
        // here rather than by every signature's fault check. Each relation
        // is computed in full, and only the verdict is revealed.
        let p_mont = Mont::new_secret(p.words_at_width(width)?, p.as_words().len());
        let agree = Components {
            p: p.words_at_width(width)?,
            q: q.words_at_width(width)?,
            d: d.as_words(),
            dp: dp.words_at_width(width)?,
            dq: dq.words_at_width(width)?,
            iqmp: iqmp.words_at_width(width)?,
            n: public.n.words_at_width(width * 2)?,
            e: u64::from(e),
        }
        .agree(&p_mont);
        if !low::ct::into_public(agree == u64::MAX) {
            return Err(KeyFormatError::MismatchedRsaComponents.into());
        }

        Ok(Self {
            public,
            p,
            q,
            d,
            dp,
            dq,
            iqmp,
        })
    }

    pub(crate) fn generate(
        size: RsaKeySize,
        candidate_source: &mut dyn RandomSource,
        witness_source: &mut dyn RandomSource,
    ) -> Result<Self, Error> {
        generate::generate_key(size, candidate_source, witness_source)
    }

    /// Swaps `dp` and `dq`, as a fault in the CRT would corrupt them.
    #[cfg(test)]
    pub(crate) fn swap_crt_exponents(&mut self) {
        core::mem::swap(&mut self.dp, &mut self.dq);
    }

    pub(crate) fn public_key(&self) -> RsaPublicKey {
        self.public.clone()
    }

    pub(crate) fn modulus_len_bytes(&self) -> usize {
        self.public.modulus_len_bytes()
    }

    pub(crate) fn modulus_len_bits(&self) -> usize {
        self.public.modulus_len_bits()
    }

    pub(crate) fn encode_components<'a>(
        &self,
        buffer: &'a mut RsaComponentsBuffer,
    ) -> Result<RsaComponents<'a>, Error> {
        let (public_modulus, buffer) = buffer.0.split_at_mut(MAX_PUBLIC_MODULUS_BYTES + 1);
        let (public_exponent, buffer) = buffer.split_at_mut(4);
        let (p, buffer) = buffer.split_at_mut(MAX_PRIVATE_MODULUS_BYTES + 1);
        let (q, buffer) = buffer.split_at_mut(MAX_PRIVATE_MODULUS_BYTES + 1);
        let (d, buffer) = buffer.split_at_mut(MAX_PUBLIC_MODULUS_BYTES + 1);
        let (dp, buffer) = buffer.split_at_mut(MAX_PRIVATE_MODULUS_BYTES + 1);
        let (dq, buffer) = buffer.split_at_mut(MAX_PRIVATE_MODULUS_BYTES + 1);
        let (iqmp, _) = buffer.split_at_mut(MAX_PRIVATE_MODULUS_BYTES + 1);

        let public_modulus = self.public.n.to_bytes_asn1(public_modulus)?;
        public_exponent.copy_from_slice(&self.public.e.to_be_bytes());

        let p = self.p.to_bytes_asn1(p)?;
        let q = self.q.to_bytes_asn1(q)?;
        let d = self.d.to_bytes_asn1(d)?;
        let dp = self.dp.to_bytes_asn1(dp)?;
        let dq = self.dq.to_bytes_asn1(dq)?;
        let iqmp = self.iqmp.to_bytes_asn1(iqmp)?;

        // We are exporting this key; it is leaving the confines of this
        // library and becoming public data.
        low::ct::public_slice(p);
        low::ct::public_slice(q);
        low::ct::public_slice(d);
        low::ct::public_slice(dp);
        low::ct::public_slice(dq);
        low::ct::public_slice(iqmp);

        Ok(RsaComponents {
            public_modulus,
            public_exponent,
            p,
            q,
            d,
            dp,
            dq,
            iqmp,
        })
    }

    /// returns c ^ d mod n
    ///
    /// (albeit via CRT)
    pub(crate) fn private_op(&self, c: &RsaPosIntModN) -> Result<RsaPosIntModN, Error> {
        let n = self.public.n.as_words();
        let c_n = c.words_at_width(n.len())?;
        if bignum64::lt_mask(n.len() as u32, c_n, n) != u64::MAX {
            return Err(Error::WrongLength);
        }

        // Widths were checked in `new`.
        let w = self.p.as_words().len().max(self.q.as_words().len());
        let dp = self.dp.words_at_width(w)?;
        let dq = self.dq.words_at_width(w)?;
        let iqmp = self.iqmp.words_at_width(w)?;
        let c = c.words_at_width(w * 2)?;

        // Each prime's length in words is public.
        let p = Mont::new_secret(self.p.words_at_width(w)?, self.p.as_words().len());
        let q = Mont::new_secret(self.q.words_at_width(w)?, self.q.as_words().len());

        let mut scratch = CrtScratch::default();
        scratch.compute(
            w,
            Primes {
                p: &p,
                q: &q,
                dp,
                dq,
                iqmp,
            },
            c,
        );
        let m = RsaPosIntModN::from_words(&scratch.m[..n.len()]);
        drop(scratch);
        let m = low::ct::into_public(m?);

        // Check the result as a fault attack countermeasure: `new` checked
        // the key's components, so only a fault fails this.
        let agrees = self.public.public_op(m.clone()).is_ok_and(|c2| {
            c2.words_at_width(n.len())
                .is_ok_and(|c2| bignum64::eq_mask(n.len() as u32, c2, c_n) == u64::MAX)
        });
        match agrees {
            true => Ok(m),
            false => Err(Error::BadSignature),
        }
    }
}

/// A private key's integers, each as wide as the wider prime, `n` twice
/// that, and `d` as wide as it is.
struct Components<'a> {
    p: &'a [u64],
    q: &'a [u64],
    d: &'a [u64],
    dp: &'a [u64],
    dq: &'a [u64],
    iqmp: &'a [u64],
    n: &'a [u64],
    e: u64,
}

impl Components<'_> {
    /// All ones if `n = p * q`, `iqmp = q^-1 mod p`, and for each prime
    /// `dp = d mod (p - 1)` with `dp * e = 1 (mod p - 1)`, and zero if not.
    ///
    /// These accept the same keys as aws-lc's `d * e = 1 (mod p - 1)` and
    /// `dp = d mod (p - 1)`, with one reduction of `d` rather than two.
    /// `p_mont` is the context for `p`.
    fn agree(&self, p_mont: &Mont) -> u64 {
        let w = self.p.len();
        let len = w as u32;
        let mut one = [0u64; MAX_PRIVATE_MODULUS_WORDS];
        one[0] = 1;
        let one = &one[..w];
        let mut wide = [0u64; MAX_PRIVATE_MODULUS_WORDS * 2];
        let wide = &mut wide[..w * 2];
        let mut t = [0u64; MAX_PRIVATE_MODULUS_WORDS];
        let t = &mut t[..w];

        bignum64::mul(len, self.p, self.q, wide);
        let mut agree = bignum64::eq_mask(len * 2, wide, self.n);

        // `mod_precomp` needs `iqmp * q` below `p * 2^(64w)`, which the range
        // check guarantees for every key it accepts.
        agree &= bignum64::lt_mask(len, self.iqmp, self.p);
        bignum64::mul(len, self.iqmp, self.q, wide);
        bignum64::mod_precomp(p_mont, wide, t);
        agree &= bignum64::eq_mask(len, t, one);

        let mut e = [0u64; MAX_PRIVATE_MODULUS_WORDS];
        e[0] = self.e;
        let e = &e[..w];
        let mut m = [0u64; MAX_PRIVATE_MODULUS_WORDS];
        let m = &mut m[..w];
        for (prime, exponent) in [(self.p, self.dp), (self.q, self.dq)] {
            // Primes are odd, so subtracting one clears bit 0.
            m.copy_from_slice(prime);
            m[0] &= !1;
            reduce_even(self.d, m, t);
            agree &= bignum64::eq_mask(len, t, exponent);
            bignum64::mul(len, t, e, wide);
            reduce_even(wide, m, t);
            agree &= bignum64::eq_mask(len, t, one);
        }
        agree
    }
}

/// Writes `x mod m` to `r`, for an `m` above one that may be even.
///
/// `Bignum64` reduces only by an odd modulus, so this doubles and adds `x`'s
/// bits from the top, each step below `m`, in constant time.
fn reduce_even(x: &[u64], m: &[u64], r: &mut [u64]) {
    let len = m.len() as u32;
    let mut bit = [0u64; MAX_PRIVATE_MODULUS_WORDS];
    let bit = &mut bit[..m.len()];
    let mut doubled = [0u64; MAX_PRIVATE_MODULUS_WORDS];
    let doubled = &mut doubled[..m.len()];
    r.fill(0);
    for word in x.iter().rev() {
        for shift in (0..64).rev() {
            base::bn_add_mod_n_u64(len, m, r, r, doubled);
            bit[0] = (word >> shift) & 1;
            base::bn_add_mod_n_u64(len, m, doubled, bit, r);
        }
    }
}

/// The CRT inputs, each `w` words wide.
struct Primes<'a> {
    p: &'a Mont,
    q: &'a Mont,
    dp: &'a [u64],
    dq: &'a [u64],
    iqmp: &'a [u64],
}

/// The CRT's intermediate values, zeroed on drop.
struct CrtScratch {
    m_1: [u64; MAX_PRIVATE_MODULUS_WORDS],
    m_2: [u64; MAX_PRIVATE_MODULUS_WORDS],
    h: [u64; MAX_PRIVATE_MODULUS_WORDS],
    t: [u64; MAX_PRIVATE_MODULUS_WORDS],
    wide: [u64; MAX_PRIVATE_MODULUS_WORDS * 2],
    qh: [u64; MAX_PRIVATE_MODULUS_WORDS * 2],
    m: [u64; MAX_PRIVATE_MODULUS_WORDS * 2],
}

impl CrtScratch {
    /// Leaves `c ^ d mod n` in `m`.
    fn compute(&mut self, w: usize, k: Primes<'_>, c: &[u64]) {
        let len = w as u32;
        let bits = len * 64;
        let (m_1, m_2) = (&mut self.m_1[..w], &mut self.m_2[..w]);
        let (h, t) = (&mut self.h[..w], &mut self.t[..w]);
        let (wide, qh) = (&mut self.wide[..w * 2], &mut self.qh[..w * 2]);
        let m = &mut self.m[..w * 2];

        // i.   Let m_1 = c^dP mod p and m_2 = c^dQ mod q.
        // (do reductions of c first, so the mod exp can be done at
        // width of p or q rather than pq.)
        bignum64::mod_precomp(k.p, c, t);
        bignum64::mod_exp_consttime_precomp(k.p, t, bits, k.dp, m_1);
        bignum64::mod_precomp(k.q, c, t);
        bignum64::mod_exp_consttime_precomp(k.q, t, bits, k.dq, m_2);

        // ii. If u > 2, let m_i = c^(d_i) mod r_i, i = 3, ..., u.
        // (we don't support multiprime rsa)

        // iii. Let h = (m_1 - m_2) * qInv mod p.
        // (m_2 < q may exceed p, so reduce it first.)
        wide.fill(0);
        wide[..w].copy_from_slice(m_2);
        bignum64::mod_precomp(k.p, wide, t);
        bignum64::sub_mod(len, &k.p[0].n, m_1, t, h);
        bignum64::mul(len, h, k.iqmp, wide);
        bignum64::mod_precomp(k.p, wide, h);

        // iv.  Let m = m_2 + q * h.
        // (no carry: m < pq < 2^(128w))
        bignum64::mul(len, &k.q[0].n, h, qh);
        wide.fill(0);
        wide[..w].copy_from_slice(m_2);
        let _carry = bignum64::add(len * 2, wide, qh, m);
    }
}

impl Default for CrtScratch {
    fn default() -> Self {
        Self {
            m_1: [0; MAX_PRIVATE_MODULUS_WORDS],
            m_2: [0; MAX_PRIVATE_MODULUS_WORDS],
            h: [0; MAX_PRIVATE_MODULUS_WORDS],
            t: [0; MAX_PRIVATE_MODULUS_WORDS],
            wide: [0; MAX_PRIVATE_MODULUS_WORDS * 2],
            qh: [0; MAX_PRIVATE_MODULUS_WORDS * 2],
            m: [0; MAX_PRIVATE_MODULUS_WORDS * 2],
        }
    }
}

impl Drop for CrtScratch {
    fn drop(&mut self) {
        low::zeroise(&mut self.m_1);
        low::zeroise(&mut self.m_2);
        low::zeroise(&mut self.h);
        low::zeroise(&mut self.t);
        low::zeroise(&mut self.wide);
        low::zeroise(&mut self.qh);
        low::zeroise(&mut self.m);
    }
}

/// A HACL* Montgomery context, zeroed on drop.
struct Mont(Box<[bn_mont_ctx_u64]>);

impl Mont {
    /// A context for a public `n`, which must be odd and above one.
    fn new(n: &[u64]) -> Self {
        Self(bignum64::mont_ctx_init(n.len() as u32, n))
    }

    /// A context for a secret `n`, which must be odd with `used`
    /// significant words.
    ///
    /// `mont_ctx_init` reads `n`'s highest nonzero word to set how many
    /// times it loops, so this takes it from `used`, which is public.
    fn new_secret(n: &[u64], used: usize) -> Self {
        let len = n.len() as u32;
        let mut r2 = vec![0; n.len()].into_boxed_slice();
        base::bn_precomp_r2_mod_n_u64(len, 64 * (used as u32 - 1), n, &mut r2);
        Self(Box::new([bn_mont_ctx_u64 {
            len,
            n: n.into(),
            mu: base::mod_inv_uint64(n[0]),
            r2,
        }]))
    }
}

impl Deref for Mont {
    type Target = [bn_mont_ctx_u64];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Drop for Mont {
    fn drop(&mut self) {
        for k in self.0.iter_mut() {
            low::zeroise(&mut k.n);
            low::zeroise(&mut k.r2);
            low::zeroise_value(&mut k.mu);
        }
    }
}

pub(crate) struct RsaComponents<'a> {
    pub(crate) public_modulus: &'a [u8],
    pub(crate) public_exponent: &'a [u8],
    pub(crate) p: &'a [u8],
    pub(crate) q: &'a [u8],
    pub(crate) d: &'a [u8],
    pub(crate) dp: &'a [u8],
    pub(crate) dq: &'a [u8],
    pub(crate) iqmp: &'a [u8],
}

pub(crate) struct RsaComponentsBuffer([u8; Self::LEN]);

impl RsaComponentsBuffer {
    pub(crate) const LEN: usize =
        // public modulus and private exponent
        (MAX_PUBLIC_MODULUS_BYTES + 1) * 2 +
            // public exponent
            4 +
            // private moduli and crt components
            (MAX_PRIVATE_MODULUS_BYTES + 1) * 5;
}

impl Default for RsaComponentsBuffer {
    fn default() -> Self {
        Self([0u8; Self::LEN])
    }
}

const MAX_PRIVATE_MODULUS_BITS: usize = 4096;
const MAX_PRIVATE_MODULUS_WORDS: usize = MAX_PRIVATE_MODULUS_BITS / 64;
pub(crate) const MAX_PRIVATE_MODULUS_BYTES: usize = MAX_PRIVATE_MODULUS_BITS / 8;

const MIN_PRIVATE_MODULUS_BITS: usize = 1024;
const MIN_PRIVATE_MODULUS_BYTES: usize = MIN_PRIVATE_MODULUS_BITS / 8;

// Signing keeps the 2048-bit floor that only legacy verification goes below.
const MIN_MODULUS_BITS: usize = 2048;

type SecretRsaPosIntModP = low::SecretPosInt<MAX_PRIVATE_MODULUS_WORDS>;
type SecretRsaPosIntD = low::SecretPosInt<{ MAX_PRIVATE_MODULUS_WORDS * 2 }>;
type RsaPosIntModP = low::PosInt<MAX_PRIVATE_MODULUS_WORDS>;
type RsaPosIntD = low::PosInt<{ MAX_PRIVATE_MODULUS_WORDS * 2 }>;
type RsaPosIntModN = low::PosInt<{ MAX_PRIVATE_MODULUS_WORDS * 2 }>;
