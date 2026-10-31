// Written for Graviola by Joe Birr-Pixton, 2024.
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

use super::rsa_pub::{MAX_PUBLIC_MODULUS_BYTES, RsaPublicKey};
use crate::error::{Error, KeyFormatError};
use crate::low;
use crate::mid::rng::RandomSource;
use crate::mid::rsa_key_size::RsaKeySize;

mod generate;

pub(crate) struct RsaPrivateKey {
    public: RsaPublicKey,

    p: SecretRsaPosIntModP,
    q: SecretRsaPosIntModP,
    d: SecretRsaPosIntD,
    dp: SecretRsaPosIntModP,
    dq: SecretRsaPosIntModP,
    iqmp: SecretRsaPosIntModP,

    iqmp_mont: SecretRsaPosIntModP,
    p_montifier: SecretRsaPosIntModP,
    q_montifier: SecretRsaPosIntModP,
    p0: u64,
    q0: u64,
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
        let (p_len, q_len) = (p.len_bytes(), q.len_bytes());
        if n.len_bits() < MIN_MODULUS_BITS {
            return Err(KeyFormatError::RsaModulus.into());
        }
        if p.is_even()
            || q.is_even()
            || q.len_bits() < 2
            || !(MIN_PRIVATE_MODULUS_BYTES..=MAX_PRIVATE_MODULUS_BYTES).contains(&p_len)
        {
            return Err(KeyFormatError::RsaPrimes.into());
        }

        let public = RsaPublicKey::new(n, e)?;

        let mut p: SecretRsaPosIntModP = p.into();
        let mut q: SecretRsaPosIntModP = q.into();
        let d: SecretRsaPosIntD = d.into();
        let dp: SecretRsaPosIntModP = dp.into();
        let dq: SecretRsaPosIntModP = dq.into();
        let iqmp: SecretRsaPosIntModP = iqmp.into();

        // Each prime is still at its own width, as `reduce_even` needs.
        let e = low::PosInt::word(e.into());
        let exponents_agree = exponents_agree(&p, &d, &dp, &e) & exponents_agree(&q, &d, &dq, &e);

        // The CRT reduces `c` mod each prime by Montgomery reduction, which
        // needs `c` below 2^(64w) times the prime for a w-word prime. Working
        // at the wider prime's width meets that for unbalanced primes too.
        if p_len < q_len {
            p.expand(&q);
        } else {
            q.expand(&p);
        }

        let p_montifier: SecretRsaPosIntModP = p.montifier().into();
        let q_montifier = q.montifier().into();
        let iqmp_mont: SecretRsaPosIntModP = iqmp.to_montgomery(&p_montifier, &p).into();
        let p0 = p.mont_neg_inverse();
        let q0 = q.mont_neg_inverse();

        // As aws-lc's `RSA_check_key`, so a key that cannot sign is refused
        // here rather than by every signature's fault check. Each relation
        // is computed in full, and only the verdict is revealed.
        let pq: RsaPosIntModN = low::PosInt::mul(&p, &q);
        let consistent = exponents_agree
            & pq.equals(&public.n)
            & iqmp.less_than(&p)
            // Out of Montgomery form: iqmp * R * q * R^-1 = iqmp * q (mod p).
            & iqmp_mont.mont_mul(&q, &p, p0).equals(&p.fixed_one());
        if !low::ct::into_public(consistent) {
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
            iqmp_mont,
            p_montifier,
            q_montifier,
            p0,
            q0,
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
        if !c.less_than(&self.public.n) {
            return Err(Error::WrongLength);
        }

        // A note about blinding:
        //
        // In this library, we only perform RSA signatures, where `c` is
        // public information, there is little use for base blinding.
        //
        // Exponent and modulus blinding are _also_ relatively unnecessary,
        // since our `PosInt::mod_exp` is side-channel silent.
        // See the commentary there for why I think that is the case.

        // i.   Let m_1 = c^dP mod p and m_2 = c^dQ mod q.
        // (do reductions of c first, so the mod exp can be done at
        // width of p or q rather than pq.)
        let cmp = c.reduce(&self.p, &self.p_montifier);
        let m_1 = cmp.mod_exp(&self.dp, &self.p, &self.p_montifier, self.p0);
        let cmq = c.reduce(&self.q, &self.q_montifier);
        let m_2 = cmq.mod_exp(&self.dq, &self.q, &self.q_montifier, self.q0);

        // ii. If u > 2, let m_i = c^(d_i) mod r_i, i = 3, ..., u.
        // (we don't support multiprime rsa)

        // iii. Let h = (m_1 - m_2) * qInv mod p.
        let h = m_1
            .sub_mod(&m_2, &self.p)
            .mont_mul(&self.iqmp_mont, &self.p, self.p0);

        // iv.  Let m = m_2 + q * h.
        let m = m_2.widen().add(&low::PosInt::mul(&self.q, &h));
        let m = low::ct::into_public(m);

        // Check the result as a fault attack countermeasure: `new` checked
        // the key's components, so only a fault fails this.
        match self.public.public_op(m.clone()) {
            Ok(c2) if c2.equals(c) => Ok(m),
            _ => Err(Error::BadSignature),
        }
    }
}

impl Drop for RsaPrivateKey {
    fn drop(&mut self) {
        low::zeroise_value(&mut self.p0);
        low::zeroise_value(&mut self.q0);
        // Not secret, but wiping it lets `tests/zeroing.rs` check every byte.
        low::zeroise_value(&mut self.public);
    }
}

/// Whether `dp = d mod (p - 1)` and `dp * e = 1 (mod p - 1)`.
///
/// These accept the same keys as aws-lc's `d * e = 1 (mod p - 1)` and
/// `dp = d mod (p - 1)`, with one reduction of `d` rather than two. `p` must
/// be above one and at its own width, as `reduce_even` needs the top word of
/// `p - 1` nonzero.
fn exponents_agree(
    p: &RsaPosIntModP,
    d: &RsaPosIntD,
    dp: &RsaPosIntModP,
    e: &RsaPosIntModP,
) -> bool {
    let p_1 = p.sub(&low::PosInt::one());
    let d_p = d.reduce_even(&p_1);
    let d_p_e: RsaPosIntD = low::PosInt::mul(&d_p, e);
    d_p.equals(dp) & d_p_e.reduce_even(&p_1).equals(&p_1.fixed_one())
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
        Self([0u8; 4619])
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
