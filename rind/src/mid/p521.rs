// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

use core::fmt;
use core::ops::Range;

use super::util;
use crate::error::{Error, KeyFormatError};
use crate::low;
use crate::mid::rng::{RandomSource, SystemRandom};

mod precomp;

/// A P-521 public key.
#[derive(Clone, Debug)]
pub(crate) struct PublicKey {
    point: AffinePoint,
}

impl PublicKey {
    pub(crate) const BYTES: usize = 1 + FieldElement::BYTES + FieldElement::BYTES;

    /// Create a P-521 [`PublicKey`] from a byte slice.
    ///
    /// This must be exactly 133 bytes in length, using the X9.62
    /// uncompressed encoding.  An error is returned if a coordinate
    /// is not below the field prime, or the point is not on the curve.
    pub(crate) fn from_x962_uncompressed(bytes: &[u8]) -> Result<Self, Error> {
        let _entry = low::Entry::new_public();
        let point = AffinePoint::from_x962_uncompressed(bytes)?;
        Ok(Self { point })
    }
}

/// A P-521 public key for ECDSA verification.
///
/// On aarch64 it keeps the point's multiples, so verifying again with the
/// same key skips computing them.  Elsewhere s2n-bignum's
/// `p521_jscalarmul`, verified, measured as fast as that window, so it
/// takes the point alone.
#[derive(Clone, Debug)]
pub(crate) struct VerifyingKey {
    #[cfg(target_arch = "aarch64")]
    precomp_w5: JacobianPointTableW5,
    #[cfg(not(target_arch = "aarch64"))]
    point: AffinePoint,
}

impl VerifyingKey {
    /// Create a [`VerifyingKey`] as [`PublicKey::from_x962_uncompressed`] does.
    pub(crate) fn from_x962_uncompressed(bytes: &[u8]) -> Result<Self, Error> {
        let PublicKey { point } = PublicKey::from_x962_uncompressed(bytes)?;
        Ok(Self {
            #[cfg(target_arch = "aarch64")]
            precomp_w5: point.public_precomp_w5(),
            #[cfg(not(target_arch = "aarch64"))]
            point,
        })
    }

    pub(crate) fn raw_ecdsa_verify(&self, r: &Scalar, s: &Scalar, e: &Scalar) -> Result<(), Error> {
        // 4. Compute: u1 = e s^-1 mod n and u2 = r s^−1 mod n
        let s_inv = s.inv().as_mont();
        let u1 = s_inv.mont_mul(&e.as_mont()).demont();
        let u2 = s_inv.mont_mul(&r.as_mont()).demont();

        // 5. Compute: R = (xR, yR) = u1 G + u2 QU
        //  If R = O, output "invalid" and stop.
        let lhs = JacobianPoint::public_base_multiply(&u1);
        #[cfg(target_arch = "aarch64")]
        let rhs = JacobianPoint::public_multiply_w5(&u2, &self.precomp_w5);
        #[cfg(not(target_arch = "aarch64"))]
        let rhs = JacobianPoint::multiply(&u2, &self.point);
        let point = JacobianPoint::public_add(&lhs, &rhs);

        if point.public_is_infinity() {
            return Err(Error::BadSignature);
        }

        // 6. Convert the field element xR to an integer xR using the conversion routine specified in Section 2.3.9.
        // 7. Set v = xR mod n.
        let v = point.x_scalar();

        // 8. Compare v and r — if v = r, output "valid", and if v != r, output "invalid".
        match v.public_eq(r) {
            true => Ok(()),
            false => Err(Error::BadSignature),
        }
    }
}

/// A P-521 ephemeral private key.
///
/// `agreement::EphemeralPrivateKey` uses one for a single Diffie-Hellman
/// operation.
pub(crate) struct PrivateKey {
    scalar: Scalar,
}

impl PrivateKey {
    /// Generate a new random private key using the system RNG.
    pub(crate) fn new_random() -> Result<Self, Error> {
        let _entry = low::Entry::new_secret();
        Self::generate(&mut SystemRandom)
    }

    /// Derive the corresponding public key, and return it in
    /// X9.62 uncompressed encoding.
    pub(crate) fn public_key_uncompressed(&self) -> [u8; PublicKey::BYTES] {
        let _entry = low::Entry::new_secret();
        self.public_point().as_bytes_uncompressed()
    }

    /// Do the Diffie-Hellman operation.
    ///
    /// `peer` is the peer's public key (and this type means it was
    /// already checked to be on the curve.)
    ///
    /// Returns a [`SharedSecret`].  May return an error in fault conditions.
    pub(crate) fn diffie_hellman(&self, peer: &PublicKey) -> Result<SharedSecret, Error> {
        let _entry = low::Entry::new_secret();
        let mut shared_point = JacobianPoint::multiply(&self.scalar, &peer.point);
        let result = shared_point.as_affine();
        // aws-lc wipes the product point, but not the coordinates derived from it.
        low::zeroise(&mut shared_point.xyz);
        match low::ct::into_public(result.on_curve()) {
            true => Ok(SharedSecret(result.x().as_bytes())),
            false => Err(KeyFormatError::NotOnCurve.into()),
        }
    }

    fn public_point(&self) -> AffinePoint {
        let point = JacobianPoint::base_multiply(&self.scalar).as_affine();
        let point = low::ct::into_public(point);
        match point.on_curve() {
            true => point,
            false => panic!("internal fault"),
        }
    }

    /// Draws a scalar as RFC6979's `bits2int` does: the leftmost 521 bits
    /// of 66 random bytes, retried until it is in range.
    ///
    /// Through `HmacDrbg`, this is RFC6979's nonce generation; from the
    /// system RNG, it is a uniform key.
    fn generate(rng: &mut dyn RandomSource) -> Result<Self, Error> {
        for _ in 0..64 {
            let mut r = [0u8; Scalar::BYTES];
            rng.fill(&mut r)?;
            low::ct::secret_slice(&r);
            let words = util::big_endian_slice_any_size_to_u64x9(&r).unwrap();
            let words = core::array::from_fn(|i| {
                let above = words
                    .get(i + 1)
                    .map_or(0, |w| w << (64 - Scalar::EXCESS_BITS));
                (words[i] >> Scalar::EXCESS_BITS) | above
            });
            if let Ok(scalar) = Scalar(words).into_range_check() {
                return Ok(Self {
                    scalar: low::ct::into_secret(scalar),
                });
            }
        }

        Err(Error::RngFailed)
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        Scalar::from_bytes_checked(bytes).map(|scalar| Self {
            scalar: low::ct::into_secret(scalar),
        })
    }
}

impl fmt::Debug for PrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateKey").finish_non_exhaustive()
    }
}

/// A P-521 static private key.
///
/// This backs ECDSA, so it can be serialized and deserialized. Its
/// Diffie-Hellman operation is only for tests with known scalars.
pub(crate) struct StaticPrivateKey(PrivateKey);

impl StaticPrivateKey {
    /// Generate a new random private key using the system RNG.
    #[cfg(test)]
    pub(crate) fn new_random() -> Result<Self, Error> {
        let _entry = low::Entry::new_secret();
        Self::generate(&mut SystemRandom)
    }

    /// Decode a private key from `bytes`.
    ///
    /// `bytes` may be larger or smaller than the size of `n`: excess bytes
    /// must be zero.  If given a variable-sized input, this is deemed a
    /// non-secret property.  Prefer to use fixed-sized inputs.
    ///
    /// An error is returned if the magnitude of the value is larger than
    /// `n` (ie, the input is never reduced mod n),  or the value is zero.
    pub(crate) fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let _entry = low::Entry::new_secret();
        PrivateKey::from_bytes(bytes).map(Self)
    }

    /// Return a fixed-length encoding of this private key's value, still secret.
    pub(crate) fn secret_bytes(&self) -> [u8; Scalar::BYTES] {
        self.0.scalar.as_bytes()
    }

    /// Derive the corresponding public key, and return it in
    /// X9.62 uncompressed encoding.
    pub(crate) fn public_key_uncompressed(&self) -> [u8; PublicKey::BYTES] {
        let _entry = low::Entry::new_secret();
        self.0.public_point().as_bytes_uncompressed()
    }

    /// Do the Diffie-Hellman operation.
    ///
    /// `peer` is the peer's public key (and this type means it was
    /// already checked to be on the curve.)
    ///
    /// Returns a [`SharedSecret`].  May return an error in fault conditions.
    #[cfg(test)]
    pub(crate) fn diffie_hellman(&self, peer: &PublicKey) -> Result<SharedSecret, Error> {
        let _entry = low::Entry::new_secret();
        self.0.diffie_hellman(peer)
    }

    pub(crate) fn public_key_x_scalar(&self) -> Scalar {
        let _entry = low::Entry::new_secret();
        self.0.public_point().x_scalar()
    }

    pub(crate) fn generate(rng: &mut dyn RandomSource) -> Result<Self, Error> {
        PrivateKey::generate(rng).map(Self)
    }

    pub(crate) fn raw_ecdsa_sign(&self, k: &Self, e: &Scalar, r: &Scalar) -> Scalar {
        // this is (e + r * d) / k
        let lhs_mont = self
            .0
            .scalar
            .as_mont()
            .mont_mul(&r.as_mont())
            .demont()
            .add(e)
            .as_mont();
        low::ct::into_public(k.0.scalar.inv().mont_mul(&lhs_mont))
    }
}

/// A shared secret output from a P-521 Diffie-Hellman operation.
pub(crate) struct SharedSecret(pub(crate) [u8; FieldElement::BYTES]);

impl Drop for SharedSecret {
    fn drop(&mut self) {
        low::zeroise(&mut self.0);
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct AffinePoint {
    xy: [u64; 18],
}

impl AffinePoint {
    const X: Range<usize> = 0..9;
    const Y: Range<usize> = 9..18;

    fn from_x962_uncompressed(bytes: &[u8]) -> Result<Self, Error> {
        match bytes.first() {
            Some(0x04) => (),
            Some(_) => return Err(KeyFormatError::Compressed.into()),
            None => return Err(KeyFormatError::WrongLength.into()),
        }

        if bytes.len() != PublicKey::BYTES {
            return Err(KeyFormatError::WrongLength.into());
        }

        let (_, xy) = bytes.split_at(1);
        let (x, y) = xy.split_at(FieldElement::BYTES);

        let x = util::big_endian_slice_any_size_to_u64x9(x).unwrap();
        let y = util::big_endian_slice_any_size_to_u64x9(y).unwrap();

        // A coordinate at or above p would be reduced, giving the point a
        // second encoding.  Public, so this need not be constant time.
        let below_p = |v: &[u64; 9]| v.iter().rev().lt(CURVE_PRIME.iter().rev());
        if !below_p(&x) || !below_p(&y) {
            return Err(KeyFormatError::NotOnCurve.into());
        }

        let point = Self::from_xy(FieldElement(x), FieldElement(y));

        if !point.on_curve() {
            return Err(KeyFormatError::NotOnCurve.into());
        }

        Ok(point)
    }

    fn x_scalar(&self) -> Scalar {
        Scalar(self.x().0).reduce_mod_n()
    }

    fn from_xy(x: FieldElement, y: FieldElement) -> Self {
        let mut r = Self::default();
        r.xy[Self::X].copy_from_slice(&x.0[..]);
        r.xy[Self::Y].copy_from_slice(&y.0[..]);
        r
    }

    fn x(&self) -> FieldElement {
        FieldElement(self.xy[Self::X].try_into().unwrap())
    }

    fn y(&self) -> FieldElement {
        FieldElement(self.xy[Self::Y].try_into().unwrap())
    }

    fn on_curve(&self) -> bool {
        // Compute the curve equation:
        //
        // y ^ 2 === x ^ 3 + ax + b
        //
        // all in GF(p)
        //

        let x = self.x();
        let rhs = x.sqr(); // x ^ 2
        let rhs = rhs.add(&CURVE_A); // x ^ 2 + a
        let rhs = rhs.mul(&x); // (x ^ 2 + a) * x   equiv  x ^ 3 + ax
        let rhs = rhs.add(&CURVE_B);

        let lhs = self.y().sqr();

        // Constant time, since `diffie_hellman` checks a secret point.
        low::bignum_eq(&lhs.0, &rhs.0)
    }

    fn as_bytes_uncompressed(&self) -> [u8; PublicKey::BYTES] {
        let mut r = [0u8; PublicKey::BYTES];

        let (indicator, xy) = r.split_at_mut(1);
        let (x, y) = xy.split_at_mut(FieldElement::BYTES);
        indicator[0] = 0x04;
        x.copy_from_slice(&self.x().as_bytes());
        y.copy_from_slice(&self.y().as_bytes());
        r
    }

    #[cfg(test)]
    fn slow_multiply(&self, scalar: &Scalar) -> Self {
        let mut result = JacobianPoint::infinity();
        let mut j = JacobianPoint::from_affine(self);

        for bit in scalar.bits() {
            if bit == 1 {
                result = JacobianPoint::public_add(&result, &j);
            }
            j = j.double();
        }

        result.as_affine()
    }

    /// Returns table[i - 1] if index > 0, or else the affine point at infinity
    fn lookup_comb(table: &[u64; 288], index: u8) -> Self {
        let mut r = Self::default();
        low::bignum_aff_point_select_p521(&mut r.xy, table, index);
        r
    }

    /// Returns table[i - 1] for a public index > 0
    fn public_lookup_comb(table: &[u64; 288], index: u8) -> Self {
        let offs = (index - 1) as usize * 18;
        let mut r = Self::default();
        r.xy.copy_from_slice(&table[offs..offs + 18]);
        r
    }

    fn negate_y(&mut self) {
        let neg_y = self.y().negate();
        self.xy[Self::Y].copy_from_slice(&neg_y.0);
    }

    fn maybe_negate_y(&mut self, sign: u8) {
        let y = self.y();
        let neg_y = y.negate();
        let result = FieldElement::select(&y, &neg_y, sign);
        self.xy[Self::Y].copy_from_slice(&result.0);
    }

    #[cfg(any(target_arch = "aarch64", test))]
    fn public_precomp_w5(&self) -> JacobianPointTableW5 {
        let mut r = [JacobianPoint::infinity(); 16];

        // indices into r are intuitively 1-based; index i contains i * G,
        // and 0 * G is not useful to store.
        macro_rules! index {
            ($i:literal) => {
                $i - 1
            };
        }

        // Each sum adds distinct multiples below n, none at infinity, as
        // `p521_jadd` requires.
        r[index!(1)] = JacobianPoint::from_affine(self);
        r[index!(2)] = r[index!(1)].double();
        r[index!(3)] = r[index!(1)].add(&r[index!(2)]);
        r[index!(4)] = r[index!(2)].double();
        r[index!(5)] = r[index!(1)].add(&r[index!(4)]);
        r[index!(6)] = r[index!(3)].double();
        r[index!(7)] = r[index!(1)].add(&r[index!(6)]);
        r[index!(8)] = r[index!(4)].double();
        r[index!(9)] = r[index!(1)].add(&r[index!(8)]);
        r[index!(10)] = r[index!(5)].double();
        r[index!(11)] = r[index!(1)].add(&r[index!(10)]);
        r[index!(12)] = r[index!(6)].double();
        r[index!(13)] = r[index!(1)].add(&r[index!(12)]);
        r[index!(14)] = r[index!(7)].double();
        r[index!(15)] = r[index!(1)].add(&r[index!(14)]);
        r[index!(16)] = r[index!(8)].double();

        let mut t = [0; 432];

        let (chunks, _) = t.as_chunks_mut::<27>();
        for (out, rr) in chunks.iter_mut().zip(r) {
            out.copy_from_slice(&rr.xyz);
        }

        t
    }
}

/// A point in Jacobian coordinates, at infinity when z is zero.
///
/// s2n-bignum's P-521 point routines require a nonzero z, and the two
/// points of an addition to differ and not be opposites, so the callers
/// here keep to those.
#[derive(Clone, Copy, Debug)]
struct JacobianPoint {
    xyz: [u64; 27],
}

impl JacobianPoint {
    const X: Range<usize> = 0..9;
    const Y: Range<usize> = 9..18;
    const XY: Range<usize> = 0..18;
    const Z: Range<usize> = 18..27;

    fn infinity() -> Self {
        Self { xyz: [0; 27] }
    }

    fn public_is_infinity(&self) -> bool {
        self.z().public_eq(&FieldElement::default())
    }

    /// 1 if this point is at infinity, else 0, in constant time.
    fn is_infinity(&self) -> u8 {
        low::bignum_eq(&self.z().0, &[0; 9]) as u8
    }

    fn x(&self) -> FieldElement {
        FieldElement(self.xyz[Self::X].try_into().unwrap())
    }

    fn y(&self) -> FieldElement {
        FieldElement(self.xyz[Self::Y].try_into().unwrap())
    }

    fn z(&self) -> FieldElement {
        FieldElement(self.xyz[Self::Z].try_into().unwrap())
    }

    fn base_multiply(scalar: &Scalar) -> Self {
        Self::multiply_comb::<true>(scalar)
    }

    fn public_base_multiply(scalar: &Scalar) -> Self {
        Self::multiply_comb::<false>(scalar)
    }

    /// `scalar * G`, for a `scalar` below n, by the comb layout of aws-lc's
    /// `ec_nistp_scalar_mul_base`.
    ///
    /// Window `w` of the 105 Booth-recoded 5-bit windows is `4j + t` for
    /// one tooth `t` in 0..4, and table `j` holds its multiples of
    /// `2^(20j) G`.  So each tooth's windows are added straight from the
    /// tables, and the 5 doublings between teeth supply the `2^(5t)`: 15
    /// doublings in all, rather than 520.
    ///
    /// No addition doubles or cancels, which `p521_jmixadd` cannot.  Scaled
    /// by `2^(-5t)`, the accumulator and the table point are sums of signed
    /// digits of distinct windows, so their sum and difference are nonzero
    /// integers unless one is zero, which is handled apart as infinity.
    /// Until window 104, which is added last, the accumulator is below
    /// `16/31 * 2^520` and the table point below `2^505`, so neither sum
    /// nor difference reaches n.  Window 104's digit `d` is at most 2: an
    /// equal accumulator would be `d * 2^520 - n`, out of its range for
    /// `d = 1` and making `scalar` `2^522 - n` for `d = 2`, and an opposite
    /// one would make `scalar` a multiple of n.
    fn multiply_comb<const SECRET: bool>(scalar: &Scalar) -> Self {
        let mut windows = [(0u8, 0u8); 105];
        for ((digit, sign, _), window) in scalar
            .reversed_booth_recoded_w5()
            .zip(windows.iter_mut().rev())
        {
            *window = (digit, sign);
        }

        let mut result = Self::infinity();
        for tooth in (0..4).rev() {
            if tooth != 3 {
                if SECRET {
                    // `p521_jdouble` requires a nonzero z, so infinity is kept.
                    let mut doubled = result;
                    doubled.double_inplace_n(5);
                    result = Self::select(&doubled, &result, result.is_infinity());
                } else if !result.public_is_infinity() {
                    result.double_inplace_n(5);
                }
            }

            for (table, &(digit, sign)) in precomp::CURVE_GENERATOR_PRECOMP_COMB
                .iter()
                .zip(windows.iter().skip(tooth).step_by(4))
            {
                if SECRET {
                    let mut tmp = AffinePoint::lookup_comb(table, digit);
                    tmp.maybe_negate_y(sign);
                    result.add_inplace_affine(&tmp, digit);
                } else if digit > 0 {
                    let mut tmp = AffinePoint::public_lookup_comb(table, digit);
                    if sign > 0 {
                        tmp.negate_y();
                    }
                    result = match result.public_is_infinity() {
                        true => Self::from_affine(&tmp),
                        false => result.add_affine(&tmp),
                    };
                }
            }
        }

        result
    }

    /// `scalar * point`, by s2n-bignum's `p521_jscalarmul`.
    fn multiply(scalar: &Scalar, point: &AffinePoint) -> Self {
        let mut r = Self::infinity();
        low::p521_jscalarmul(&mut r.xyz, &scalar.0, &Self::from_affine(point).xyz);
        r
    }

    /// `scalar * P`, for a public `scalar` below n, from `P`'s multiples in
    /// `precomp`, by Booth-recoded 5-bit windows.
    ///
    /// Before each addition, the accumulator is `32m P` for the value `m`
    /// of the windows above, and the table point is `d P` for a digit `d`
    /// of at most 16.  `32m + d` is the value of the windows so far, below
    /// n, so the two are never opposites; they are equal only if `32m - d`
    /// is n, which needs `32m + d` within 32 of n, so only the last window,
    /// for a `scalar` from n - 32 to n - 2, can double.
    #[cfg(any(target_arch = "aarch64", test))]
    fn public_multiply_w5(scalar: &Scalar, precomp: &JacobianPointTableW5) -> Self {
        let mut terms = scalar.reversed_booth_recoded_w5();

        let (digit, _, _) = terms.next().unwrap();
        let mut result = Self::public_lookup_w5(precomp, digit, 0);

        for (digit, sign, last) in terms {
            if !result.public_is_infinity() {
                result.double_inplace_n(5);
            }
            if digit == 0 {
                continue;
            }

            let term = Self::public_lookup_w5(precomp, digit, sign);
            result = match (result.public_is_infinity(), last) {
                (true, _) => term,
                (false, false) => result.add(&term),
                (false, true) => Self::public_add(&result, &term),
            };
        }

        result
    }

    /// `a + b`, for any points, including at infinity, equal, or opposite.
    fn public_add(a: &Self, b: &Self) -> Self {
        if a.public_is_infinity() {
            return *b;
        }
        if b.public_is_infinity() {
            return *a;
        }

        // Both points scaled to the product of their z's.
        let (az2, bz2) = (a.z().sqr(), b.z().sqr());
        let same_x = a.x().mul(&bz2).public_eq(&b.x().mul(&az2));
        if !same_x {
            return a.add(b);
        }
        let ay = a.y().mul(&bz2.mul(&b.z()));
        let by = b.y().mul(&az2.mul(&a.z()));
        match ay.public_eq(&by) {
            true => a.double(),
            false => Self::infinity(),
        }
    }

    fn from_affine(p: &AffinePoint) -> Self {
        let mut xyz = [0; 27];
        xyz[Self::XY].copy_from_slice(&p.xy);
        xyz[Self::Z].copy_from_slice(&CURVE_ONE.0);
        Self { xyz }
    }

    fn as_affine(&self) -> AffinePoint {
        // recover (x, y) from (x / z ^ 2, x / z ^ 3, z)
        let z_inv = self.z().inv();
        let z2_inv = z_inv.sqr();
        let z3_inv = z2_inv.mul(&z_inv);

        let x = self.x().mul(&z2_inv);
        let y = self.y().mul(&z3_inv);

        AffinePoint::from_xy(x, y)
    }

    fn x_scalar(&self) -> Scalar {
        // this is a faster version of `as_affine().x_scalar()`
        let z2_inv = self.z().sqr().inv();
        Scalar(self.x().mul(&z2_inv).0).reduce_mod_n()
    }

    #[must_use]
    fn double(&self) -> Self {
        let mut tmp = Self::infinity();
        low::p521_jdouble(&mut tmp.xyz, &self.xyz);
        tmp
    }

    fn double_inplace_n(&mut self, n: usize) {
        for _ in 0..n {
            let tmp = *self;
            low::p521_jdouble(&mut self.xyz, &tmp.xyz);
        }
    }

    /// Adds `p`, a table entry for `digit`, which is zero when `digit` is zero.
    ///
    /// `p521_jmixadd` requires a nonzero z, so the sum is `p` itself when
    /// this point is at infinity, and this point when `digit` is zero.
    fn add_inplace_affine(&mut self, p: &AffinePoint, digit: u8) {
        let sum = self.add_affine(p);
        let sum = Self::select(&sum, &Self::from_affine(p), self.is_infinity());
        *self = Self::select(self, &sum, digit);
    }

    #[must_use]
    fn add_affine(&self, p: &AffinePoint) -> Self {
        let mut r = Self::infinity();
        low::p521_jmixadd(&mut r.xyz, &self.xyz, &p.xy);
        r
    }

    #[must_use]
    fn add(&self, p: &Self) -> Self {
        let mut r = Self::infinity();
        low::p521_jadd(&mut r.xyz, &self.xyz, &p.xyz);
        r
    }

    /// Return p0 if select == 0, p1 otherwise
    #[must_use]
    fn select(p0: &Self, p1: &Self, select: u8) -> Self {
        let mut r = Self::infinity();
        let select = select as u64;
        low::bignum_mux(select, &mut r.xyz[..], &p1.xyz[..], &p0.xyz[..]);
        r
    }

    /// Returns `table[index - 1]`, negated if `sign` is set, or infinity
    /// for a zero `index`.
    #[cfg(any(target_arch = "aarch64", test))]
    fn public_lookup_w5(table: &JacobianPointTableW5, index: u8, sign: u8) -> Self {
        let mut r = Self::infinity();
        if index > 0 {
            let offs = (index - 1) as usize * 27;
            r.xyz.copy_from_slice(&table[offs..offs + 27]);
            if sign > 0 {
                let neg_y = r.y().negate();
                r.xyz[Self::Y].copy_from_slice(&neg_y.0);
            }
        }
        r
    }
}

/// An element of GF(p), fully reduced.  P-521's prime is a Mersenne prime,
/// so its arithmetic is direct rather than Montgomery's.
#[derive(Clone, Copy, Debug, Default)]
struct FieldElement([u64; 9]);

impl FieldElement {
    const BYTES: usize = 66;

    /// Big-endian, from the 72 bytes of the words, whose top 7 bits are zero.
    fn as_bytes(&self) -> [u8; Self::BYTES] {
        util::u64x9_to_big_endian(&self.0)[72 - Self::BYTES..]
            .try_into()
            .unwrap()
    }

    fn inv(&self) -> Self {
        let mut r = Self::default();
        low::bignum_inv_p521(&mut r.0, &self.0);
        r
    }

    /// Squaring mod p521
    fn sqr(&self) -> Self {
        let mut r = Self::default();
        low::bignum_sqr_p521(&mut r.0, &self.0);
        r
    }

    /// Addition mod p521
    fn add(&self, other: &Self) -> Self {
        let mut r = Self::default();
        low::bignum_add_p521(&mut r.0, &self.0, &other.0);
        r
    }

    /// Multiplication mod p521
    fn mul(&self, other: &Self) -> Self {
        let mut r = Self::default();
        low::bignum_mul_p521(&mut r.0, &self.0, &other.0);
        r
    }

    fn negate(&self) -> Self {
        let mut r = Self::default();
        low::bignum_neg_p521(&mut r.0, &self.0);
        r
    }

    /// Public equality
    fn public_eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }

    /// Return p0 if select == 0, p1 otherwise
    fn select(p0: &Self, p1: &Self, select: u8) -> Self {
        let mut r = Self::default();
        let select = select as u64;
        low::bignum_mux(select, &mut r.0[..], &p1.0[..], &p0.0[..]);
        r
    }
}

#[derive(Default)]
pub(crate) struct Scalar([u64; 9]);

impl Scalar {
    pub(crate) const BYTES: usize = 66;

    /// The bits of `BYTES` above n's 521.
    const EXCESS_BITS: u32 = 7;

    /// Create a scalar from the given slice, which can be any size.
    ///
    /// If it is larger than 72 bytes, the leading bytes must be
    /// zero (this is deemed a non-secret property).
    ///
    /// This returns an error if the scalar is zero or larger than
    /// the curve order.
    pub(crate) fn from_bytes_checked(bytes: &[u8]) -> Result<Self, Error> {
        let full = Self(
            util::big_endian_slice_any_size_to_u64x9(bytes)
                .ok_or(KeyFormatError::ScalarOutOfRange)?,
        );

        full.into_range_check()
    }

    pub(crate) fn from_bytes_reduced(bytes: &[u8]) -> Result<Self, Error> {
        Ok(
            Self(util::big_endian_slice_any_size_to_u64x9(bytes).ok_or(Error::WrongLength)?)
                .reduce_mod_n(),
        )
    }

    fn into_range_check(self) -> Result<Self, Error> {
        let reduced = self.reduce_mod_n();

        // Whether a scalar is in range is public: a key or signature is refused
        // on it, and a rejected nonce candidate says nothing of the one accepted.
        match low::ct::into_public(reduced.private_eq(&self) & !self.is_zero()) {
            true => Ok(self),
            false => Err(KeyFormatError::ScalarOutOfRange.into()),
        }
    }

    pub(crate) fn as_bytes(&self) -> [u8; Self::BYTES] {
        util::u64x9_to_big_endian(&self.0)[72 - Self::BYTES..]
            .try_into()
            .unwrap()
    }

    #[cfg(test)]
    fn small_u64(v: u64) -> Self {
        Self([v, 0, 0, 0, 0, 0, 0, 0, 0])
    }

    /// Private test for zero
    pub(crate) fn is_zero(&self) -> bool {
        self.private_eq(&Self::default())
    }

    /// Private equality
    fn private_eq(&self, other: &Self) -> bool {
        low::bignum_eq(&self.0, &other.0)
    }

    /// Public equality
    fn public_eq(&self, other: &Self) -> bool {
        low::bignum_eq(&self.0, &other.0)
    }

    /// Reduce mod n (curve order)
    fn reduce_mod_n(&self) -> Self {
        let mut r = Self::default();
        low::bignum_mod_n521(&mut r.0, &self.0);
        r
    }

    /// Remove one montgomery factor mod n
    fn demont(&self) -> Self {
        let mut r = Self::default();
        low::bignum_demont(&mut r.0, &self.0, &CURVE_ORDER);
        r
    }

    /// Add a montgomery factor mod n
    fn as_mont(&self) -> Self {
        let mut r = Self::default();
        low::bignum_montmul(&mut r.0, &self.0, &CURVE_ORDER_MM, &CURVE_ORDER);
        r
    }

    /// Return 2^1152 mod n, ie MM mod n
    #[cfg(test)]
    fn montifier() -> Self {
        let mut r = Self::default();
        let mut tmp = Self::default();
        low::bignum_montifier(&mut r.0, &CURVE_ORDER, &mut tmp.0);
        r
    }

    /// Montgomery multiplication mod n
    ///
    /// Assumes `self` and `other` are in montgomery domain.
    /// Result is in montgomery domain.
    fn mont_mul(&self, other: &Self) -> Self {
        let mut r = Self::default();
        low::bignum_montmul(&mut r.0, &self.0, &other.0, &CURVE_ORDER);
        r
    }

    /// Find the multiplicative inverse of `self` mod n
    fn inv(&self) -> Self {
        let mut r = Self::default();
        let mut temp = [0u64; 9 * 3];
        low::bignum_modinv(&mut r.0, &self.0, &CURVE_ORDER, &mut temp);
        r
    }

    /// Add `self` + `other` mod n
    fn add(&self, other: &Self) -> Self {
        let mut r = Self::default();
        low::bignum_modadd(&mut r.0, &self.0, &other.0, &CURVE_ORDER);
        r
    }

    /// Iterator of the bits of the element, lowest first
    #[cfg(test)]
    fn bits(&self) -> impl Iterator<Item = u8> + '_ {
        (0..576).map(|i| ((self.0[i / 64] >> (i % 64)) & 1) as u8)
    }

    /// Iterator of 105 5-bit windows, highest first, each a digit, its sign,
    /// and whether it is the last
    fn reversed_booth_recoded_w5(&self) -> BoothRecodeW5 {
        BoothRecodeW5::new(self)
    }
}

impl Drop for Scalar {
    fn drop(&mut self) {
        low::zeroise(&mut self.0);
    }
}

struct BoothRecodeW5 {
    // little endian
    bytes: [u8; 73],
    index: usize,
}

impl BoothRecodeW5 {
    fn new(scalar: &Scalar) -> Self {
        let mut bytes = [0u8; 73];
        for (chunk, word) in bytes.as_chunks_mut::<8>().0.iter_mut().zip(scalar.0) {
            *chunk = word.to_le_bytes();
        }

        Self { bytes, index: 520 }
    }

    fn recode(v: u8) -> (u8, u8) {
        // see the comment above boringssl's `ec_GFp_nistp_recode_scalar_bits` for
        // references
        let sign = !((v >> 5).wrapping_sub(1));

        let d = (1u16 << 6).wrapping_sub(v as u16).wrapping_sub(1) as u8;
        let d = (d & sign) | (v & !sign);
        let d = (d >> 1).wrapping_add(d & 1);

        (d, sign & 1)
    }
}

impl Iterator for BoothRecodeW5 {
    type Item = (u8, u8, bool);

    fn next(&mut self) -> Option<Self::Item> {
        const MASK: u8 = (1 << (5 + 1)) - 1;

        match self.index {
            5..=520 => {
                let offset = (self.index - 1) / 8;
                let shift = (self.index - 1) % 8;
                let value = (((self.bytes[offset] as u16) | ((self.bytes[offset + 1] as u16) << 8))
                    >> shift) as u8
                    & MASK;
                let (digit, sign) = Self::recode(value);
                self.index -= 5;
                Some((digit, sign, false))
            }

            0 => {
                let value = (self.bytes[0] << 1) & MASK;
                let (digit, sign) = Self::recode(value);
                self.index = usize::MAX;
                Some((digit, sign, true))
            }

            _ => None,
        }
    }
}

/// 16 jacobian points
#[cfg(any(target_arch = "aarch64", test))]
type JacobianPointTableW5 = [u64; 432];

/// 27 tables of 16 affine points
type AffinePointTableComb = [[u64; 288]; 27];

/// a, which is -3
const CURVE_A: FieldElement = FieldElement([
    0xffff_ffff_ffff_fffc,
    0xffff_ffff_ffff_ffff,
    0xffff_ffff_ffff_ffff,
    0xffff_ffff_ffff_ffff,
    0xffff_ffff_ffff_ffff,
    0xffff_ffff_ffff_ffff,
    0xffff_ffff_ffff_ffff,
    0xffff_ffff_ffff_ffff,
    0x0000_0000_0000_01ff,
]);

const CURVE_B: FieldElement = FieldElement([
    0xef45_1fd4_6b50_3f00,
    0x3573_df88_3d2c_34f1,
    0x1652_c0bd_3bb1_bf07,
    0x5619_3951_ec7e_937b,
    0xb8b4_8991_8ef1_09e1,
    0xa2da_725b_99b3_15f3,
    0x929a_21a0_b685_40ee,
    0x953e_b961_8e1c_9a1f,
    0x0000_0000_0000_0051,
]);

const CURVE_ONE: FieldElement = FieldElement([1, 0, 0, 0, 0, 0, 0, 0, 0]);

const CURVE_PRIME: [u64; 9] = [
    0xffff_ffff_ffff_ffff,
    0xffff_ffff_ffff_ffff,
    0xffff_ffff_ffff_ffff,
    0xffff_ffff_ffff_ffff,
    0xffff_ffff_ffff_ffff,
    0xffff_ffff_ffff_ffff,
    0xffff_ffff_ffff_ffff,
    0xffff_ffff_ffff_ffff,
    0x0000_0000_0000_01ff,
];

const CURVE_ORDER: [u64; 9] = [
    0xbb6f_b71e_9138_6409,
    0x3bb5_c9b8_899c_47ae,
    0x7fcc_0148_f709_a5d0,
    0x5186_8783_bf2f_966b,
    0xffff_ffff_ffff_fffa,
    0xffff_ffff_ffff_ffff,
    0xffff_ffff_ffff_ffff,
    0xffff_ffff_ffff_ffff,
    0x0000_0000_0000_01ff,
];

/// 2^1152 mod n: the Montgomery factor, 2^576, squared.
const CURVE_ORDER_MM: [u64; 9] = [
    0x137c_d04d_cf15_dd04,
    0xf707_badc_e554_7ea3,
    0x12a7_8d38_7945_73ff,
    0xd372_1ef5_57f7_5e06,
    0xdd6e_23d8_2e49_c7db,
    0xcff3_d142_b775_6e3e,
    0x5bcc_6d61_a8e5_67bc,
    0x2d8e_03d1_492d_0d45,
    0x0000_0000_0000_003d,
];

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    const CURVE_GENERATOR: AffinePoint = AffinePoint {
        xy: [
            0xf97e_7e31_c2e5_bd66,
            0x3348_b3c1_856a_429b,
            0xfe1d_c127_a2ff_a8de,
            0xa14b_5e77_efe7_5928,
            0xf828_af60_6b4d_3dba,
            0x9c64_8139_053f_b521,
            0x9e3e_cb66_2395_b442,
            0x858e_06b7_0404_e9cd,
            0x0000_0000_0000_00c6,
            0x88be_9476_9fd1_6650,
            0x353c_7086_a272_c240,
            0xc550_b901_3fad_0761,
            0x97ee_7299_5ef4_2640,
            0x17af_bd17_273e_662c,
            0x98f5_4449_579b_4468,
            0x5c8a_5fb4_2c7d_1bd9,
            0x3929_6a78_9a3b_c004,
            0x0000_0000_0000_0118,
        ],
    };

    fn n_minus(k: u64) -> Scalar {
        let mut s = CURVE_ORDER;
        s[0] -= k;
        Scalar(s)
    }

    /// Scalars at the edges of the windowed multiplications: small ones,
    /// one top bit, and those near n, including n - 2 to n - 32, whose last
    /// window doubles in `public_multiply_w5`.
    fn edge_scalars() -> impl Iterator<Item = Scalar> {
        [1, 2, 3, 16, 17, 31, 32, 33, 99999999]
            .into_iter()
            .map(Scalar::small_u64)
            .chain([Scalar([0, 0, 0, 0, 0, 0, 0, 0, 0x100])])
            .chain((1..=34).map(n_minus))
    }

    #[test]
    fn generator_on_curve() {
        assert!(CURVE_GENERATOR.on_curve());
    }

    #[test]
    fn multiplications_match_double_and_add() {
        let point = CURVE_GENERATOR.slow_multiply(&Scalar::small_u64(5));
        let precomp = point.public_precomp_w5();
        for scalar in edge_scalars() {
            let expected = point.slow_multiply(&scalar).xy;
            assert_eq!(
                JacobianPoint::multiply(&scalar, &point).as_affine().xy,
                expected
            );
            assert_eq!(
                JacobianPoint::public_multiply_w5(&scalar, &precomp)
                    .as_affine()
                    .xy,
                expected
            );

            let expected = CURVE_GENERATOR.slow_multiply(&scalar).xy;
            assert_eq!(
                JacobianPoint::base_multiply(&scalar).as_affine().xy,
                expected
            );
            assert_eq!(
                JacobianPoint::public_base_multiply(&scalar).as_affine().xy,
                expected
            );
        }
    }

    #[test]
    fn public_add_edges() {
        let g = JacobianPoint::from_affine(&CURVE_GENERATOR);
        let g2 = g.double();
        let negate = |p: &JacobianPoint| {
            let mut r = *p;
            r.xyz[JacobianPoint::Y].copy_from_slice(&p.y().negate().0);
            r
        };
        // 2G again, as 4G - 2G, with another z.
        let g2_again = g2.double().add(&negate(&g2));
        assert_ne!(g2_again.z().0, g2.z().0);
        let infinity = JacobianPoint::infinity();

        assert_eq!(
            JacobianPoint::public_add(&g, &g).as_affine().xy,
            g2.as_affine().xy
        );
        assert_eq!(
            JacobianPoint::public_add(&g2, &g2_again).as_affine().xy,
            g2.double().as_affine().xy
        );
        assert!(JacobianPoint::public_add(&g2, &negate(&g2_again)).public_is_infinity());
        assert!(JacobianPoint::public_add(&g, &negate(&g)).public_is_infinity());
        assert_eq!(JacobianPoint::public_add(&g, &infinity).xyz, g.xyz);
        assert_eq!(JacobianPoint::public_add(&infinity, &g).xyz, g.xyz);
        assert!(JacobianPoint::public_add(&infinity, &infinity).public_is_infinity());
    }

    #[test]
    fn generate_key_known_answer() {
        // From RFC6979 A.2.7.
        let private = PrivateKey::from_bytes(&hex::decode("00fad06daa62ba3b25d2fb40133da757205de67f5bb0018fee8c86e1b68c7e75caa896eb32f1f47c70855836a6d16fcc1466f6d8fbec67db89ec0c08b0e996b83538").unwrap()).unwrap();
        let public = private.public_key_uncompressed();
        assert_eq!(
            hex::encode(public),
            "04\
             01894550d0785932e00eaa23b694f213f8c3121f86dc97a04e5a7167db4e5bcd371123d46e45db6b5d5370a7f20fb633155d38ffa16d2bd761dcac474b9a2f5023a4\
             00493101c962cd4d2fddf782285e64584139c2f91b47f87ff82354d6630f746a28a0db25741b5b34a828008b22acc23f924faafbd4d33f81ea66956dfeaa2bfdfcf5"
        );
        PublicKey::from_x962_uncompressed(&public).unwrap();
    }

    #[test]
    fn generate_takes_leftmost_521_bits() {
        // RFC6979's bits2int: the top 7 of 528 bits drawn are dropped.
        let mut drawn = [0xffu8; Scalar::BYTES];
        drawn[0] = 0x00;
        drawn[1] = 0x80;
        let key = PrivateKey::generate(&mut crate::mid::rng::SliceRandomSource(&drawn)).unwrap();
        let mut expected = [0xffu8; Scalar::BYTES];
        expected[0] = 0x00;
        expected[1] = 0x01;
        expected[2] = 0x01;
        assert_eq!(low::ct::into_public(key.scalar.as_bytes()), expected);
    }

    #[test]
    fn test_scalar() {
        let mut one = [0u8; 66];
        one[65] = 1;
        let scalar = Scalar::from_bytes_checked(&one);
        assert!(scalar.is_ok());
        assert_eq!(scalar.unwrap().as_bytes(), Scalar::small_u64(1).as_bytes());

        assert!(Scalar::from_bytes_checked(&[0xff; 66]).is_err());
    }

    #[test]
    fn private_key_in_range() {
        assert_eq!(
            PrivateKey::from_bytes(&[0u8; 66]).unwrap_err(),
            Error::from(KeyFormatError::ScalarOutOfRange)
        );

        let order = Scalar(CURVE_ORDER).as_bytes();
        assert_eq!(
            PrivateKey::from_bytes(&order).unwrap_err(),
            Error::from(KeyFormatError::ScalarOutOfRange)
        );
        let mut order_plus_1 = order;
        order_plus_1[65] += 1;
        assert_eq!(
            PrivateKey::from_bytes(&order_plus_1).unwrap_err(),
            Error::from(KeyFormatError::ScalarOutOfRange)
        );
        PrivateKey::from_bytes(&n_minus(1).as_bytes()).unwrap();
    }

    #[test]
    fn montifier() {
        assert_eq!(Scalar::montifier().0, CURVE_ORDER_MM);
    }

    /// Checks each point of `admin/p521-precomp`'s table, which uses
    /// Python's integers, against rind's own arithmetic.
    #[test]
    fn base_point_precomp_comb() {
        let mut base = JacobianPoint::from_affine(&CURVE_GENERATOR);
        for table in &precomp::CURVE_GENERATOR_PRECOMP_COMB {
            let mut multiple = base;
            for (i, entry) in (1..).zip(table.as_chunks::<18>().0) {
                assert_eq!(&multiple.as_affine().xy, entry);
                multiple = match i {
                    1 => multiple.double(),
                    _ => multiple.add(&base),
                };
            }
            base.double_inplace_n(20);
        }
    }
}
