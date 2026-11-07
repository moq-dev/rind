//! The one serialization type aws-lc-rs's API returns: a positive integer,
//! as an RSA public key's modulus and exponent are given.

/// A big-endian positive integer, without leading zero bytes.
#[derive(Copy, Clone)]
pub struct Positive<'a>(&'a [u8]);

impl<'a> Positive<'a> {
    /// Wraps a non-empty magnitude without leading zero bytes.
    pub(crate) fn new(magnitude: &'a [u8]) -> Self {
        Self(magnitude)
    }

    /// The integer's big-endian bytes, without leading zero bytes.
    #[must_use]
    pub fn big_endian_without_leading_zero(&self) -> &'a [u8] {
        self.0
    }

    /// The integer's first byte.
    #[must_use]
    pub fn first_byte(&self) -> u8 {
        self.0[0]
    }
}
