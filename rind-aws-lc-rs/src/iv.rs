//! Initialization vectors.

use crate::error::Unspecified;

/// The length of a 128-bit IV, in bytes.
pub const IV_LEN_128_BIT: usize = 16;

/// An IV of `L` bytes.
pub struct FixedLength<const L: usize>([u8; L]);

impl<const L: usize> FixedLength<L> {
    /// The length, in bytes.
    pub fn size(&self) -> usize {
        L
    }

    /// Draws a random IV from the system random source.
    pub fn new() -> Result<Self, Unspecified> {
        let mut iv = [0u8; L];
        crate::rand::fill(&mut iv)?;
        Ok(Self(iv))
    }
}

impl<const L: usize> AsRef<[u8; L]> for FixedLength<L> {
    fn as_ref(&self) -> &[u8; L] {
        &self.0
    }
}

impl<const L: usize> From<&[u8; L]> for FixedLength<L> {
    fn from(bytes: &[u8; L]) -> Self {
        Self(*bytes)
    }
}

impl<const L: usize> From<[u8; L]> for FixedLength<L> {
    fn from(bytes: [u8; L]) -> Self {
        Self(bytes)
    }
}

/// Fails unless `value` is `L` bytes.
impl<const L: usize> TryFrom<&[u8]> for FixedLength<L> {
    type Error = Unspecified;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        Ok(Self(value.try_into()?))
    }
}

impl<const L: usize> TryFrom<FixedLength<L>> for [u8; L] {
    type Error = Unspecified;

    fn try_from(value: FixedLength<L>) -> Result<Self, Self::Error> {
        Ok(value.0)
    }
}
