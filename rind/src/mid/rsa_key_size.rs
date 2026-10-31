// Written for Graviola by Joe Birr-Pixton, 2025.
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

/// The modulus size of an RSA key pair to generate.
#[derive(Clone, Copy, Debug, PartialEq)]
#[non_exhaustive]
pub enum RsaKeySize {
    /// A 2048-bit modulus.
    Rsa2048,
    /// A 3072-bit modulus.
    Rsa3072,
    /// A 4096-bit modulus.
    Rsa4096,
    /// A 6144-bit modulus.
    Rsa6144,
    /// An 8192-bit modulus.
    Rsa8192,
}

impl RsaKeySize {
    /// The length of each prime, half the modulus, in bits.
    pub(crate) fn prime_bits(self) -> usize {
        match self {
            Self::Rsa2048 => 1024,
            Self::Rsa3072 => 1536,
            Self::Rsa4096 => 2048,
            Self::Rsa6144 => 3072,
            Self::Rsa8192 => 4096,
        }
    }

    pub(crate) fn miller_rabin_rounds(self) -> usize {
        // FIPS186-5, Table B.1.
        match self {
            Self::Rsa2048 => 5,
            Self::Rsa3072 => 4,
            Self::Rsa4096 => 4,
            // nb. not included in FIPS186-5.
            Self::Rsa6144 | Self::Rsa8192 => 4,
        }
    }
}
