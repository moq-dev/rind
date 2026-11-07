//! PKCS#8 private key documents.

use alloc::vec::Vec;

use zeroize::Zeroizing;

/// A PKCS#8 private key document, wiped on drop.
pub struct Document(Zeroizing<Vec<u8>>);

impl Document {
    pub(crate) fn new(der: &[u8]) -> Self {
        Self(Zeroizing::new(der.to_vec()))
    }
}

impl AsRef<[u8]> for Document {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}
