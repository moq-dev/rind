//! PKCS#8 private key documents.

/// A PKCS#8 private key document, wiped on drop.
pub struct Document(rind::signature::Pkcs8);

impl Document {
    pub(crate) fn new(pkcs8: rind::signature::Pkcs8) -> Self {
        Self(pkcs8)
    }
}

impl AsRef<[u8]> for Document {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}
