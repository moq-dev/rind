use crypto::SupportedKxGroup;
use rind::agreement;
use rustls::crypto;
use rustls::ffdhe_groups::FfdheGroup;

mod hybrid;
mod mlkem;

/// Key exchange with X25519.
pub static X25519: &dyn SupportedKxGroup = &KxGroup {
    name: rustls::NamedGroup::X25519,
    algorithm: &agreement::X25519,
};

/// Key exchange with ECDH on P-256, also known as secp256r1.
pub static SECP256R1: &dyn SupportedKxGroup = &KxGroup {
    name: rustls::NamedGroup::secp256r1,
    algorithm: &agreement::ECDH_P256,
};

/// Key exchange with ECDH on P-384, also known as secp384r1.
pub static SECP384R1: &dyn SupportedKxGroup = &KxGroup {
    name: rustls::NamedGroup::secp384r1,
    algorithm: &agreement::ECDH_P384,
};

/// Hybrid key exchange with X25519 and ML-KEM-768, for TLS 1.3 only.
pub static X25519MLKEM768: &dyn SupportedKxGroup = &hybrid::Hybrid {
    classical: X25519,
    classical_share_len: 32,
    post_quantum: &mlkem::MlKem768,
    post_quantum_client_share_len: mlkem::MlKem768::ENCAPS_LEN,
    post_quantum_server_share_len: mlkem::MlKem768::CIPHERTEXT_LEN,
    name: rustls::NamedGroup::X25519MLKEM768,
};

/// An elliptic-curve key exchange group.
#[derive(Debug)]
struct KxGroup {
    name: rustls::NamedGroup,
    algorithm: &'static agreement::Algorithm,
}

impl SupportedKxGroup for KxGroup {
    fn start(&self) -> Result<Box<dyn crypto::ActiveKeyExchange>, rustls::Error> {
        let priv_key = agreement::PrivateKey::generate(self.algorithm)
            .map_err(|_| rustls::Error::from(crypto::GetRandomFailed))?;
        let pub_key = priv_key.public_key();
        Ok(Box::new(Active {
            group: self.name,
            priv_key,
            pub_key,
        }))
    }

    fn ffdhe_group(&self) -> Option<FfdheGroup<'static>> {
        None
    }

    fn name(&self) -> rustls::NamedGroup {
        self.name
    }
}

struct Active {
    group: rustls::NamedGroup,
    priv_key: agreement::PrivateKey,
    pub_key: agreement::PublicKey,
}

impl crypto::ActiveKeyExchange for Active {
    fn complete(self: Box<Self>, peer: &[u8]) -> Result<crypto::SharedSecret, rustls::Error> {
        let shared_secret = self
            .priv_key
            .agree(peer)
            .map_err(|_| rustls::Error::from(rustls::PeerMisbehaved::InvalidKeyShare))?;
        Ok(crypto::SharedSecret::from(shared_secret.as_ref()))
    }

    fn pub_key(&self) -> &[u8] {
        self.pub_key.as_ref()
    }

    fn ffdhe_group(&self) -> Option<FfdheGroup<'static>> {
        None
    }

    fn group(&self) -> rustls::NamedGroup {
        self.group
    }
}

#[cfg(test)]
mod tests {
    use rustls::NamedGroup;
    use rustls::ProtocolVersion;

    use super::*;

    #[test]
    fn classical_groups() {
        for (group, name, algorithm) in [
            (X25519, NamedGroup::X25519, &agreement::X25519),
            (SECP256R1, NamedGroup::secp256r1, &agreement::ECDH_P256),
            (SECP384R1, NamedGroup::secp384r1, &agreement::ECDH_P384),
        ] {
            assert_eq!(group.name(), name);
            assert_eq!(group.ffdhe_group(), None);
            assert!(group.usable_for_version(ProtocolVersion::TLSv1_2));
            assert!(group.usable_for_version(ProtocolVersion::TLSv1_3));

            // A key exchange with an invalid peer public key should fail.
            let active = group.start().unwrap();
            assert_eq!(active.group(), name);
            assert!(active.complete(&[0u8]).is_err());

            // A key exchange with a valid peer public key should succeed.
            let active = group.start().unwrap();
            assert_eq!(active.ffdhe_group(), None);
            let peer = agreement::PrivateKey::generate(algorithm).unwrap();
            assert!(active.complete(peer.public_key().as_ref()).is_ok());
        }
    }

    #[test]
    fn hybrid_refuses_shares_of_the_wrong_length() {
        let client_len = mlkem::MlKem768::ENCAPS_LEN + 32;
        let server_len = mlkem::MlKem768::CIPHERTEXT_LEN + 32;
        assert_eq!(X25519MLKEM768.start().unwrap().pub_key().len(), client_len);

        for len in [0, client_len - 1, client_len + 1] {
            assert!(X25519MLKEM768.start_and_complete(&vec![0; len]).is_err());
        }
        for len in [0, server_len - 1, server_len + 1] {
            let active = X25519MLKEM768.start().unwrap();
            assert!(active.complete(&vec![0; len]).is_err());
        }
    }
}
