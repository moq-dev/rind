//! Constant-time checks for each secret path, run under valgrind by
//! `admin/ctgrind`.
//!
//! Outputs that are public by design are marked defined before the test checks
//! them. rind itself marks the private keys it generates and parses, so
//! memcheck flags any branch or memory index that depends on them.

use crabgrind::memcheck::{self, MemState};
use crabgrind::valgrind::{self, RunningMode};
use rcgen::{
    CertificateParams, PKCS_ECDSA_P256_SHA256, PKCS_ECDSA_P384_SHA384, PKCS_ED25519,
    PKCS_RSA_SHA256, PKCS_RSA_SHA384, PKCS_RSA_SHA512, PublicKeyData, SerialNumber,
    SignatureAlgorithm,
};
use rind::signature::{PublicKey, RsaVerificationAlgorithm, VerificationAlgorithm, verify};
use rind_rcgen::KeyPair;
use rustls_pki_types::PrivatePkcs8KeyDer;

/// Marks `value` public, so the test may branch on it.
fn public<T: ?Sized>(value: &T) {
    mark(value, MemState::Defined);
}

fn mark<T: ?Sized>(value: &T, state: MemState) {
    if let RunningMode::Valgrind = valgrind::running_mode() {
        memcheck::mark_memory((value as *const T).cast(), size_of_val(value), state).unwrap();
    }
}

/// Each algorithm rind-rcgen generates keys for, and the rind algorithm that
/// verifies it.
const ALGORITHMS: [(&SignatureAlgorithm, &VerificationAlgorithm); 3] = [
    (&PKCS_ECDSA_P256_SHA256, &verify::ECDSA_P256_SHA256_ASN1),
    (&PKCS_ECDSA_P384_SHA384, &verify::ECDSA_P384_SHA384_ASN1),
    (&PKCS_ED25519, &verify::ED25519),
];

#[test]
fn self_signed() {
    for (algorithm, verification) in ALGORITHMS {
        let key = KeyPair::generate(algorithm).unwrap();

        let mut params = CertificateParams::new(["localhost".to_string()]).unwrap();
        params.serial_number = Some(SerialNumber::from_slice(&[1]));
        let cert = params.self_signed(&key).unwrap();
        public(cert.der().as_ref());
        assert!(!cert.der().is_empty());

        let signature = rcgen::SigningKey::sign(&key, b"message").unwrap();
        public(&signature[..]);
        PublicKey::new(verification, key.der_bytes())
            .unwrap()
            .verify(b"message", &signature)
            .unwrap();
    }
}

#[test]
fn export() {
    for (algorithm, _) in ALGORITHMS {
        let key = KeyPair::generate(algorithm).unwrap();
        // rind treats an exported key as leaving its care, so the encoding is public.
        let der = key.to_pkcs8();

        let reloaded = KeyPair::from_pkcs8(algorithm, &der).unwrap();
        let public_key = reloaded.der_bytes();
        public(public_key);
        assert_eq!(public_key, key.der_bytes());
    }
}

#[test]
fn rsa() {
    let der =
        PrivatePkcs8KeyDer::from(&include_bytes!("../../rind/src/high/rsa/rsa2048.pkcs8.der")[..]);
    let algorithms: [(&SignatureAlgorithm, &RsaVerificationAlgorithm); 3] = [
        (&PKCS_RSA_SHA256, &verify::RSA_PKCS1_SHA256),
        (&PKCS_RSA_SHA384, &verify::RSA_PKCS1_SHA384),
        (&PKCS_RSA_SHA512, &verify::RSA_PKCS1_SHA512),
    ];
    for (algorithm, verification) in algorithms {
        let key = KeyPair::from_pkcs8(algorithm, &der).unwrap();

        let signature = rcgen::SigningKey::sign(&key, b"message").unwrap();
        public(&signature[..]);
        PublicKey::new(verification, key.der_bytes())
            .unwrap()
            .verify(b"message", &signature)
            .unwrap();

        // rind treats an exported key as leaving its care, so the encoding is public.
        let exported = key.to_pkcs8();
        public(exported.secret_pkcs8_der());
        assert_eq!(exported.secret_pkcs8_der(), der.secret_pkcs8_der());
    }
}
