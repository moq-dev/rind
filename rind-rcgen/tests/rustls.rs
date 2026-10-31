//! Certificates signed by rind-rcgen verify under rind-rustls and under
//! rustls on aws-lc-rs, and each key loads and matches its certificate.

use std::sync::Arc;
use std::time::Duration;

use rcgen::{
    BasicConstraints, CertificateParams, Error, IsCa, Issuer, PKCS_ECDSA_P256_SHA256,
    PKCS_ECDSA_P384_SHA384, PKCS_ED25519, PKCS_RSA_SHA256, PKCS_RSA_SHA384, PKCS_RSA_SHA512,
    PublicKeyData, SerialNumber, SignatureAlgorithm,
};
use rind_rcgen::KeyPair;
use rustls::RootCertStore;
use rustls::client::WebPkiServerVerifier;
use rustls::client::danger::ServerCertVerifier;
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::sign::CertifiedKey;

/// Every algorithm rind-rcgen generates keys for.
const GENERATED: [&SignatureAlgorithm; 3] = [
    &PKCS_ECDSA_P256_SHA256,
    &PKCS_ECDSA_P384_SHA384,
    &PKCS_ED25519,
];

#[test]
fn self_signed() {
    for algorithm in GENERATED {
        let key = KeyPair::generate(algorithm).unwrap();
        let cert = params(1).self_signed(&key).unwrap();

        for provider in providers() {
            verify(&provider, cert.der(), cert.der()).unwrap();
            load(&provider, cert.der(), &key);
        }
    }
}

#[test]
fn signed_by_ca() {
    for algorithm in GENERATED {
        let ca_key = KeyPair::generate(algorithm).unwrap();
        let mut ca_params = params(1);
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let ca = ca_params.self_signed(&ca_key).unwrap();

        let key = KeyPair::generate(&PKCS_ECDSA_P256_SHA256).unwrap();
        let cert = params(2)
            .signed_by(&key, &Issuer::new(ca_params, &ca_key))
            .unwrap();

        for provider in providers() {
            verify(&provider, ca.der(), cert.der()).unwrap();
            load(&provider, cert.der(), &key);
        }
    }
}

#[test]
fn rsa_loads_but_does_not_generate() {
    let der =
        PrivatePkcs8KeyDer::from(&include_bytes!("../../rind/src/high/rsa/rsa2048.pkcs8.der")[..]);
    for algorithm in [&PKCS_RSA_SHA256, &PKCS_RSA_SHA384, &PKCS_RSA_SHA512] {
        let key = KeyPair::from_pkcs8(algorithm, &der).unwrap();
        let cert = params(1).self_signed(&key).unwrap();

        for provider in providers() {
            verify(&provider, cert.der(), cert.der()).unwrap();
            load(&provider, cert.der(), &key);
        }
        assert_eq!(
            KeyPair::generate(algorithm).unwrap_err(),
            Error::KeyGenerationUnavailable
        );
    }
}

#[test]
fn reloads_its_own_encoding() {
    for algorithm in GENERATED {
        let key = KeyPair::generate(algorithm).unwrap();
        let reloaded = KeyPair::from_pkcs8(algorithm, &key.to_pkcs8()).unwrap();
        assert_eq!(reloaded.der_bytes(), key.der_bytes());
    }
}

#[test]
fn refusal_keeps_rinds_reason() {
    let p256 = KeyPair::generate(&PKCS_ECDSA_P256_SHA256)
        .unwrap()
        .to_pkcs8();
    assert_eq!(
        KeyPair::from_pkcs8(&PKCS_ECDSA_P384_SHA384, &p256).unwrap_err(),
        Error::RingKeyRejected("mismatched PKCS#8 parameters".to_string())
    );
    assert_eq!(
        KeyPair::from_pkcs8(&PKCS_RSA_SHA256, &p256).unwrap_err(),
        Error::RingKeyRejected("mismatched PKCS#8 algorithm".to_string())
    );
}

fn providers() -> [Arc<CryptoProvider>; 2] {
    [
        Arc::new(rind_rustls::default_provider().unwrap()),
        Arc::new(rustls::crypto::aws_lc_rs::default_provider()),
    ]
}

fn params(serial: u64) -> CertificateParams {
    let mut params = CertificateParams::new(["localhost".to_string()]).unwrap();
    params.serial_number = Some(SerialNumber::from(serial));
    params
}

fn verify(
    provider: &Arc<CryptoProvider>,
    root: &CertificateDer<'_>,
    cert: &CertificateDer<'_>,
) -> Result<(), rustls::Error> {
    let mut roots = RootCertStore::empty();
    roots.add(root.clone().into_owned()).unwrap();
    let verifier = WebPkiServerVerifier::builder_with_provider(roots.into(), provider.clone())
        .build()
        .unwrap();

    // Inside rcgen's default validity, without reading the wall clock.
    let now = UnixTime::since_unix_epoch(Duration::from_secs(1_800_000_000));
    let name = ServerName::try_from("localhost").unwrap();
    verifier
        .verify_server_cert(cert, &[], &name, &[], now)
        .map(|_| ())
}

fn load(provider: &CryptoProvider, cert: &CertificateDer<'_>, key: &KeyPair) {
    let key = PrivateKeyDer::Pkcs8(key.to_pkcs8().clone_key());
    CertifiedKey::from_der(vec![cert.clone().into_owned()], key, provider).unwrap();
}
