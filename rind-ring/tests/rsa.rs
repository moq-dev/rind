//! ring signs only with moduli of 2048 to 4096 bits, which rind-ring keeps
//! though rind loads keys up to 8192 bits; ring's own vectors stop at 4096.

use rind_ring::{rand, signature};

#[test]
fn key_pair_modulus_sizes() {
    for (bits, ok) in [
        (2048, true),
        (3072, true),
        (4096, true),
        (6144, false),
        (8192, false),
    ] {
        let der = std::fs::read(format!("../rind/src/high/rsa/rsa{bits}.der")).unwrap();
        let key_pair = signature::RsaKeyPair::from_der(&der);
        assert_eq!(key_pair.is_ok(), ok, "{bits} bits");
        let Ok(key_pair) = key_pair else { continue };
        assert_eq!(key_pair.public_modulus_len(), bits / 8);

        let mut signature = vec![0; key_pair.public_modulus_len()];
        key_pair
            .sign(
                &signature::RSA_PSS_SHA256,
                &rand::SystemRandom::new(),
                b"message",
                &mut signature,
            )
            .unwrap();
        signature::UnparsedPublicKey::new(
            &signature::RSA_PSS_2048_8192_SHA256,
            key_pair.public().as_ref(),
        )
        .verify(b"message", &signature)
        .unwrap();
    }
}
