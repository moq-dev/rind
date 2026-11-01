use aws_lc_rs::rsa::KeyPair;
use aws_lc_rs::{digest, hmac, signature::Ed25519KeyPair};
use proptest::collection::vec;
use proptest::prelude::*;
use rind::signature::{self, RsaKeyPair, RsaKeySize};

#[test]
fn rsa_2048_key_generation() {
    check_key_generation(RsaKeySize::Rsa2048);
}

#[test]
fn rsa_2048_key_generation_soak() {
    if std::env::var_os("SLOW_TESTS").is_some() {
        for _ in 0..512 {
            check_key_generation(RsaKeySize::Rsa2048);
        }
    }
}

#[test]
fn rsa_3072_key_generation() {
    check_key_generation(RsaKeySize::Rsa3072);
}

#[test]
fn rsa_4096_key_generation() {
    check_key_generation(RsaKeySize::Rsa4096);
}

#[test]
fn rsa_6144_key_generation() {
    if std::env::var_os("SLOW_TESTS").is_some() {
        check_key_generation(RsaKeySize::Rsa6144);
    }
}

#[test]
fn rsa_8192_key_generation() {
    if std::env::var_os("SLOW_TESTS").is_some() {
        check_key_generation(RsaKeySize::Rsa8192);
    }
}

fn check_key_generation(size: RsaKeySize) {
    let key = RsaKeyPair::generate(size).unwrap();
    KeyPair::from_pkcs8(key.to_pkcs8().as_ref()).expect("aws-lc-rs rejected a key we generated");
}

#[test]
fn ed25519_key_generation() {
    for _ in 0..100 {
        let key = signature::Ed25519KeyPair::generate().unwrap();
        let key_enc = key.to_pkcs8();
        let key_enc = key_enc.as_ref();

        let aws = Ed25519KeyPair::from_pkcs8(key_enc)
            .expect("aws-lc-rs rejected an ed25519 key we generated");
        assert_eq!(
            aws.to_pkcs8().unwrap().as_ref(),
            key_enc,
            "aws-lc-rs varied our ed25519 key encoding"
        );
    }
}

proptest! {
    #[test]
    fn hashes_match_aws_lc_rs(
        message in vec(any::<u8>(), 0..1024),
        split in any::<prop::sample::Index>(),
    ) {
        // Two updates split anywhere exercise the partial-block buffering.
        let split = split.index(message.len() + 1);
        for (ours, theirs) in [
            (&rind::digest::legacy::SHA1, &digest::SHA1_FOR_LEGACY_USE_ONLY),
            (&rind::digest::SHA256, &digest::SHA256),
            (&rind::digest::SHA384, &digest::SHA384),
            (&rind::digest::SHA512, &digest::SHA512),
            (&rind::digest::SHA512_256, &digest::SHA512_256),
        ] {
            let mut ctx = rind::digest::Context::new(ours);
            ctx.update(&message[..split]);
            ctx.update(&message[split..]);
            let (got, wanted) = (ctx.finish(), digest::digest(theirs, &message));
            prop_assert_eq!(got.as_ref(), wanted.as_ref());
        }
    }

    #[test]
    fn hmac_matches_aws_lc_rs(
        // Up to 300 bytes spans keys below, at, and above both block sizes (64 and 128).
        key in vec(any::<u8>(), 0..300),
        message in vec(any::<u8>(), 0..1024),
        split in any::<prop::sample::Index>(),
    ) {
        let split = split.index(message.len() + 1);
        for (ours, theirs) in [
            (&rind::hmac::legacy::HMAC_SHA1, hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY),
            (&rind::hmac::HMAC_SHA256, hmac::HMAC_SHA256),
            (&rind::hmac::HMAC_SHA384, hmac::HMAC_SHA384),
            (&rind::hmac::HMAC_SHA512, hmac::HMAC_SHA512),
        ] {
            let ours = rind::hmac::Key::new(ours, &key);
            let mut ctx = rind::hmac::Context::with_key(&ours);
            ctx.update(&message[..split]);
            ctx.update(&message[split..]);
            let wanted = hmac::sign(&hmac::Key::new(theirs, &key), &message);
            let got = ctx.sign();
            prop_assert_eq!(got.as_ref(), wanted.as_ref());
            prop_assert_eq!(rind::hmac::verify(&ours, &message, wanted.as_ref()), Ok(()));
        }
    }

    #[test]
    fn slice_comparison_matches_aws_lc_rs(
        a in vec(any::<u8>(), 0..64),
        other in vec(any::<u8>(), 0..64),
        flip in any::<prop::sample::Index>(),
    ) {
        let mut flipped = a.clone();
        if !flipped.is_empty() {
            flipped[flip.index(a.len())] ^= 1;
        }
        for b in [&a, &flipped, &other] {
            let ours = rind::constant_time::verify(&a, b);
            let theirs = aws_lc_rs::constant_time::verify_slices_are_equal(&a, b);
            prop_assert_eq!(ours.is_ok(), theirs.is_ok());
            let wanted = if a.len() != b.len() {
                Err(rind::Error::WrongLength)
            } else if a != *b {
                Err(rind::Error::NotEqual)
            } else {
                Ok(())
            };
            prop_assert_eq!(ours, wanted);
        }
    }
}

mod cipher {
    use aws_lc_rs::aead::{Aad, CHACHA20_POLY1305, LessSafeKey, Nonce, UnboundKey, quic};
    use aws_lc_rs::cipher::{AES_128, AES_256, EncryptingKey, EncryptionContext, UnboundCipherKey};
    use proptest::prelude::*;
    use rind::Error;
    use rind::cipher::{self, Aes, AesCtr, ChaCha20};

    fn aes_key() -> impl Strategy<Value = Vec<u8>> {
        prop_oneof![
            prop::collection::vec(any::<u8>(), 16),
            prop::collection::vec(any::<u8>(), 32)
        ]
    }

    fn rind_aes_algorithm(key: &[u8]) -> &'static cipher::Algorithm {
        if key.len() == 16 {
            &cipher::AES_128
        } else {
            &cipher::AES_256
        }
    }

    fn aws_aes_key(key: &[u8]) -> UnboundCipherKey {
        let alg = if key.len() == 16 { &AES_128 } else { &AES_256 };
        UnboundCipherKey::new(alg, key).unwrap()
    }

    // Counters near the top of the range exercise the wrap refusal.
    fn counter() -> impl Strategy<Value = u32> {
        prop_oneof![any::<u32>(), (u32::MAX - 80)..=u32::MAX]
    }

    proptest! {
        #[test]
        fn aes_block(key in aes_key(), block in any::<[u8; 16]>()) {
            let mut ours = block;
            Aes::new(rind_aes_algorithm(&key), &key).unwrap().encrypt_block(&mut ours);

            let mut theirs = block;
            EncryptingKey::ecb(aws_aes_key(&key))
                .unwrap()
                .less_safe_encrypt(&mut theirs, EncryptionContext::None)
                .unwrap();
            prop_assert_eq!(ours, theirs);
        }

        #[test]
        fn aes_ctr(
            key in aes_key(),
            nonce in any::<[u8; 12]>(),
            counter in counter(),
            msg in prop::collection::vec(any::<u8>(), 0..1100),
        ) {
            let mut ours = msg.clone();
            let result = AesCtr::new(rind_aes_algorithm(&key), &key)
                .unwrap()
                .apply_keystream(&nonce, counter, &mut ours);

            // aws-lc-rs carries into the nonce where we refuse, so compare only
            // what we accept.
            let blocks = msg.len().div_ceil(16) as u64;
            if u64::from(counter) + blocks > 1 << 32 {
                prop_assert_eq!(result, Err(Error::WrongLength));
                prop_assert_eq!(ours, msg);
                return Ok(());
            }
            result.unwrap();

            let mut iv = [0u8; 16];
            iv[..12].copy_from_slice(&nonce);
            iv[12..].copy_from_slice(&counter.to_be_bytes());
            let mut theirs = msg.clone();
            if !theirs.is_empty() {
                EncryptingKey::ctr(aws_aes_key(&key))
                    .unwrap()
                    .less_safe_encrypt(&mut theirs, EncryptionContext::Iv128(iv.into()))
                    .unwrap();
            }
            prop_assert_eq!(ours, theirs);
        }

        #[test]
        fn quic_header_protection_mask(
            algorithm in 0..3usize,
            key in any::<[u8; 32]>(),
            sample in any::<[u8; 16]>(),
        ) {
            use rind::aead::quic as ours;
            let (algorithm, theirs) = [
                (&ours::AES_128, &quic::AES_128),
                (&ours::AES_256, &quic::AES_256),
                (&ours::CHACHA20, &quic::CHACHA20),
            ][algorithm];
            let key = &key[..algorithm.key_len()];

            let mask = ours::HeaderProtectionKey::new(algorithm, key).unwrap().mask(&sample);
            let wanted = quic::HeaderProtectionKey::new(theirs, key)
                .unwrap()
                .new_mask(&sample)
                .unwrap();
            prop_assert_eq!(mask, wanted);
        }

        // ChaCha20-Poly1305's ciphertext is the plaintext XORed with the
        // keystream from block 1, which checks long, ragged outputs.
        #[test]
        fn chacha20_keystream(
            key in any::<[u8; 32]>(),
            nonce in any::<[u8; 12]>(),
            msg in prop::collection::vec(any::<u8>(), 0..1100),
        ) {
            let mut ours = msg.clone();
            ChaCha20::new(key).apply_keystream(&nonce, 1, &mut ours).unwrap();

            let mut theirs = msg.clone();
            let _tag = LessSafeKey::new(UnboundKey::new(&CHACHA20_POLY1305, &key).unwrap())
                .seal_in_place_separate_tag(
                    Nonce::assume_unique_for_key(nonce),
                    Aad::empty(),
                    &mut theirs,
                )
                .unwrap();
            prop_assert_eq!(ours, theirs);
        }
    }
}

mod hkdf {
    use aws_lc_rs::{aead as their_aead, hkdf as theirs, hmac as their_hmac};
    use proptest::collection::vec;
    use proptest::prelude::*;
    use rind::{Error, aead, hkdf, hmac};

    struct Len(usize);

    impl theirs::KeyType for Len {
        fn len(&self) -> usize {
            self.0
        }
    }

    fn algorithms() -> [(&'static hkdf::Algorithm, theirs::Algorithm, usize); 4] {
        [
            (
                &hkdf::legacy::HKDF_SHA1,
                theirs::HKDF_SHA1_FOR_LEGACY_USE_ONLY,
                20,
            ),
            (&hkdf::HKDF_SHA256, theirs::HKDF_SHA256, 32),
            (&hkdf::HKDF_SHA384, theirs::HKDF_SHA384, 48),
            (&hkdf::HKDF_SHA512, theirs::HKDF_SHA512, 64),
        ]
    }

    // Salts either side of both block sizes (64 and 128), info split into
    // parts, and lengths up to a few blocks or either side of each hash's
    // 255-block limit.
    proptest! {
        #[test]
        fn matches_aws_lc_rs(
            algorithm in 0..4usize,
            salt in vec(any::<u8>(), 0..200),
            ikm in vec(any::<u8>(), 0..200),
            info in vec(vec(any::<u8>(), 0..100), 0..4),
            len in 0..200usize,
            at_limit in any::<bool>(),
        ) {
            let (ours, their_alg, hash_len) = algorithms()[algorithm];
            let len = match at_limit {
                true => 255 * hash_len + len - 100,
                false => len,
            };
            let info: Vec<&[u8]> = info.iter().map(Vec::as_slice).collect();

            let mut ours_out = vec![0u8; len];
            let prk = hkdf::Salt::new(ours, &salt).extract(&ikm);
            let result = prk.expand(&info, len).fill(&mut ours_out);

            let prk = theirs::Salt::new(their_alg, &salt).extract(&ikm);
            match prk.expand(&info, Len(len)) {
                Ok(okm) => {
                    result.unwrap();
                    let mut theirs_out = vec![0u8; len];
                    okm.fill(&mut theirs_out).unwrap();
                    prop_assert_eq!(ours_out, theirs_out);
                }
                Err(_) => {
                    prop_assert_eq!(result, Err(Error::WrongLength));
                    prop_assert!(ours_out.iter().all(|b| *b == 0));
                }
            }
        }

        // Keys built straight from an `Okm` match aws-lc-rs's conversions,
        // including keys longer than the PRK's hash output.
        #[test]
        fn keys(
            algorithm in 0..4usize,
            ikm in vec(any::<u8>(), 0..100),
            info in vec(vec(any::<u8>(), 0..50), 0..3),
            msg in vec(any::<u8>(), 0..100),
        ) {
            let (ours_prk_alg, theirs_prk_alg, _) = algorithms()[algorithm];
            let info: Vec<&[u8]> = info.iter().map(Vec::as_slice).collect();
            let ours = hkdf::Salt::new(ours_prk_alg, b"salt").extract(&ikm);
            let theirs = theirs::Salt::new(theirs_prk_alg, b"salt").extract(&ikm);

            for (ours_alg, theirs_alg) in [
                (&aead::AES_128_GCM, &their_aead::AES_128_GCM),
                (&aead::AES_256_GCM, &their_aead::AES_256_GCM),
                (&aead::CHACHA20_POLY1305, &their_aead::CHACHA20_POLY1305),
            ] {
                let ours_key = aead::Key::from(ours.expand(&info, ours_alg));
                let mut ours_sealed = msg.clone();
                ours_key
                    .seal_in_place_append_tag(
                        aead::Nonce::assume_unique_for_key([0; 12]),
                        &[],
                        &mut ours_sealed,
                    )
                    .unwrap();

                let theirs_key = their_aead::LessSafeKey::new(their_aead::UnboundKey::from(
                    theirs.expand(&info, theirs_alg).unwrap(),
                ));
                let mut theirs_sealed = msg.clone();
                theirs_key
                    .seal_in_place_append_tag(
                        their_aead::Nonce::assume_unique_for_key([0; 12]),
                        their_aead::Aad::empty(),
                        &mut theirs_sealed,
                    )
                    .unwrap();
                prop_assert_eq!(ours_sealed, theirs_sealed);
            }

            for (ours_alg, theirs_alg) in [
                (&hmac::legacy::HMAC_SHA1, their_hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY),
                (&hmac::HMAC_SHA256, their_hmac::HMAC_SHA256),
                (&hmac::HMAC_SHA384, their_hmac::HMAC_SHA384),
                (&hmac::HMAC_SHA512, their_hmac::HMAC_SHA512),
            ] {
                let ours_key = hmac::Key::from(ours.expand(&info, ours_alg));
                let theirs_key = their_hmac::Key::from(theirs.expand(&info, theirs_alg).unwrap());
                let ours_tag = hmac::sign(&ours_key, &msg);
                let theirs_tag = their_hmac::sign(&theirs_key, &msg);
                prop_assert_eq!(ours_tag.as_ref(), theirs_tag.as_ref());
            }
        }
    }
}

mod pbkdf2 {
    use core::num::NonZeroU32;

    use aws_lc_rs::pbkdf2 as theirs;
    use proptest::collection::vec;
    use proptest::prelude::*;
    use rind::{Error, pbkdf2};

    // Passwords either side of both block sizes (64 and 128), and keys of
    // several blocks with a partial last one.
    proptest! {
        #[test]
        fn matches_aws_lc_rs(
            password in vec(any::<u8>(), 0..300),
            salt in vec(any::<u8>(), 0..200),
            iterations in 1..20u32,
            len in 1..200usize,
        ) {
            let iterations = NonZeroU32::new(iterations).unwrap();
            for (ours, theirs, hash_len) in [
                (&pbkdf2::legacy::PBKDF2_HMAC_SHA1, theirs::PBKDF2_HMAC_SHA1, 20),
                (&pbkdf2::PBKDF2_HMAC_SHA256, theirs::PBKDF2_HMAC_SHA256, 32),
                (&pbkdf2::PBKDF2_HMAC_SHA384, theirs::PBKDF2_HMAC_SHA384, 48),
                (&pbkdf2::PBKDF2_HMAC_SHA512, theirs::PBKDF2_HMAC_SHA512, 64),
            ] {
                let mut wanted = vec![0u8; len];
                theirs::derive(theirs, iterations, &salt, &password, &mut wanted);

                let secret = pbkdf2::Secret::new(ours, &password);
                let mut got = vec![0u8; len];
                secret.derive(iterations, &salt, &mut got).unwrap();
                prop_assert_eq!(&got, &wanted);
                // Unlike aws-lc-rs, rind refuses to verify a key shorter than the HMAC output.
                let verified = match len < hash_len {
                    true => Err(Error::WrongLength),
                    false => Ok(()),
                };
                prop_assert_eq!(secret.verify(iterations, &salt, &wanted), verified);
            }
        }
    }
}

mod aead {
    use aws_lc_rs::aead as theirs;
    use proptest::collection::vec;
    use proptest::prelude::*;
    use proptest::sample::Index;
    use rind::Error;
    use rind::aead::{AES_128_GCM, AES_256_GCM, Algorithm, CHACHA20_POLY1305, Key, Nonce};

    /// Seals on both sides and compares, then opens aws-lc-rs's output,
    /// first with one bit of its ciphertext or tag flipped if `flip` is set.
    fn check(
        ours: &'static Algorithm,
        theirs: &'static theirs::Algorithm,
        key: &[u8],
        nonce: [u8; 12],
        aad: &[u8],
        msg: &[u8],
        flip: Option<Index>,
    ) -> Result<(), TestCaseError> {
        let ours = Key::new(ours, key).unwrap();
        let mut ours_sealed = msg.to_vec();
        ours.seal_in_place_append_tag(Nonce::assume_unique_for_key(nonce), aad, &mut ours_sealed)
            .unwrap();

        let mut theirs_sealed = msg.to_vec();
        theirs::LessSafeKey::new(theirs::UnboundKey::new(theirs, key).unwrap())
            .seal_in_place_append_tag(
                theirs::Nonce::assume_unique_for_key(nonce),
                theirs::Aad::from(aad),
                &mut theirs_sealed,
            )
            .unwrap();
        prop_assert_eq!(&ours_sealed, &theirs_sealed);

        if let Some(flip) = flip {
            let index = flip.index(theirs_sealed.len());
            theirs_sealed[index] ^= 1;
        }
        let result = ours
            .open_in_place(Nonce::assume_unique_for_key(nonce), aad, &mut theirs_sealed)
            .map(|plain| plain.to_vec());
        if flip.is_some() {
            prop_assert_eq!(result, Err(Error::DecryptFailed));
        } else {
            prop_assert_eq!(result, Ok(msg.to_vec()));
        }
        Ok(())
    }

    // Every message and AAD length to 32 blocks, each with every partial
    // tail, so each path through the aarch64 kernels runs, the eight-way
    // loop's repeat included, and so does every tail after x86_64's 128- and
    // 256-byte chunks. Then every message length across x86_64's switch to
    // BoringSSL's 512-bit kernel at 2048 bytes, through every tail after its
    // first chunk past it. They work in place, which a block stored before it
    // is loaded would break.
    #[test]
    fn aes_gcm_every_length() {
        let msg: Vec<u8> = (0..2048 + 256 + 15).map(|i| (i * 7 + 3) as u8).collect();
        for (ours, theirs, key) in [
            (&AES_128_GCM, &theirs::AES_128_GCM, &[1u8; 16][..]),
            (&AES_256_GCM, &theirs::AES_256_GCM, &[2u8; 32][..]),
        ] {
            for len in 0..=32 * 16 + 15 {
                check(ours, theirs, key, [3; 12], b"aad", &msg[..len], None).unwrap();
                check(ours, theirs, key, [3; 12], &msg[..len], b"msg", None).unwrap();
            }
            for len in 2048 - 16..=msg.len() {
                check(ours, theirs, key, [3; 12], b"aad", &msg[..len], None).unwrap();
            }
        }
    }

    // Messages and AAD span several blocks with ragged tails.
    proptest! {
        #[test]
        fn aes_gcm(
            key in prop_oneof![vec(any::<u8>(), 16), vec(any::<u8>(), 32)],
            nonce in any::<[u8; 12]>(),
            aad in vec(any::<u8>(), 0..100),
            msg in vec(any::<u8>(), 0..1100),
            flip in any::<Option<Index>>(),
        ) {
            let (ours, theirs) = if key.len() == 16 {
                (&AES_128_GCM, &theirs::AES_128_GCM)
            } else {
                (&AES_256_GCM, &theirs::AES_256_GCM)
            };
            check(ours, theirs, &key, nonce, &aad, &msg, flip)?;
        }

        #[test]
        fn chacha20_poly1305(
            key in any::<[u8; 32]>(),
            nonce in any::<[u8; 12]>(),
            aad in vec(any::<u8>(), 0..100),
            msg in vec(any::<u8>(), 0..1100),
            flip in any::<Option<Index>>(),
        ) {
            check(&CHACHA20_POLY1305, &theirs::CHACHA20_POLY1305, &key, nonce, &aad, &msg, flip)?;
        }
    }
}

/// ECDSA and ECDH on one curve: aws-lc-rs and rind accept each other's keys,
/// signatures, and public keys.
macro_rules! ec_crosschecks {
    ($curve:ident, $ecdh:ident, $fixed_signing:ident, $fixed:ident, $asn1_signing:ident, $asn1:ident) => {
        mod $curve {
            use aws_lc_rs::agreement::{self, $ecdh, EphemeralPrivateKey};
            use aws_lc_rs::encoding::{AsBigEndian, AsDer};
            use aws_lc_rs::rand::SystemRandom;
            use aws_lc_rs::signature::{
                $asn1, $asn1_signing, $fixed, $fixed_signing, EcdsaKeyPair, KeyPair,
                UnparsedPublicKey,
            };
            use proptest::collection::vec;
            use proptest::prelude::*;
            use rind::signature::{self, sign, verify};

            // Each case generates keys on both sides, which is slow under emulation.
            proptest! {
                #![proptest_config(ProptestConfig::with_cases(32))]

                #[test]
                fn ecdsa(message in vec(any::<u8>(), 0..300)) {
                    // aws-lc-rs accepts our key and derives the same public
                    // key, encodings, and scalar.
                    let ours = signature::EcdsaKeyPair::generate(&sign::$fixed).unwrap();
                    let encoded = ours.public_key();
                    let public = encoded.as_ref();
                    let theirs_from_ours = EcdsaKeyPair::from_pkcs8(
                        &$fixed_signing,
                        ours.to_pkcs8().as_ref(),
                    )
                    .expect("aws-lc-rs rejected a key we generated");
                    prop_assert_eq!(theirs_from_ours.public_key().as_ref(), public);
                    let spki = theirs_from_ours.public_key().as_der().unwrap();
                    let ours_spki = ours.to_spki();
                    prop_assert_eq!(spki.as_ref(), ours_spki.as_ref());
                    let scalar = theirs_from_ours.private_key().as_be_bytes().unwrap();

                    // We load its scalar and point as the same key, and refuse
                    // the scalar with another key's point.
                    let reloaded = signature::EcdsaKeyPair::from_private_key_and_public_key(
                        &sign::$asn1,
                        scalar.as_ref(),
                        public,
                    )
                    .unwrap();
                    let (reloaded_pkcs8, ours_pkcs8) = (reloaded.to_pkcs8(), ours.to_pkcs8());
                    prop_assert_eq!(reloaded_pkcs8.as_ref(), ours_pkcs8.as_ref());
                    let other = EcdsaKeyPair::generate(&$fixed_signing).unwrap();
                    prop_assert!(signature::EcdsaKeyPair::from_private_key_and_public_key(
                        &sign::$asn1,
                        scalar.as_ref(),
                        other.public_key().as_ref(),
                    )
                    .is_err());

                    // It verifies our signatures, in both encodings.
                    let theirs_verifier = |alg| UnparsedPublicKey::new(alg, public);
                    let signature = ours.sign(&message).unwrap();
                    theirs_verifier(&$fixed).verify(&message, signature.as_ref()).unwrap();
                    let signature = reloaded.sign(&message).unwrap();
                    theirs_verifier(&$asn1).verify(&message, signature.as_ref()).unwrap();

                    // We verify its signatures, in both encodings, and refuse
                    // one over another message.
                    for (signing, ours_verification) in [
                        (&$fixed_signing, &verify::$fixed),
                        (&$asn1_signing, &verify::$asn1),
                    ] {
                        let theirs = EcdsaKeyPair::generate(signing).unwrap();
                        let signature = theirs.sign(&SystemRandom::new(), &message).unwrap();
                        let verifier =
                            signature::PublicKey::new(ours_verification, theirs.public_key().as_ref())
                                .unwrap();
                        verifier.verify(&message, signature.as_ref()).unwrap();
                        prop_assert!(
                            verifier.verify(&[&message[..], b"!"].concat(), signature.as_ref()).is_err()
                        );
                    }
                }

                #[test]
                fn ecdh(_case in any::<u8>()) {
                    let ours = rind::agreement::PrivateKey::generate(&rind::agreement::$ecdh)
                        .unwrap();
                    let ours_public = ours.public_key();
                    let theirs = EphemeralPrivateKey::generate(&$ecdh, &SystemRandom::new()).unwrap();
                    let theirs_public = theirs.compute_public_key().unwrap();

                    let ours_secret = ours.agree(theirs_public.as_ref()).unwrap();
                    let theirs_secret = agreement::agree_ephemeral(
                        theirs,
                        agreement::UnparsedPublicKey::new(&$ecdh, ours_public.as_ref()),
                        (),
                        |secret| Ok(secret.to_vec()),
                    )
                    .unwrap();
                    prop_assert_eq!(ours_secret.as_ref(), &theirs_secret[..]);
                }
            }
        }
    };
}

ec_crosschecks!(
    p256,
    ECDH_P256,
    ECDSA_P256_SHA256_FIXED_SIGNING,
    ECDSA_P256_SHA256_FIXED,
    ECDSA_P256_SHA256_ASN1_SIGNING,
    ECDSA_P256_SHA256_ASN1
);

ec_crosschecks!(
    p384,
    ECDH_P384,
    ECDSA_P384_SHA384_FIXED_SIGNING,
    ECDSA_P384_SHA384_FIXED,
    ECDSA_P384_SHA384_ASN1_SIGNING,
    ECDSA_P384_SHA384_ASN1
);

ec_crosschecks!(
    p521,
    ECDH_P521,
    ECDSA_P521_SHA512_FIXED_SIGNING,
    ECDSA_P521_SHA512_FIXED,
    ECDSA_P521_SHA512_ASN1_SIGNING,
    ECDSA_P521_SHA512_ASN1
);

mod ed25519 {
    use aws_lc_rs::encoding::AsDer;
    use aws_lc_rs::signature::{ED25519, Ed25519KeyPair, KeyPair, UnparsedPublicKey};
    use proptest::collection::vec;
    use proptest::prelude::*;
    use proptest::sample::Index;
    use rind::signature;

    proptest! {
        #[test]
        fn sign_verify(
            seed in any::<[u8; 32]>(),
            message in vec(any::<u8>(), 0..300),
            flip in any::<Option<Index>>(),
        ) {
            // Signing is deterministic, so one seed gives both sides the same
            // public key, encoding, and signatures; loading ours checks the
            // public key matches theirs.
            let theirs = Ed25519KeyPair::from_seed_unchecked(&seed).unwrap();
            let public = theirs.public_key().as_ref();
            let ours = signature::Ed25519KeyPair::from_seed_and_public_key(&seed, public).unwrap();
            let spki = theirs.public_key().as_der().unwrap();
            let ours_spki = ours.to_spki();
            prop_assert_eq!(ours_spki.as_ref(), spki.as_ref());
            let (ours_pkcs8, theirs_pkcs8) = (ours.to_pkcs8(), theirs.to_pkcs8().unwrap());
            prop_assert_eq!(ours_pkcs8.as_ref(), theirs_pkcs8.as_ref());
            let signature = ours.sign(&message);
            let theirs_signature = theirs.sign(&message);
            prop_assert_eq!(signature.as_ref(), theirs_signature.as_ref());

            // Both verify it, and refuse it with any one bit flipped.
            let mut signature = signature.as_ref().to_vec();
            if let Some(flip) = flip {
                let bit = flip.index(signature.len() * 8);
                signature[bit / 8] ^= 1 << (bit % 8);
            }
            let ours_result = signature::PublicKey::new(&signature::verify::ED25519, public)
                .unwrap()
                .verify(&message, &signature);
            let theirs_result = UnparsedPublicKey::new(&ED25519, public).verify(&message, &signature);
            prop_assert_eq!(ours_result.is_ok(), flip.is_none());
            prop_assert_eq!(theirs_result.is_ok(), flip.is_none());
        }

        #[test]
        fn seed_and_public_key(seed in any::<[u8; 32]>(), other in any::<[u8; 32]>()) {
            // Both load a seed with its public key, and refuse it with another's.
            let public = Ed25519KeyPair::from_seed_unchecked(&seed).unwrap();
            let public = public.public_key().as_ref();
            let wrong = Ed25519KeyPair::from_seed_unchecked(&other).unwrap();
            let wrong = wrong.public_key().as_ref();

            signature::Ed25519KeyPair::from_seed_and_public_key(&seed, public).unwrap();
            Ed25519KeyPair::from_seed_and_public_key(&seed, public).unwrap();
            prop_assert_eq!(
                signature::Ed25519KeyPair::from_seed_and_public_key(&seed, wrong).is_ok(),
                seed == other
            );
            prop_assert_eq!(
                Ed25519KeyPair::from_seed_and_public_key(&seed, wrong).is_ok(),
                seed == other
            );
        }
    }
}

mod rsa {
    use std::sync::LazyLock;

    use aws_lc_rs::encoding::AsDer;
    use aws_lc_rs::rand::SystemRandom;
    use aws_lc_rs::rsa::{KeyPair, KeySize};
    use aws_lc_rs::signature::{self, KeyPair as _, UnparsedPublicKey};
    use proptest::collection::vec;
    use proptest::prelude::*;
    use rind::Error;
    use rind::signature::{RsaKeyPair, sign, verify};

    /// One padding and hash: each side's signing and verification constants.
    struct Scheme {
        ours_sign: &'static rind::signature::RsaSigningAlgorithm,
        ours_verify: &'static rind::signature::RsaVerificationAlgorithm,
        theirs_sign: &'static signature::RsaSignatureEncoding,
        theirs_verify: &'static signature::RsaParameters,
        /// PKCS#1 v1.5 signatures have no randomness, so both sides must agree.
        deterministic: bool,
    }

    const SCHEMES: [Scheme; 6] = [
        Scheme {
            ours_sign: &sign::RSA_PKCS1_SHA256,
            ours_verify: &verify::RSA_PKCS1_SHA256,
            theirs_sign: &signature::RSA_PKCS1_SHA256,
            theirs_verify: &signature::RSA_PKCS1_2048_8192_SHA256,
            deterministic: true,
        },
        Scheme {
            ours_sign: &sign::RSA_PKCS1_SHA384,
            ours_verify: &verify::RSA_PKCS1_SHA384,
            theirs_sign: &signature::RSA_PKCS1_SHA384,
            theirs_verify: &signature::RSA_PKCS1_2048_8192_SHA384,
            deterministic: true,
        },
        Scheme {
            ours_sign: &sign::RSA_PKCS1_SHA512,
            ours_verify: &verify::RSA_PKCS1_SHA512,
            theirs_sign: &signature::RSA_PKCS1_SHA512,
            theirs_verify: &signature::RSA_PKCS1_2048_8192_SHA512,
            deterministic: true,
        },
        Scheme {
            ours_sign: &sign::RSA_PSS_SHA256,
            ours_verify: &verify::RSA_PSS_SHA256,
            theirs_sign: &signature::RSA_PSS_SHA256,
            theirs_verify: &signature::RSA_PSS_2048_8192_SHA256,
            deterministic: false,
        },
        Scheme {
            ours_sign: &sign::RSA_PSS_SHA384,
            ours_verify: &verify::RSA_PSS_SHA384,
            theirs_sign: &signature::RSA_PSS_SHA384,
            theirs_verify: &signature::RSA_PSS_2048_8192_SHA384,
            deterministic: false,
        },
        Scheme {
            ours_sign: &sign::RSA_PSS_SHA512,
            ours_verify: &verify::RSA_PSS_SHA512,
            theirs_sign: &signature::RSA_PSS_SHA512,
            theirs_verify: &signature::RSA_PSS_2048_8192_SHA512,
            deterministic: false,
        },
    ];

    // Loaded by both: one key generated by aws-lc-rs (`check_key_generation`
    // covers the reverse), and OpenSSL keys aws-lc-rs cannot generate: moduli
    // that are not a whole number of words, and a 33-bit public exponent,
    // 2^32 + 1. At 2049 bits PSS's encoded message is a byte shorter than the
    // modulus, at 2050 bits it masks seven top bits, and 2056 bits is a whole
    // number of bytes. Key generation is slow under emulation, so there is
    // one of each.
    static THEIRS: LazyLock<[KeyPair; 5]> = LazyLock::new(|| {
        [
            KeyPair::generate(KeySize::Rsa2048).unwrap(),
            KeyPair::from_pkcs8(include_bytes!("../src/high/rsa/rsa2049.pkcs8.der")).unwrap(),
            KeyPair::from_pkcs8(include_bytes!("../src/high/rsa/rsa2050.pkcs8.der")).unwrap(),
            KeyPair::from_pkcs8(include_bytes!("../src/high/rsa/rsa2056.pkcs8.der")).unwrap(),
            KeyPair::from_pkcs8(include_bytes!("../src/high/rsa/rsa2048-e33.pkcs8.der")).unwrap(),
        ]
    });

    // Each case makes a dozen private-key operations per key, which are slow
    // under emulation.
    proptest! {
        #![proptest_config(ProptestConfig::with_cases(8))]

        #[test]
        fn sign_verify(message in vec(any::<u8>(), 0..300)) {
            for theirs in &*THEIRS {
                let ours = RsaKeyPair::from_pkcs8(theirs.as_der().unwrap().as_ref()).unwrap();
                let public = theirs.public_key().as_ref();
                let spki = theirs.public_key().as_der().unwrap();
                let ours_spki = ours.to_spki();
                prop_assert_eq!(ours_spki.as_ref(), spki.as_ref());
                let rng = SystemRandom::new();
                let len = theirs.public_modulus_len();

                for scheme in &SCHEMES {
                    let ours_public = ours.public_key(scheme.ours_sign);
                    prop_assert_eq!(ours_public.as_ref(), public);

                    // It verifies our signature.
                    let ours_signature = ours.sign(scheme.ours_sign, &message).unwrap();
                    let ours_signature = ours_signature.as_ref();
                    prop_assert_eq!(ours_signature.len(), len);
                    UnparsedPublicKey::new(scheme.theirs_verify, public)
                        .verify(&message, ours_signature)
                        .unwrap();

                    // We verify its signature, and refuse it over another message.
                    let mut theirs_signature = vec![0u8; len];
                    theirs
                        .sign(scheme.theirs_sign, &rng, &message, &mut theirs_signature)
                        .unwrap();
                    if scheme.deterministic {
                        prop_assert_eq!(ours_signature, &theirs_signature[..]);
                    }
                    let verifier = rind::signature::PublicKey::new(scheme.ours_verify, public).unwrap();
                    verifier.verify(&message, &theirs_signature).unwrap();
                    prop_assert_eq!(
                        verifier.verify(&[&message[..], b"!"].concat(), &theirs_signature),
                        Err(Error::BadSignature)
                    );
                }
            }
        }
    }

    // Every verification algorithm, beside aws-lc-rs's of the same name.
    const VERIFICATION: [(
        &rind::signature::RsaVerificationAlgorithm,
        &signature::RsaParameters,
    ); 11] = [
        (
            &verify::legacy::RSA_PKCS1_1024_SHA1,
            &signature::RSA_PKCS1_1024_8192_SHA1_FOR_LEGACY_USE_ONLY,
        ),
        (
            &verify::legacy::RSA_PKCS1_1024_SHA256,
            &signature::RSA_PKCS1_1024_8192_SHA256_FOR_LEGACY_USE_ONLY,
        ),
        (
            &verify::legacy::RSA_PKCS1_1024_SHA512,
            &signature::RSA_PKCS1_1024_8192_SHA512_FOR_LEGACY_USE_ONLY,
        ),
        (
            &verify::legacy::RSA_PKCS1_SHA1,
            &signature::RSA_PKCS1_2048_8192_SHA1_FOR_LEGACY_USE_ONLY,
        ),
        (
            &verify::RSA_PKCS1_SHA256,
            &signature::RSA_PKCS1_2048_8192_SHA256,
        ),
        (
            &verify::RSA_PKCS1_SHA384,
            &signature::RSA_PKCS1_2048_8192_SHA384,
        ),
        (
            &verify::RSA_PKCS1_SHA512,
            &signature::RSA_PKCS1_2048_8192_SHA512,
        ),
        (
            &verify::legacy::RSA_PKCS1_3072_SHA384,
            &signature::RSA_PKCS1_3072_8192_SHA384,
        ),
        (
            &verify::RSA_PSS_SHA256,
            &signature::RSA_PSS_2048_8192_SHA256,
        ),
        (
            &verify::RSA_PSS_SHA384,
            &signature::RSA_PSS_2048_8192_SHA384,
        ),
        (
            &verify::RSA_PSS_SHA512,
            &signature::RSA_PSS_2048_8192_SHA512,
        ),
    ];

    /// Both accept and refuse the same signatures under every algorithm, for
    /// keys as DER or as components. aws-lc-rs signs neither SHA-1 nor
    /// 1024-bit keys, so the signatures are Wycheproof's.
    #[test]
    fn verification_agrees() {
        for file in [
            "rsa_pkcs1_1024_sig_gen_test.json",
            "rsa_pkcs1_2048_sig_gen_test.json",
        ] {
            let path = format!("../thirdparty/wycheproof/testvectors_v1/{file}");
            let tests: serde_json::Value =
                serde_json::from_reader(std::fs::File::open(path).unwrap()).unwrap();
            for group in tests["testGroups"].as_array().unwrap() {
                let hex = |value: &serde_json::Value| hex::decode(value.as_str().unwrap()).unwrap();
                let der = hex(&group["keyAsn"]);
                let modulus = hex(&group["privateKey"]["modulus"]);
                let e = hex(&group["privateKey"]["publicExponent"]);
                // A leading zero, as the DER sign byte leaves, is refused.
                let n = modulus.strip_prefix(&[0]).unwrap();

                for (i, test) in group["tests"].as_array().unwrap().iter().enumerate() {
                    let message = hex(&test["msg"]);
                    let signature = hex(&test["sig"]);
                    let other = [&message[..], b"!"].concat();
                    // Another message is refused alike, so checking it once
                    // per group keeps this fast under emulation.
                    let messages = match i {
                        0 => &[&message[..], &other][..],
                        _ => &[&message[..]],
                    };

                    for message in messages {
                        for (ours, theirs) in VERIFICATION {
                            let case = format!("{file} {i} {ours:?}");
                            for n in [n, &modulus] {
                                let ours = rind::signature::RsaPublicKeyComponents { n, e: &e }
                                    .to_public_key(ours)
                                    .and_then(|key| key.verify(message, &signature));
                                let theirs = signature::RsaPublicKeyComponents { n, e: &e }
                                    .verify(theirs, message, &signature);
                                assert_eq!(ours.is_ok(), theirs.is_ok(), "{case} {ours:?}");
                            }

                            let ours = rind::signature::PublicKey::new(ours, &der)
                                .and_then(|key| key.verify(message, &signature));
                            let theirs =
                                UnparsedPublicKey::new(theirs, &der).verify(message, &signature);
                            assert_eq!(ours.is_ok(), theirs.is_ok(), "{case} {ours:?}");
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn refuses_modulus_below_2048_bits() {
        let private = include_bytes!("../src/high/rsa/rsa2047.pkcs8.der");
        assert!(KeyPair::from_pkcs8(private).is_err());
        assert!(matches!(
            RsaKeyPair::from_pkcs8(private),
            Err(Error::KeyRejected(_))
        ));
        let public = include_bytes!("../src/high/rsa/rsa2047.pub.der");
        assert!(matches!(
            rind::signature::PublicKey::new(&verify::RSA_PKCS1_SHA256, public),
            Err(Error::KeyRejected(_))
        ));
    }

    /// An OpenSSL key with e = 2^33 + 1, just past the 33 bits both take, and
    /// its signature over "message", which OpenSSL verifies.
    #[test]
    fn refuses_exponent_over_33_bits() {
        let private = include_bytes!("../src/high/rsa/rsa2048-e34.pkcs8.der");
        assert!(KeyPair::from_pkcs8(private).is_err());
        assert!(matches!(
            RsaKeyPair::from_pkcs8(private),
            Err(Error::KeyRejected(_))
        ));
        let public = include_bytes!("../src/high/rsa/rsa2048-e34.pub.der");
        let signature = include_bytes!("../src/high/rsa/rsa2048-e34.sig");
        assert!(
            UnparsedPublicKey::new(&signature::RSA_PKCS1_2048_8192_SHA256, public)
                .verify(b"message", signature)
                .is_err()
        );
        assert!(matches!(
            rind::signature::PublicKey::new(&verify::RSA_PKCS1_SHA256, public),
            Err(Error::KeyRejected(_))
        ));
    }
}

mod mlkem768 {
    use aws_lc_rs::kem::{Ciphertext, DecapsulationKey, ML_KEM_768};
    use proptest::prelude::*;
    use rind::kem;

    // Each case generates a key, which is slow under emulation.
    proptest! {
        #![proptest_config(ProptestConfig::with_cases(32))]

        // aws-lc-rs decapsulates what we encapsulate to its key.
        #[test]
        fn encapsulated_by_ours(_case in any::<u8>()) {
            let theirs = DecapsulationKey::generate(&ML_KEM_768).unwrap();
            let theirs_public = theirs.encapsulation_key().unwrap().key_bytes().unwrap();
            let (ciphertext, secret) =
                kem::EncapsulationKey::new(&kem::ML_KEM_768, theirs_public.as_ref())
                    .unwrap()
                    .encapsulate()
                    .unwrap();
            let theirs_secret = theirs
                .decapsulate(Ciphertext::from(ciphertext.as_ref()))
                .unwrap();
            prop_assert_eq!(secret.as_ref(), theirs_secret.as_ref());
        }
    }
}
