#![no_main]

use libfuzzer_sys::{arbitrary, arbitrary::Arbitrary, fuzz_target};
use rind::aead::{Key, Nonce};

mod edit;

fuzz_target!(|input: (Operation, edit::Edit)| {
    let (op, edit) = input;
    let (ours, theirs, key, nonce, aad, plain) = match &op {
        Operation::ChaCha20Poly1305 {
            key,
            nonce,
            aad,
            plain,
        } => (
            &rind::aead::CHACHA20_POLY1305,
            &aws_lc_rs::aead::CHACHA20_POLY1305,
            &key[..],
            nonce,
            aad,
            plain,
        ),
        Operation::Aes128Gcm {
            key,
            nonce,
            aad,
            plain,
        } => (
            &rind::aead::AES_128_GCM,
            &aws_lc_rs::aead::AES_128_GCM,
            &key[..],
            nonce,
            aad,
            plain,
        ),
        Operation::Aes192Gcm {
            key,
            nonce,
            aad,
            plain,
        } => (
            &rind::aead::AES_192_GCM,
            &aws_lc_rs::aead::AES_192_GCM,
            &key[..],
            nonce,
            aad,
            plain,
        ),
        Operation::Aes256Gcm {
            key,
            nonce,
            aad,
            plain,
        } => (
            &rind::aead::AES_256_GCM,
            &aws_lc_rs::aead::AES_256_GCM,
            &key[..],
            nonce,
            aad,
            plain,
        ),
    };

    let right = baseline_encrypt(theirs, key, nonce, aad, plain);
    let k = Key::new(ours, key).unwrap();
    let left = {
        let mut cipher = plain.clone();
        let tag = k
            .seal_in_place_separate_tag(Nonce::assume_unique_for_key(*nonce), aad, &mut cipher)
            .unwrap();

        let mut roundtrip = cipher.clone();
        k.open_in_place_separate_tag(
            Nonce::assume_unique_for_key(*nonce),
            aad,
            tag,
            &mut roundtrip,
        )
        .unwrap();
        assert_eq!(&roundtrip, plain);
        (cipher, tag.as_ref().try_into().unwrap())
    };

    assert_eq!(left, right);

    // Both open the sealed message tampered with alike, and refuse it if
    // it changed.
    let (cipher, tag) = right;
    let mut sealed = [&cipher[..], &tag].concat();
    let changed = edit.apply(&mut sealed);
    let mut ours_sealed = sealed.clone();
    let ours_result = k
        .open_in_place(Nonce::assume_unique_for_key(*nonce), aad, &mut ours_sealed)
        .map(|plain| plain.to_vec());
    let theirs_result = baseline_decrypt(theirs, key, nonce, aad, sealed);
    assert_eq!(ours_result.as_ref().ok(), theirs_result.as_ref());
    assert_eq!(ours_result.is_err(), changed);
});

fn baseline_encrypt(
    alg: &'static aws_lc_rs::aead::Algorithm,
    key: &[u8],
    nonce: &[u8; 12],
    aad: &[u8],
    plain: &[u8],
) -> (Vec<u8>, [u8; 16]) {
    let k = aws_lc_rs::aead::LessSafeKey::new(aws_lc_rs::aead::UnboundKey::new(alg, key).unwrap());
    let mut cipher = plain.to_vec();
    let tag = k
        .seal_in_place_separate_tag(
            aws_lc_rs::aead::Nonce::assume_unique_for_key(*nonce),
            aws_lc_rs::aead::Aad::from(aad),
            &mut cipher,
        )
        .unwrap();

    let mut tag_array = [0u8; 16];
    tag_array.copy_from_slice(tag.as_ref());
    (cipher, tag_array)
}

fn baseline_decrypt(
    alg: &'static aws_lc_rs::aead::Algorithm,
    key: &[u8],
    nonce: &[u8; 12],
    aad: &[u8],
    mut sealed: Vec<u8>,
) -> Option<Vec<u8>> {
    let k = aws_lc_rs::aead::LessSafeKey::new(aws_lc_rs::aead::UnboundKey::new(alg, key).unwrap());
    k.open_in_place(
        aws_lc_rs::aead::Nonce::assume_unique_for_key(*nonce),
        aws_lc_rs::aead::Aad::from(aad),
        &mut sealed,
    )
    .ok()
    .map(|plain| plain.to_vec())
}

#[derive(Arbitrary, Debug)]
enum Operation {
    ChaCha20Poly1305 {
        key: [u8; 32],
        nonce: [u8; 12],
        aad: Vec<u8>,
        plain: Vec<u8>,
    },
    Aes128Gcm {
        key: [u8; 16],
        nonce: [u8; 12],
        aad: Vec<u8>,
        plain: Vec<u8>,
    },
    Aes256Gcm {
        key: [u8; 32],
        nonce: [u8; 12],
        aad: Vec<u8>,
        plain: Vec<u8>,
    },
    Aes192Gcm {
        key: [u8; 24],
        nonce: [u8; 12],
        aad: Vec<u8>,
        plain: Vec<u8>,
    },
}
