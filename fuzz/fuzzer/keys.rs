#![no_main]

//! Every public key loader against aws-lc-rs's: the first byte picks the
//! loader and the rest is its input. Both must accept and refuse alike, except
//! where an [`Expect`] names a difference by design, and every key rind loads
//! must re-encode to input both load again as the same key.

use aws_lc_rs::encoding::{AsBigEndian, AsDer};
use aws_lc_rs::signature::KeyPair as _;
use aws_lc_rs::{kem as their_kem, rsa as their_rsa, signature as theirs};
use libfuzzer_sys::fuzz_target;
use rind::kem as our_kem;
use rind::signature::{self as ours, sign, verify};

fuzz_target!(|data: &[u8]| {
    let Some((&loader, input)) = data.split_first() else {
        return;
    };
    match loader {
        0 => ecdsa_pkcs8(&P256, input),
        1 => ecdsa_pkcs8(&P384, input),
        2 => ecdsa_pkcs8(&P521, input),
        3 => ecdsa_sec1(&P256, input),
        4 => ecdsa_sec1(&P384, input),
        5 => ecdsa_sec1(&P521, input),
        6 => ecdsa_scalar(&P256, input),
        7 => ecdsa_scalar(&P384, input),
        8 => ecdsa_scalar(&P521, input),
        9 => ecdsa_public(&P256, input),
        10 => ecdsa_public(&P384, input),
        11 => ecdsa_public(&P521, input),
        12 => rsa_private(
            input,
            ours::RsaKeyPair::from_pkcs8,
            their_rsa::KeyPair::from_pkcs8,
        ),
        13 => rsa_private(
            input,
            ours::RsaKeyPair::from_pkcs1,
            their_rsa::KeyPair::from_der,
        ),
        14 => rsa_public(&RSA_1024, input),
        15 => rsa_public(&RSA_2048, input),
        16 => rsa_public(&RSA_3072, input),
        17 => rsa_components(&RSA_1024, input),
        18 => rsa_components(&RSA_2048, input),
        19 => rsa_components(&RSA_3072, input),
        20 => ed25519_pkcs8(input),
        21 => ed25519_seed(input),
        22 => ed25519_public(input),
        23 => mlkem_public(input),
        _ => {}
    }
});

/// One curve's algorithms on each side, and its scalar's length.
struct Curve {
    ours: &'static ours::EcdsaSigningAlgorithm,
    ours_verify: &'static ours::VerificationAlgorithm,
    theirs: &'static theirs::EcdsaSigningAlgorithm,
    theirs_verify: &'static theirs::EcdsaVerificationAlgorithm,
    scalar_len: usize,
}

const P256: Curve = Curve {
    ours: &sign::ECDSA_P256_SHA256_ASN1,
    ours_verify: &verify::ECDSA_P256_SHA256_ASN1,
    theirs: &theirs::ECDSA_P256_SHA256_ASN1_SIGNING,
    theirs_verify: &theirs::ECDSA_P256_SHA256_ASN1,
    scalar_len: 32,
};

const P384: Curve = Curve {
    ours: &sign::ECDSA_P384_SHA384_ASN1,
    ours_verify: &verify::ECDSA_P384_SHA384_ASN1,
    theirs: &theirs::ECDSA_P384_SHA384_ASN1_SIGNING,
    theirs_verify: &theirs::ECDSA_P384_SHA384_ASN1,
    scalar_len: 48,
};

const P521: Curve = Curve {
    ours: &sign::ECDSA_P521_SHA512_ASN1,
    ours_verify: &verify::ECDSA_P521_SHA512_ASN1,
    theirs: &theirs::ECDSA_P521_SHA512_ASN1_SIGNING,
    theirs_verify: &theirs::ECDSA_P521_SHA512_ASN1,
    scalar_len: 66,
};

/// An RSA verification algorithm on each side, and its smallest modulus.
struct Rsa {
    ours: &'static ours::RsaVerificationAlgorithm,
    theirs: &'static theirs::RsaParameters,
    min_bits: usize,
}

const RSA_1024: Rsa = Rsa {
    ours: &verify::legacy::RSA_PKCS1_1024_SHA256,
    theirs: &theirs::RSA_PKCS1_1024_8192_SHA256_FOR_LEGACY_USE_ONLY,
    min_bits: 1024,
};

const RSA_2048: Rsa = Rsa {
    ours: &verify::RSA_PKCS1_SHA256,
    theirs: &theirs::RSA_PKCS1_2048_8192_SHA256,
    min_bits: 2048,
};

const RSA_3072: Rsa = Rsa {
    ours: &verify::legacy::RSA_PKCS1_3072_SHA384,
    theirs: &theirs::RSA_PKCS1_3072_8192_SHA384,
    min_bits: 3072,
};

/// How rind's answer to an input may differ from aws-lc-rs's.
#[derive(Clone, Copy, PartialEq)]
enum Expect {
    /// Both take it or both refuse it.
    Agree,
    /// rind refuses it by design, though aws-lc-rs may take it.
    Refused,
    /// rind may refuse it where aws-lc-rs takes it, never the reverse.
    Stricter,
}

impl From<bool> for Expect {
    /// [`Expect::Refused`] if a difference by design applies, else
    /// [`Expect::Agree`].
    fn from(refused: bool) -> Self {
        match refused {
            true => Self::Refused,
            false => Self::Agree,
        }
    }
}

fn agree<A, B, E: std::fmt::Debug>(
    ours: &Result<A, rind::Error>,
    theirs: &Result<B, E>,
    expect: Expect,
) {
    let (ours, theirs) = (ours.as_ref().err(), theirs.as_ref().err());
    match expect {
        Expect::Agree => assert_eq!(
            ours.is_none(),
            theirs.is_none(),
            "rind: {ours:?}, aws-lc-rs: {theirs:?}"
        ),
        Expect::Refused => assert!(ours.is_some(), "rind took an input it refuses by design"),
        Expect::Stricter => assert!(
            ours.is_some() || theirs.is_none(),
            "rind took an input aws-lc-rs refused: {theirs:?}"
        ),
    }
}

/// The DER element starting `input`: its tag, its contents, and the bytes
/// after it.
fn element(input: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let (&tag, rest) = input.split_first()?;
    let (&first, rest) = rest.split_first()?;
    let (len, rest) = match first {
        0..=0x7f => (usize::from(first), rest),
        0x81..=0x84 => {
            let (len, rest) = rest.split_at_checked(usize::from(first & 0x7f))?;
            let len = len.iter().fold(0, |len, &b| len << 8 | usize::from(b));
            (len, rest)
        }
        _ => return None,
    };
    let (contents, rest) = rest.split_at_checked(len)?;
    Some((tag, contents, rest))
}

/// The tags and contents of the DER elements in `contents`, up to the first
/// that does not parse.
fn elements(mut contents: &[u8]) -> impl Iterator<Item = (u8, &[u8])> {
    std::iter::from_fn(move || {
        let (tag, inner, rest) = element(contents)?;
        contents = rest;
        Some((tag, inner))
    })
}

/// The contents of the sequence starting `input`.
fn sequence(input: &[u8]) -> Option<&[u8]> {
    element(input).and_then(|(tag, contents, _)| (tag == 0x30).then_some(contents))
}

/// Whether bytes follow the DER element starting `input`, which aws-lc-rs
/// ignores and rind refuses as malformed.
fn trailing(input: &[u8]) -> bool {
    element(input).is_some_and(|(_, _, rest)| !rest.is_empty())
}

/// Whether `input` is shaped like a `SubjectPublicKeyInfo`: a sequence whose
/// first element is a sequence, the algorithm identifier. aws-lc-rs takes one
/// wherever it takes a public key, and rind only the raw key.
fn spki(input: &[u8]) -> bool {
    sequence(input).is_some_and(|contents| contents.first() == Some(&0x30))
}

/// Whether `input` is a PKCS#8 version 2 document without a public key, which
/// aws-lc-rs takes for Ed25519. RFC 5958 sets version 2 only when the public
/// key is present.
fn v2_without_public_key(input: &[u8]) -> bool {
    let Some(contents) = sequence(input) else {
        return false;
    };
    let mut fields = elements(contents);
    fields.next() == Some((0x02, &[1][..])) && fields.all(|(tag, _)| tag != 0x81)
}

/// The `privateKey` of the PKCS#8 document `input`.
fn pkcs8_private_key(input: &[u8]) -> Option<&[u8]> {
    let (tag, private_key) = elements(sequence(input)?).nth(2)?;
    (tag == 0x04).then_some(private_key)
}

/// The public key of the SEC1 `ECPrivateKey` `input`.
fn sec1_public_key(input: &[u8]) -> Option<&[u8]> {
    let (_, field) = elements(sequence(input)?).find(|(tag, _)| *tag == 0xa1)?;
    let (tag, bits, _) = element(field)?;
    (tag == 0x03).then_some(bits)?.strip_prefix(&[0])
}

/// Whether `point` is in X9.62's hybrid form, which aws-lc-rs takes and rind
/// refuses everywhere: no consumer sends it.
fn hybrid(point: &[u8]) -> bool {
    matches!(point.first(), Some(6 | 7))
}

/// Splits `input` after a leading big-endian 16-bit length, for loaders
/// taking two values.
fn split(input: &[u8]) -> Option<(&[u8], &[u8])> {
    let (len, rest) = input.split_first_chunk::<2>()?;
    rest.split_at_checked(usize::from(u16::from_be_bytes(*len)))
}

fn ecdsa_pkcs8(curve: &Curve, input: &[u8]) {
    let ours = ours::EcdsaKeyPair::from_pkcs8(curve.ours, input);
    let theirs = theirs::EcdsaKeyPair::from_pkcs8(curve.theirs, input);
    let point = pkcs8_private_key(input).and_then(sec1_public_key);
    let refused = trailing(input) || point.is_some_and(hybrid);
    agree_ecdsa(curve, ours, theirs, refused.into());
}

fn ecdsa_sec1(curve: &Curve, input: &[u8]) {
    let ours = ours::EcdsaKeyPair::from_sec1(curve.ours, input);
    let theirs = theirs::EcdsaKeyPair::from_private_key_der(curve.theirs, input);
    // aws-lc-rs's loader also takes PKCS#8; rind's caller always knows which
    // of the two it holds.
    let pkcs8 = theirs::EcdsaKeyPair::from_pkcs8(curve.theirs, input).is_ok();
    let refused = pkcs8 || trailing(input) || sec1_public_key(input).is_some_and(hybrid);
    agree_ecdsa(curve, ours, theirs, refused.into());
}

fn ecdsa_scalar(curve: &Curve, input: &[u8]) {
    let Some((scalar, point)) = split(input) else {
        return;
    };
    let ours = ours::EcdsaKeyPair::from_private_key_and_public_key(curve.ours, scalar, point);
    let theirs = theirs::EcdsaKeyPair::from_private_key_and_public_key(curve.theirs, scalar, point);
    // aws-lc-rs takes leading zeros added or stripped, though its docs
    // require the curve's length.
    let refused = scalar.len() != curve.scalar_len || hybrid(point);
    agree_ecdsa(curve, ours, theirs, refused.into());
}

fn agree_ecdsa(
    curve: &Curve,
    ours: Result<ours::EcdsaKeyPair, rind::Error>,
    theirs: Result<theirs::EcdsaKeyPair, aws_lc_rs::error::KeyRejected>,
    expect: Expect,
) {
    agree(&ours, &theirs, expect);
    let Ok(ours) = ours else {
        return;
    };
    if let Ok(theirs) = &theirs {
        assert_eq!(ours.public_key().as_ref(), theirs.public_key().as_ref());
        let scalar = theirs.private_key().as_be_bytes().unwrap();
        assert_eq!(ours.to_scalar().as_ref(), scalar.as_ref());
    }

    // Each encoding loads again, on both sides, as the same key.
    let public = ours.public_key();
    let point = public.as_ref();
    let pkcs8 = ours.to_pkcs8();
    let again = ours::EcdsaKeyPair::from_pkcs8(curve.ours, pkcs8.as_ref()).unwrap();
    assert_eq!(again.public_key().as_ref(), point);
    let theirs = theirs::EcdsaKeyPair::from_pkcs8(curve.theirs, pkcs8.as_ref()).unwrap();
    assert_eq!(theirs.public_key().as_ref(), point);
    assert_eq!(
        ours.to_spki().as_ref(),
        theirs.public_key().as_der().unwrap().as_ref()
    );

    // The scalar loads with the point uncompressed or compressed.
    let scalar = ours.to_scalar();
    let (x, y) = point[1..].split_at(point.len() / 2);
    let compressed = [&[0x02 | (y[y.len() - 1] & 1)][..], x].concat();
    for point in [point, &compressed] {
        ours::EcdsaKeyPair::from_private_key_and_public_key(curve.ours, scalar.as_ref(), point)
            .unwrap();
        theirs::EcdsaKeyPair::from_private_key_and_public_key(curve.theirs, scalar.as_ref(), point)
            .unwrap();
    }
    ecdsa_public(curve, point);
}

fn ecdsa_public(curve: &Curve, input: &[u8]) {
    let ours = ours::PublicKey::new(curve.ours_verify, input);
    let theirs = theirs::ParsedPublicKey::new(curve.theirs_verify, input);
    // rind takes only the uncompressed point here: no consumer sends another
    // form, and a compressed one would cost a square root.
    let compressed = matches!(input.first(), Some(2 | 3));
    let refused = compressed || hybrid(input) || spki(input);
    agree(&ours, &theirs, refused.into());
    let Ok(ours) = ours else {
        return;
    };
    assert_eq!(ours.as_ref(), input);
    let again = ours::PublicKey::new(curve.ours_verify, ours.as_ref()).unwrap();
    assert_eq!(again.as_ref(), input);
}

fn rsa_private(
    input: &[u8],
    ours: fn(&[u8]) -> Result<ours::RsaKeyPair, rind::Error>,
    theirs: fn(&[u8]) -> Result<their_rsa::KeyPair, aws_lc_rs::error::KeyRejected>,
) {
    let (ours, theirs) = (ours(input), theirs(input));
    agree(&ours, &theirs, trailing(input).into());
    let Ok(ours) = ours else {
        return;
    };
    let public = ours.public_key(&sign::RSA_PKCS1_SHA256);
    if let Ok(theirs) = &theirs {
        assert_eq!(public.as_ref(), theirs.public_key().as_ref());
    }

    let pkcs8 = ours.to_pkcs8();
    let again = ours::RsaKeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
    assert_eq!(
        again.public_key(&sign::RSA_PKCS1_SHA256).as_ref(),
        public.as_ref()
    );
    let theirs = their_rsa::KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
    assert_eq!(theirs.public_key().as_ref(), public.as_ref());
    assert_eq!(
        ours.to_spki().as_ref(),
        theirs.public_key().as_der().unwrap().as_ref()
    );
    rsa_public(&RSA_2048, public.as_ref());
}

/// aws-lc-rs's key, if it takes `der` and its modulus is in `rsa`'s range.
///
/// aws-lc-rs checks the range only when it verifies, and rind as it loads the
/// key, so neither verifies with a key the other refuses.
fn their_rsa_public(rsa: &Rsa, der: &[u8]) -> Result<their_rsa::PublicKey, &'static str> {
    let key = their_rsa::PublicKey::from_der(der).map_err(|_| "refused")?;
    let modulus = key.modulus();
    let modulus = modulus.big_endian_without_leading_zero();
    let bits = modulus.len() * 8 - modulus.first().map_or(8, |b| b.leading_zeros() as usize);
    match (rsa.min_bits..=8192).contains(&bits) {
        true => Ok(key),
        false => Err("modulus out of range"),
    }
}

fn rsa_public(rsa: &Rsa, input: &[u8]) {
    let ours = ours::PublicKey::new(rsa.ours, input);
    let theirs = their_rsa_public(rsa, input);
    agree(&ours, &theirs, (spki(input) || trailing(input)).into());
    let Ok(ours) = ours else {
        return;
    };
    if let Ok(theirs) = &theirs {
        assert_eq!(ours.as_ref(), theirs.as_ref());
    }
    rsa_reencode(rsa, &ours);
}

fn rsa_components(rsa: &Rsa, input: &[u8]) {
    let Some((n, e)) = split(input) else {
        return;
    };
    let ours = ours::RsaPublicKeyComponents { n, e }.to_public_key(rsa.ours);
    // aws-lc-rs checks components only when it verifies, so their key is the
    // same components as DER. Both refuse an empty component or a leading
    // zero, which DER cannot carry.
    let theirs = match [n, e].iter().all(|x| x.first().is_some_and(|&b| b != 0)) {
        true => their_rsa_public(rsa, &rsa_public_key_der(n, e)),
        false => Err("leading zero"),
    };
    agree(&ours, &theirs, Expect::Agree);
    let Ok(ours) = ours else {
        return;
    };
    assert_eq!(ours.as_ref(), rsa_public_key_der(n, e));
    rsa_reencode(rsa, &ours);
}

/// `key`'s DER loads again on both sides, and as components on rind's.
fn rsa_reencode(rsa: &Rsa, key: &ours::PublicKey) {
    let again = ours::PublicKey::new(rsa.ours, key.as_ref()).unwrap();
    assert_eq!(again.as_ref(), key.as_ref());
    theirs::ParsedPublicKey::new(rsa.theirs, key.as_ref()).unwrap();

    let theirs = their_rsa::PublicKey::from_der(key.as_ref()).unwrap();
    let (n, e) = (theirs.modulus(), theirs.exponent());
    let components = ours::RsaPublicKeyComponents {
        n: n.big_endian_without_leading_zero(),
        e: e.big_endian_without_leading_zero(),
    };
    let again = components.to_public_key(rsa.ours).unwrap();
    assert_eq!(again.as_ref(), key.as_ref());
}

/// The PKCS#1 `RSAPublicKey` for `n` and `e`, each without leading zeros.
fn rsa_public_key_der(n: &[u8], e: &[u8]) -> Vec<u8> {
    fn element(tag: u8, body: &[u8]) -> Vec<u8> {
        let mut out = vec![tag];
        match body.len() {
            len @ 0..=0x7f => out.push(len as u8),
            len => {
                let len = len.to_be_bytes();
                let len = &len[len.iter().position(|&b| b != 0).unwrap()..];
                out.push(0x80 | len.len() as u8);
                out.extend_from_slice(len);
            }
        }
        out.extend_from_slice(body);
        out
    }
    let integer = |x: &[u8]| match x[0] & 0x80 {
        0 => element(0x02, x),
        _ => element(0x02, &[&[0], x].concat()),
    };
    element(0x30, &[integer(n), integer(e)].concat())
}

fn ed25519_pkcs8(input: &[u8]) {
    let ours = ours::Ed25519KeyPair::from_pkcs8(input);
    let theirs = theirs::Ed25519KeyPair::from_pkcs8(input);
    let refused = trailing(input) || v2_without_public_key(input);
    agree_ed25519(ours, theirs, refused.into());
}

fn ed25519_seed(input: &[u8]) {
    let Some((seed, public)) = split(input) else {
        return;
    };
    let ours = ours::Ed25519KeyPair::from_seed_and_public_key(seed, public);
    let theirs = theirs::Ed25519KeyPair::from_seed_and_public_key(seed, public);
    agree_ed25519(ours, theirs, Expect::Agree);
}

fn agree_ed25519(
    ours: Result<ours::Ed25519KeyPair, rind::Error>,
    theirs: Result<theirs::Ed25519KeyPair, aws_lc_rs::error::KeyRejected>,
    expect: Expect,
) {
    agree(&ours, &theirs, expect);
    let Ok(ours) = ours else {
        return;
    };
    let public = ours.public_key();
    if let Ok(theirs) = &theirs {
        assert_eq!(public.as_ref(), theirs.public_key().as_ref());
        let seed = theirs.seed().unwrap();
        assert_eq!(
            ours.to_seed().as_ref(),
            seed.as_be_bytes().unwrap().as_ref()
        );
    }

    let pkcs8 = ours.to_pkcs8();
    let again = ours::Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
    assert_eq!(again.public_key().as_ref(), public.as_ref());
    let theirs = theirs::Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
    assert_eq!(theirs.public_key().as_ref(), public.as_ref());
    assert_eq!(
        ours.to_spki().as_ref(),
        theirs.public_key().as_der().unwrap().as_ref()
    );
    ours::Ed25519KeyPair::from_seed_and_public_key(ours.to_seed().as_ref(), public.as_ref())
        .unwrap();
    ed25519_public(public.as_ref());
}

fn ed25519_public(input: &[u8]) {
    let ours = ours::PublicKey::new(&verify::ED25519, input);
    let theirs = theirs::ParsedPublicKey::new(&theirs::ED25519, input);
    // aws-lc-rs takes a `SubjectPublicKeyInfo` for any length but 32, and
    // any 32 bytes, checking the point only when it verifies.
    let expect = match input.len() {
        32 => Expect::Stricter,
        _ => Expect::Refused,
    };
    agree(&ours, &theirs, expect);
    let Ok(ours) = ours else {
        return;
    };
    assert_eq!(ours.as_ref(), input);
    ours::PublicKey::new(&verify::ED25519, ours.as_ref()).unwrap();
}

fn mlkem_public(input: &[u8]) {
    let ours = our_kem::EncapsulationKey::new(&our_kem::ML_KEM_768, input);
    // aws-lc-rs checks the modulus only when it encapsulates.
    let theirs = their_kem::EncapsulationKey::new(&their_kem::ML_KEM_768, input)
        .map_err(|_| "refused")
        .and_then(|key| key.encapsulate().map(|_| key).map_err(|_| "modulus"));
    agree(&ours, &theirs, Expect::Agree);
    let Ok(ours) = ours else {
        return;
    };
    assert_eq!(ours.as_ref(), input);
    let theirs = theirs.unwrap();
    assert_eq!(theirs.key_bytes().unwrap().as_ref(), input);
}
