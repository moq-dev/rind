//! RSA by hand, for inputs rind's API cannot make: private keys that share one
//! public key but differ in their secrets, and raw encryption of a chosen
//! encoded message.
//!
//! Loading a key sets up its public modulus in time that depends on it, by
//! design, so keys with different moduli would differ in time for a public
//! reason. Keys of one modulus differ only in which prime is `p`, and so in
//! `dP`, `dQ`, and `qInv`, and in which valid `d` they hold: `d + kλ(n)` for
//! small `k`. Those `d` share `dP` and `dQ`, which is all a private operation
//! uses, so only key loading is timed on them.

use num_bigint::BigUint;
use num_integer::Integer;

/// PKCS#1 encodings of keys with `pkcs8`'s public key: `pkcs8`'s own key
/// first, then every other that encodes `d` in as many bytes, since a
/// component's length is public in practice.
pub fn variants(pkcs8: &[u8]) -> Vec<Vec<u8>> {
    // PrivateKeyInfo: version, algorithm, then the RSAPrivateKey.
    let mut info = sequence(pkcs8);
    let _version = next(&mut info);
    let _algorithm = next(&mut info);
    let pkcs1 = next(&mut info).1;
    // RSAPrivateKey: version, n, e, d, p, q, dP, dQ, qInv.
    let mut fields = sequence(pkcs1);
    let _version = next(&mut fields);
    let [n, e, d, p, q] = [(); 5].map(|()| BigUint::from_bytes_be(next(&mut fields).1));

    let one = BigUint::from(1u8);
    let lambda = (&p - &one).lcm(&(&q - &one));
    let len = d.to_bytes_be().len();
    let mut keys = Vec::new();
    for (p, q) in [(&p, &q), (&q, &p)] {
        for k in 0u8..4 {
            let d = &d + &lambda * k;
            if d < n && d.to_bytes_be().len() == len {
                keys.push(encode(&[
                    &BigUint::ZERO,
                    &n,
                    &e,
                    &d,
                    p,
                    q,
                    &(&d % (p - &one)),
                    &(&d % (q - &one)),
                    &q.modinv(p).expect("distinct primes"),
                ]));
            }
        }
    }
    keys
}

/// `message`, as long as the modulus, raised to the public exponent of the
/// PKCS#1 `RSAPrivateKey` `pkcs1`, modulo its modulus.
pub fn encrypt_raw(pkcs1: &[u8], message: &[u8]) -> Vec<u8> {
    let mut fields = sequence(pkcs1);
    let _version = next(&mut fields);
    let [n, e] = [(); 2].map(|()| BigUint::from_bytes_be(next(&mut fields).1));
    let len = n.to_bytes_be().len();
    assert_eq!(message.len(), len);
    let c = BigUint::from_bytes_be(message).modpow(&e, &n).to_bytes_be();
    let mut out = vec![0; len - c.len()];
    out.extend(c);
    out
}

/// The contents of the DER SEQUENCE `der`.
fn sequence(der: &[u8]) -> &[u8] {
    let mut der = der;
    let (tag, contents) = next(&mut der);
    assert_eq!(tag, 0x30);
    contents
}

/// Splits the next DER element off `der`, returning its tag and contents.
fn next<'a>(der: &mut &'a [u8]) -> (u8, &'a [u8]) {
    let (tag, rest) = (der[0], &der[1..]);
    let (len, rest) = match rest[0] {
        n if n < 0x80 => (usize::from(n), &rest[1..]),
        0x81 => (usize::from(rest[1]), &rest[2..]),
        0x82 => (
            usize::from(u16::from_be_bytes([rest[1], rest[2]])),
            &rest[3..],
        ),
        n => panic!("unexpected DER length byte {n:#x}"),
    };
    let (contents, rest) = rest.split_at(len);
    *der = rest;
    (tag, contents)
}

/// A DER SEQUENCE of `integers`.
fn encode(integers: &[&BigUint]) -> Vec<u8> {
    let mut contents = Vec::new();
    for i in integers {
        let mut bytes = i.to_bytes_be();
        if bytes[0] & 0x80 != 0 {
            bytes.insert(0, 0);
        }
        element(&mut contents, 0x02, &bytes);
    }
    let mut der = Vec::new();
    element(&mut der, 0x30, &contents);
    der
}

fn element(out: &mut Vec<u8>, tag: u8, contents: &[u8]) {
    out.push(tag);
    match contents.len() {
        n if n < 0x80 => out.push(n as u8),
        n if n < 0x100 => out.extend([0x81, n as u8]),
        n => out.extend([0x82, (n >> 8) as u8, n as u8]),
    }
    out.extend_from_slice(contents);
}
