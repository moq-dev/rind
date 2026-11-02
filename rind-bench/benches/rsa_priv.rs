mod criterion;
use std::hint::black_box;

use criterion::{Criterion, Throughput, criterion_group, criterion_main};

fn rsa2048_pkcs1_sha256_sign(c: &mut Criterion) {
    let private_key = include_bytes!("../../rind/src/high/rsa/rsa2048.der");
    let message =
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";

    let mut group = c.benchmark_group("rsa2048-pkcs1-sha256-sign");
    group.throughput(Throughput::Elements(1));

    group.bench_function("ring", |b| {
        use ring::{rand, rsa, signature};

        let key = rsa::KeyPair::from_der(private_key).unwrap();
        let rng = rand::SystemRandom::new();

        b.iter(|| {
            let mut signature = [0u8; 256];
            black_box(key.sign(&signature::RSA_PKCS1_SHA256, &rng, message, &mut signature))
                .unwrap();
        })
    });

    group.bench_function("aws-lc-rs", |b| {
        use aws_lc_rs::{rand, rsa, signature};

        let key = rsa::KeyPair::from_der(private_key).unwrap();
        let rng = rand::SystemRandom::new();

        b.iter(|| {
            let mut signature = [0u8; 256];
            black_box(key.sign(&signature::RSA_PKCS1_SHA256, &rng, message, &mut signature))
                .unwrap();
        })
    });

    group.bench_function("rustcrypto", |b| {
        use rsa::pkcs1::DecodeRsaPrivateKey;
        use rsa::signature::Signer;
        let key = rsa::pkcs1v15::SigningKey::<sha2::Sha256>::new(
            rsa::RsaPrivateKey::from_pkcs1_der(private_key).unwrap(),
        );

        b.iter(|| {
            black_box(key.sign(message));
        });
    });

    group.bench_function("rind", |b| {
        use rind::signature::{RsaKeyPair, sign};
        let key = RsaKeyPair::from_pkcs1(private_key).unwrap();

        b.iter(|| {
            black_box(key.sign(&sign::RSA_PKCS1_SHA256, message)).unwrap();
        })
    });
}

fn rsa2048_pss_sha256_sign(c: &mut Criterion) {
    let private_key = include_bytes!("../../rind/src/high/rsa/rsa2048.der");
    let message =
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";

    let mut group = c.benchmark_group("rsa2048-pss-sha256-sign");
    group.throughput(Throughput::Elements(1));

    group.bench_function("ring", |b| {
        use ring::{rand, rsa, signature};

        let key = rsa::KeyPair::from_der(private_key).unwrap();
        let rng = rand::SystemRandom::new();

        b.iter(|| {
            let mut signature = [0u8; 256];
            black_box(key.sign(&signature::RSA_PSS_SHA256, &rng, message, &mut signature)).unwrap();
        })
    });

    group.bench_function("aws-lc-rs", |b| {
        use aws_lc_rs::{rand, rsa, signature};

        let key = rsa::KeyPair::from_der(private_key).unwrap();
        let rng = rand::SystemRandom::new();

        b.iter(|| {
            let mut signature = [0u8; 256];
            black_box(key.sign(&signature::RSA_PSS_SHA256, &rng, message, &mut signature)).unwrap();
        })
    });

    group.bench_function("rind", |b| {
        use rind::signature::{RsaKeyPair, sign};
        let key = RsaKeyPair::from_pkcs1(private_key).unwrap();

        b.iter(|| {
            black_box(key.sign(&sign::RSA_PSS_SHA256, message)).unwrap();
        })
    });
}

/// Signing at the other sizes, whose primes take a different Montgomery
/// multiplication from RSA-2048's on some CPUs: 2056 bits for primes of an
/// odd number of words, and 2560 for a multiple of four but not eight.
fn rsa_pkcs1_sha256_sign_sizes(c: &mut Criterion) {
    let keys: [(u32, &[u8]); 6] = [
        (
            2056,
            include_bytes!("../../rind/src/high/rsa/rsa2056.pkcs8.der"),
        ),
        (
            2560,
            include_bytes!("../../rind/src/high/rsa/rsa2560.pkcs8.der"),
        ),
        (
            3072,
            include_bytes!("../../rind/src/high/rsa/rsa3072.pkcs8.der"),
        ),
        (
            4096,
            include_bytes!("../../rind/src/high/rsa/rsa4096.pkcs8.der"),
        ),
        (
            6144,
            include_bytes!("../../rind/src/high/rsa/rsa6144.pkcs8.der"),
        ),
        (
            8192,
            include_bytes!("../../rind/src/high/rsa/rsa8192.pkcs8.der"),
        ),
    ];
    let message = b"hello";
    for (bits, private_key) in keys {
        let mut group = c.benchmark_group(format!("rsa{bits}-pkcs1-sha256-sign"));
        group.throughput(Throughput::Elements(1));

        group.bench_function("aws-lc-rs", |b| {
            use aws_lc_rs::{rand, rsa, signature};

            let key = rsa::KeyPair::from_pkcs8(private_key).unwrap();
            let rng = rand::SystemRandom::new();
            let mut signature = vec![0u8; key.public_modulus_len()];

            b.iter(|| {
                black_box(key.sign(&signature::RSA_PKCS1_SHA256, &rng, message, &mut signature))
                    .unwrap();
            })
        });

        group.bench_function("rind", |b| {
            use rind::signature::{RsaKeyPair, sign};
            let key = RsaKeyPair::from_pkcs8(private_key).unwrap();

            b.iter(|| {
                black_box(key.sign(&sign::RSA_PKCS1_SHA256, message)).unwrap();
            })
        });
    }
}

/// Loading a key checks its components agree, which should stay small next
/// to a signature at every size.
fn rsa_load(c: &mut Criterion) {
    let keys: [(u32, &[u8]); 2] = [
        (2048, include_bytes!("../../rind/src/high/rsa/rsa2048.der")),
        (8192, include_bytes!("../../rind/src/high/rsa/rsa8192.der")),
    ];
    for (bits, private_key) in keys {
        let mut group = c.benchmark_group(format!("rsa{bits}-load"));
        group.throughput(Throughput::Elements(1));

        group.bench_function("aws-lc-rs", |b| {
            use aws_lc_rs::rsa;

            b.iter(|| black_box(rsa::KeyPair::from_der(black_box(private_key)).unwrap()))
        });

        group.bench_function("rind", |b| {
            use rind::signature::RsaKeyPair;

            b.iter(|| black_box(RsaKeyPair::from_pkcs1(black_box(private_key)).unwrap()))
        });

        group.bench_function("rind-sign", |b| {
            use rind::signature::{RsaKeyPair, sign};
            let key = RsaKeyPair::from_pkcs1(private_key).unwrap();
            b.iter(|| black_box(key.sign(&sign::RSA_PKCS1_SHA256, b"hello")).unwrap())
        });
    }
}

criterion_group!(
    benches,
    rsa2048_pkcs1_sha256_sign,
    rsa2048_pss_sha256_sign,
    rsa_pkcs1_sha256_sign_sizes,
    rsa_load
);
criterion_main!(benches);
