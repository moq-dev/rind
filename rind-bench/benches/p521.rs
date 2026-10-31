mod criterion;
use std::hint::black_box;

use criterion::{Criterion, Throughput, criterion_group, criterion_main};

// RFC6979 A.2.7's public key, and its SHA-512 signature over "sample".
const PUBLIC_KEY: &str = "0401894550d0785932e00eaa23b694f213f8c3121f86dc97a04e5a7167db4e5bcd371123d46e45db6b5d5370a7f20fb633155d38ffa16d2bd761dcac474b9a2f5023a400493101c962cd4d2fddf782285e64584139c2f91b47f87ff82354d6630f746a28a0db25741b5b34a828008b22acc23f924faafbd4d33f81ea66956dfeaa2bfdfcf5";
const MESSAGE: &[u8] = b"sample";
const SIGNATURE: &str = "00c328fafcbd79dd77850370c46325d987cb525569fb63c5d3bc53950e6d4c5f174e25a1ee9017b5d450606add152b534931d7d4e8455cc91f9b15bf05ec36e377fa00617cce7cf5064806c467f678d3b4080d6f1cc50af26ca209417308281b68af282623eaa63e5b5c0723d8b8c37ff0777b1a20f8ccb1dccc43997f1ee0e44da4a67a";

fn ecdh(c: &mut Criterion) {
    let mut group = c.benchmark_group("p521-ecdh");
    group.throughput(Throughput::Elements(1));
    let public_key = hex::decode(PUBLIC_KEY).unwrap();

    group.bench_function("aws-lc-rs", |b| {
        use aws_lc_rs::{agreement, error, rand};
        let rng = rand::SystemRandom::new();

        b.iter(|| {
            let our_private_key =
                agreement::EphemeralPrivateKey::generate(&agreement::ECDH_P521, &rng).unwrap();
            black_box(our_private_key.compute_public_key().unwrap());

            let peer_public_key =
                agreement::UnparsedPublicKey::new(&agreement::ECDH_P521, &public_key);

            agreement::agree_ephemeral(
                our_private_key,
                peer_public_key,
                error::Unspecified,
                |key_material| {
                    black_box(key_material);
                    Ok(())
                },
            )
            .unwrap();
        })
    });

    group.bench_function("rind", |b| {
        b.iter(|| {
            use rind::agreement::*;
            let our_private_key = EphemeralPrivateKey::generate(&ECDH_P521).unwrap();
            let our_public_key = our_private_key.compute_public_key();
            black_box(our_public_key);

            let peer = UnparsedPublicKey::new(&ECDH_P521, &public_key);
            let secret = agree_ephemeral(our_private_key, &peer).unwrap();
            black_box(secret);
        })
    });
}

fn keygen(c: &mut Criterion) {
    let mut group = c.benchmark_group("p521-keygen");
    group.throughput(Throughput::Elements(1));

    group.bench_function("aws-lc-rs", |b| {
        use aws_lc_rs::{agreement, rand};
        let rng = rand::SystemRandom::new();

        b.iter(|| {
            let our_private_key =
                agreement::EphemeralPrivateKey::generate(&agreement::ECDH_P521, &rng).unwrap();
            black_box(our_private_key.compute_public_key().unwrap());
        })
    });

    group.bench_function("rind", |b| {
        b.iter(|| {
            use rind::agreement::*;
            let our_private_key = EphemeralPrivateKey::generate(&ECDH_P521).unwrap();
            black_box(our_private_key.compute_public_key());
        })
    });
}

fn ecdsa_verify(c: &mut Criterion) {
    let mut group = c.benchmark_group("p521-ecdsa-verify");
    group.throughput(Throughput::Elements(1));
    let public_key = hex::decode(PUBLIC_KEY).unwrap();
    let signature = hex::decode(SIGNATURE).unwrap();

    group.bench_function("aws-lc-rs", |b| {
        let public_key = aws_lc_rs::signature::UnparsedPublicKey::new(
            &aws_lc_rs::signature::ECDSA_P521_SHA512_FIXED,
            &public_key,
        );

        b.iter(|| {
            public_key.verify(MESSAGE, &signature).unwrap();
        })
    });

    group.bench_function("rind", |b| {
        use rind::signature;
        let public_key =
            signature::UnparsedPublicKey::new(&signature::ECDSA_P521_SHA512_FIXED, &public_key);

        b.iter(|| {
            public_key.verify(MESSAGE, &signature).unwrap();
        })
    });
    group.finish();

    // A key parsed once, as a JWT verifier holds it, keeps its multiplication table.
    let mut group = c.benchmark_group("p521-ecdsa-verify-parsed");
    group.throughput(Throughput::Elements(1));

    group.bench_function("aws-lc-rs", |b| {
        use aws_lc_rs::signature;
        let public_key =
            signature::ParsedPublicKey::new(&signature::ECDSA_P521_SHA512_FIXED, &public_key)
                .unwrap();

        b.iter(|| {
            public_key.verify_sig(MESSAGE, &signature).unwrap();
        })
    });

    group.bench_function("rind", |b| {
        use rind::signature;
        let public_key =
            signature::ParsedPublicKey::new(&signature::ECDSA_P521_SHA512_FIXED, &public_key)
                .unwrap();

        b.iter(|| {
            public_key.verify(MESSAGE, &signature).unwrap();
        })
    });
}

fn ecdsa_sign(c: &mut Criterion) {
    let mut group = c.benchmark_group("p521-ecdsa-sign");
    group.throughput(Throughput::Elements(1));

    group.bench_function("aws-lc-rs", |b| {
        use aws_lc_rs::{rand, signature};
        let rng = rand::SystemRandom::new();

        let private_key = signature::EcdsaKeyPair::generate_pkcs8(
            &signature::ECDSA_P521_SHA512_FIXED_SIGNING,
            &rng,
        )
        .unwrap();
        let private_key = signature::EcdsaKeyPair::from_pkcs8(
            &signature::ECDSA_P521_SHA512_FIXED_SIGNING,
            private_key.as_ref(),
        )
        .unwrap();

        b.iter(|| {
            black_box(private_key.sign(&rng, MESSAGE).unwrap());
        })
    });

    group.bench_function("rind", |b| {
        use rind::signature::{ECDSA_P521_SHA512_FIXED_SIGNING, EcdsaKeyPair};
        let signing_key = EcdsaKeyPair::generate(&ECDSA_P521_SHA512_FIXED_SIGNING).unwrap();

        b.iter(|| {
            black_box(signing_key.sign(MESSAGE).unwrap());
        });
    });
}

criterion_group!(benches, ecdh, keygen, ecdsa_verify, ecdsa_sign);
criterion_main!(benches);
