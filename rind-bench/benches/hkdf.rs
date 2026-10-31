mod criterion;
use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};

struct Len(usize);

impl aws_lc_rs::hkdf::KeyType for Len {
    fn len(&self) -> usize {
        self.0
    }
}

impl ring::hkdf::KeyType for Len {
    fn len(&self) -> usize {
        self.0
    }
}

// A 32-byte key for one label, from a PRK extracted once: what a QUIC token
// or an e2ee track key derives from a long-lived secret.
fn bench(
    c: &mut Criterion,
    name: &str,
    ring: ring::hkdf::Algorithm,
    aws: aws_lc_rs::hkdf::Algorithm,
    ours: &'static rind::hkdf::Algorithm,
) {
    let mut group = c.benchmark_group(name);
    let secret = [0x5a; 32];
    let info: [&[u8]; 1] = [b"label"];

    group.bench_function("extract/ring", |b| {
        b.iter(|| black_box(ring::hkdf::Salt::new(ring, b"salt").extract(&secret)))
    });
    group.bench_function("extract/aws-lc-rs", |b| {
        b.iter(|| black_box(aws_lc_rs::hkdf::Salt::new(aws, b"salt").extract(&secret)))
    });
    group.bench_function("extract/rind", |b| {
        b.iter(|| black_box(rind::hkdf::Salt::new(ours, b"salt").extract(&secret)))
    });

    let prk = ring::hkdf::Salt::new(ring, b"salt").extract(&secret);
    group.bench_function("expand/ring", |b| {
        b.iter(|| {
            let mut out = [0u8; 32];
            prk.expand(&info, Len(32)).unwrap().fill(&mut out).unwrap();
            black_box(out)
        })
    });

    let prk = aws_lc_rs::hkdf::Salt::new(aws, b"salt").extract(&secret);
    group.bench_function("expand/aws-lc-rs", |b| {
        b.iter(|| {
            let mut out = [0u8; 32];
            prk.expand(&info, Len(32)).unwrap().fill(&mut out).unwrap();
            black_box(out)
        })
    });
    group.bench_function("expand-aes-256-gcm-key/aws-lc-rs", |b| {
        b.iter(|| {
            black_box(aws_lc_rs::aead::UnboundKey::from(
                prk.expand(&info, &aws_lc_rs::aead::AES_256_GCM).unwrap(),
            ))
        })
    });

    let prk = rind::hkdf::Salt::new(ours, b"salt").extract(&secret);
    group.bench_function("expand/rind", |b| {
        b.iter(|| {
            let mut out = [0u8; 32];
            prk.expand(&info, out.len()).fill(&mut out).unwrap();
            black_box(out)
        })
    });
    group.bench_function("expand-aes-256-gcm-key/rind", |b| {
        b.iter(|| {
            black_box(rind::aead::Key::from(
                prk.expand(&info, &rind::aead::AES_256_GCM),
            ))
        })
    });
}

fn hkdf(c: &mut Criterion) {
    bench(
        c,
        "hkdf-sha1",
        ring::hkdf::HKDF_SHA1_FOR_LEGACY_USE_ONLY,
        aws_lc_rs::hkdf::HKDF_SHA1_FOR_LEGACY_USE_ONLY,
        &rind::hkdf::legacy::HKDF_SHA1,
    );
    bench(
        c,
        "hkdf-sha256",
        ring::hkdf::HKDF_SHA256,
        aws_lc_rs::hkdf::HKDF_SHA256,
        &rind::hkdf::HKDF_SHA256,
    );
    bench(
        c,
        "hkdf-sha384",
        ring::hkdf::HKDF_SHA384,
        aws_lc_rs::hkdf::HKDF_SHA384,
        &rind::hkdf::HKDF_SHA384,
    );
    bench(
        c,
        "hkdf-sha512",
        ring::hkdf::HKDF_SHA512,
        aws_lc_rs::hkdf::HKDF_SHA512,
        &rind::hkdf::HKDF_SHA512,
    );
}

criterion_group!(benches, hkdf);
criterion_main!(benches);
