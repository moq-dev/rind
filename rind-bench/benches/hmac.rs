mod criterion;
use std::hint::black_box;

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use hmac::{KeyInit, Mac};

fn rc<M: KeyInit + Mac>(key: &[u8], data: &[u8]) {
    let mut ctx = <M as KeyInit>::new_from_slice(key).unwrap();
    ctx.update(data);
    black_box(ctx.finalize());
}

// Each row keys HMAC per message, as a one-off MAC does; the `reused-key`
// rows sign with a long-lived key, such as a STUN or SRTP session's.
fn bench(
    c: &mut Criterion,
    name: &str,
    ring: ring::hmac::Algorithm,
    aws: aws_lc_rs::hmac::Algorithm,
    rustcrypto: fn(&[u8], &[u8]),
    ours: &'static rind::hmac::Algorithm,
    key: &[u8],
) {
    let mut group = c.benchmark_group(name);

    for (size, size_name) in criterion::HASH_SIZES {
        let input = vec![0u8; size];
        group.throughput(Throughput::Bytes(size as u64));

        group.bench_with_input(BenchmarkId::new("ring", size_name), &input, |b, input| {
            b.iter(|| {
                let mut ctx = ring::hmac::Context::with_key(&ring::hmac::Key::new(ring, key));
                ctx.update(input);
                black_box(ctx.sign())
            })
        });
        group.bench_with_input(
            BenchmarkId::new("aws-lc-rs", size_name),
            &input,
            |b, input| {
                b.iter(|| {
                    let mut ctx =
                        aws_lc_rs::hmac::Context::with_key(&aws_lc_rs::hmac::Key::new(aws, key));
                    ctx.update(input);
                    black_box(ctx.sign())
                })
            },
        );
        group.bench_with_input(
            BenchmarkId::new("rustcrypto", size_name),
            &input,
            |b, input| b.iter(|| rustcrypto(key, input)),
        );
        group.bench_with_input(BenchmarkId::new("rind", size_name), &input, |b, input| {
            b.iter(|| black_box(rind::hmac::sign(&rind::hmac::Key::new(ours, key), input)))
        });

        let ring_key = ring::hmac::Key::new(ring, key);
        group.bench_with_input(
            BenchmarkId::new("ring/reused-key", size_name),
            &input,
            |b, input| b.iter(|| black_box(ring::hmac::sign(&ring_key, input))),
        );
        let aws_key = aws_lc_rs::hmac::Key::new(aws, key);
        group.bench_with_input(
            BenchmarkId::new("aws-lc-rs/reused-key", size_name),
            &input,
            |b, input| b.iter(|| black_box(aws_lc_rs::hmac::sign(&aws_key, input))),
        );
        let rind_key = rind::hmac::Key::new(ours, key);
        group.bench_with_input(
            BenchmarkId::new("rind/reused-key", size_name),
            &input,
            |b, input| b.iter(|| black_box(rind::hmac::sign(&rind_key, input))),
        );
    }
}

fn hmac(c: &mut Criterion) {
    bench(
        c,
        "hmac-sha1",
        ring::hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY,
        aws_lc_rs::hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY,
        rc::<hmac::Hmac<sha1::Sha1>>,
        &rind::hmac::legacy::HMAC_SHA1,
        &[0xff; 20],
    );
    bench(
        c,
        "hmac-sha256",
        ring::hmac::HMAC_SHA256,
        aws_lc_rs::hmac::HMAC_SHA256,
        rc::<hmac::Hmac<sha2::Sha256>>,
        &rind::hmac::HMAC_SHA256,
        &[0xff; 32],
    );
    bench(
        c,
        "hmac-sha384",
        ring::hmac::HMAC_SHA384,
        aws_lc_rs::hmac::HMAC_SHA384,
        rc::<hmac::Hmac<sha2::Sha384>>,
        &rind::hmac::HMAC_SHA384,
        &[0xff; 48],
    );
}

criterion_group!(benches, hmac);
criterion_main!(benches);
