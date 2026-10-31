mod criterion;
use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};

fn bench_aes_ctr(c: &mut Criterion) {
    let key = [0u8; 16];
    let nonce = [0u8; 12];

    let mut group = c.benchmark_group("aes128-ctr");
    for (size, size_name) in [(32, "32B"), (1200, "1200B"), (16384, "16KB")] {
        let input = vec![0u8; size];
        group.throughput(Throughput::Bytes(size as u64));

        group.bench_with_input(
            BenchmarkId::new("aws-lc-rs", size_name),
            &input,
            |b, input| {
                use aws_lc_rs::cipher::{
                    AES_128, EncryptingKey, EncryptionContext, UnboundCipherKey,
                };
                let key =
                    EncryptingKey::ctr(UnboundCipherKey::new(&AES_128, &key).unwrap()).unwrap();
                let mut iv = [0u8; 16];
                iv[..12].copy_from_slice(&nonce);
                b.iter(|| {
                    let mut buf = input.clone();
                    key.less_safe_encrypt(&mut buf, EncryptionContext::Iv128(iv.into()))
                        .unwrap();
                    buf
                });
            },
        );
        group.bench_with_input(BenchmarkId::new("rind", size_name), &input, |b, input| {
            let key = rind::cipher::AesCtr::new(&rind::cipher::AES_128, &key).unwrap();
            b.iter(|| {
                let mut buf = input.clone();
                key.apply_keystream(&nonce, 0, &mut buf).unwrap();
                buf
            });
        });
    }
}

// The QUIC header protection mask: one cipher call on a 16-byte sample.
fn bench_header_protection(c: &mut Criterion) {
    let sample = [0x5au8; 16];
    let mut group = c.benchmark_group("quic-header-protection");

    for (name, key_len) in [("aes128", 16), ("chacha20", 32)] {
        let key = &[0u8; 32][..key_len];
        group.bench_function(format!("{name}/aws-lc-rs"), |b| {
            use aws_lc_rs::aead::quic::{AES_128, CHACHA20, HeaderProtectionKey};
            let algorithm = if key_len == 16 { &AES_128 } else { &CHACHA20 };
            let key = HeaderProtectionKey::new(algorithm, key).unwrap();
            b.iter(|| key.new_mask(&sample).unwrap());
        });
        group.bench_function(format!("{name}/rind"), |b| {
            use rind::aead::quic::{AES_128, CHACHA20, HeaderProtectionKey};
            let algorithm = if key_len == 16 { &AES_128 } else { &CHACHA20 };
            let key = HeaderProtectionKey::new(algorithm, key).unwrap();
            b.iter(|| key.mask(&sample));
        });
    }
}

criterion_group!(benches, bench_aes_ctr, bench_header_protection);
criterion_main!(benches);
