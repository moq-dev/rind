mod criterion;
use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};

/// aws-lc's XChaCha20-Poly1305, which aws-lc-rs does not expose.
struct AwsXChaCha(*mut aws_lc_sys::EVP_AEAD_CTX);

impl AwsXChaCha {
    fn new(key: &[u8; 32]) -> Self {
        // SAFETY: the key pointer and length describe `key`, and aws-lc copies it.
        let ctx = unsafe {
            aws_lc_sys::EVP_AEAD_CTX_new(
                aws_lc_sys::EVP_aead_xchacha20_poly1305(),
                key.as_ptr(),
                key.len(),
                16,
            )
        };
        assert!(!ctx.is_null());
        Self(ctx)
    }

    fn seal(&self, aad: &[u8], plain: &[u8]) {
        let mut nonce = [0u8; 24];
        rind::rand::fill(&mut nonce).unwrap();
        let mut ct = plain.to_vec();
        let mut tag = [0u8; 16];
        let mut tag_len = 0;
        // SAFETY: each pointer and length describes a live buffer, and aws-lc
        // allows `out` to equal `in`.
        let ok = unsafe {
            aws_lc_sys::EVP_AEAD_CTX_seal_scatter(
                self.0,
                ct.as_mut_ptr(),
                tag.as_mut_ptr(),
                &mut tag_len,
                tag.len(),
                nonce.as_ptr(),
                nonce.len(),
                ct.as_ptr(),
                ct.len(),
                std::ptr::null(),
                0,
                aad.as_ptr(),
                aad.len(),
            )
        };
        assert_eq!(ok, 1);
    }
}

impl Drop for AwsXChaCha {
    fn drop(&mut self) {
        // SAFETY: `self.0` came from `EVP_AEAD_CTX_new` and is freed once.
        unsafe { aws_lc_sys::EVP_AEAD_CTX_free(self.0) }
    }
}

fn test_rc_chacha(key: &chacha20poly1305::XChaCha20Poly1305, aad: &[u8], plain: &[u8]) {
    use chacha20poly1305::AeadInOut;
    let mut nonce = [0u8; 24];
    rind::rand::fill(&mut nonce).unwrap();
    let nonce = &nonce;
    let mut ct = plain.to_vec();
    let _tag = key
        .encrypt_inout_detached(nonce.into(), aad, ct.as_mut_slice().into())
        .unwrap();
}

fn test_rind_chacha(key: &rind::aead::RandomizedNonceKey, aad: &[u8], plain: &[u8]) {
    // Room for the appended tag, so sealing does not reallocate.
    let mut ct = Vec::with_capacity(plain.len() + 16);
    ct.extend_from_slice(plain);
    let _nonce = key.seal_in_place_append_tag(aad, &mut ct).unwrap();
}

fn bench_chacha20poly1305(c: &mut Criterion) {
    // Each seal draws a fresh random nonce, as a randomized-nonce key must.
    let key = [0u8; 32];
    let aad = [0u8; 32];

    let mut group = c.benchmark_group("xchacha20poly1305");
    for (size, size_name) in criterion::SIZES {
        let input = vec![0u8; size];
        group.throughput(Throughput::Bytes(size as u64));

        group.bench_with_input(
            BenchmarkId::new("aws-lc-rs", size_name),
            &input,
            |b, input| {
                let key = AwsXChaCha::new(&key);
                b.iter(|| key.seal(&aad, input));
            },
        );
        group.bench_with_input(
            BenchmarkId::new("rustcrypto", size_name),
            &input,
            |b, input| {
                use chacha20poly1305::KeyInit;
                let key = chacha20poly1305::XChaCha20Poly1305::new_from_slice(&key).unwrap();
                b.iter(|| test_rc_chacha(&key, &aad, input));
            },
        );
        group.bench_with_input(BenchmarkId::new("rind", size_name), &input, |b, input| {
            let key = rind::aead::RandomizedNonceKey::new(&key);
            b.iter(|| test_rind_chacha(&key, &aad, input));
        });
    }
}

criterion_group!(benches, bench_chacha20poly1305);
criterion_main!(benches);
