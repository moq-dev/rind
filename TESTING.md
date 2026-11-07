# Testing

What checks each primitive rind exports, on each backend and CPU tier it runs on.
[CONTRIBUTING.md](CONTRIBUTING.md#building-and-testing) says how to run the tests,
and [ALGORITHMS.md](ALGORITHMS.md) whose code each tier runs.

A primitive is checked four ways:

- **Vectors**: published known-answer tests, from [Wycheproof] (each file's
  name below, in `thirdparty/wycheproof/testvectors_v1/`), NIST's CAVP
  (`thirdparty/cavp/`), and the RFCs, run by `cargo test`.
- **Fuzz target**: a `fuzz/fuzzer/` target that compares rind with aws-lc-rs
  on fuzzed input. `fuzz.yml` runs each nightly, then replays its corpus on
  each slower tier.
- **Differential test**: a `rind/tests/crosschecks.rs` test that compares rind
  with aws-lc-rs, run by `cargo test`.
- **Constant time**: a test that marks the secrets. `admin/ctgrind` runs the
  unit tests under valgrind, which fails when a branch or address depends on a
  marked byte; the mid layer marks each key it builds, so every unit test that
  builds one is checked. `admin/ct-sde` and `admin/ct-qemu` compare the traces
  of `ct_sde_...` and `ct_qemu_...` tests for two secrets, for the code
  valgrind cannot run. None of the three sees variable-time instructions;
  [that quest](/quest/m3/confidence/vartime-scan.md) adds the check.

`admin/testing`, in `just ci`, fails when an export, fuzz target, differential
test, constant-time test, or vector file is missing from the
[primitives table](#primitives), or when the table names one the code lacks.

## Tiers

`cargo test` runs the vectors and the differential tests together, so each
tier's row says where all of them run, which fuzz targets reach it, and which
constant-time checks. A primitive's cell on a tier is its row in the
[primitives table](#primitives) narrowed to what the tier's row runs. A
"denied" tier is the runner's CPU with `RIND_CPU_DISABLE_*` hiding features,
as `build.yml`, `ctgrind.yml`, and `sh/fuzz-replay.sh` set them; an SDE tier is
an Intel SDE CPU model, as `x86-cpu.yml` names them.

| Backend | Tier | Vectors and differential tests | Fuzz targets | Constant time |
|---|---|---|---|---|
| x86_64 | AVX-512 (Ice Lake and later, Zen 4 and 5) | SDE: Cannon Lake (RSA only), Granite Rapids, Diamond Rapids | the runner's tier, when it has AVX-512 | `admin/ct-sde`: AES-GCM and RSA; ML-KEM's AVX-512 code reads only the public matrix |
| x86_64 | SHA512 instructions (Arrow Lake, Diamond Rapids) | SDE: Arrow Lake, Diamond Rapids | none: GitHub's runners lack them, [planned](/quest/m3/confidence/fuzz-tiers.md) | `admin/ct-sde`: HMAC |
| x86_64 | VAES without AVX-512 (Alder Lake, Zen 3) | SDE: Alder Lake, Granite Rapids at 256 bits; the runner, when Zen 3 | the runner's tier, when Zen 3; denied, when it has AVX-512 | `admin/ct-sde`: AES-GCM |
| x86_64 | SHA extensions (Goldmont, Cannon Lake and later, Zen) | SDE: Goldmont and later | the runner's tier | `admin/ct-sde`: HMAC |
| x86_64 | AVX2 and ADX, no SHA extensions or VAES (Broadwell to Cooper Lake) | SDE: Skylake server; denied | denied | ctgrind: valgrind hides AVX-512, VAES, and the SHA extensions, so the runner's own run lands here |
| x86_64 | AVX2 without ADX (Haswell) | SDE: Haswell; denied | denied | ctgrind: denied (`no-adx`) |
| x86_64 | AVX without AVX2 (Sandy and Ivy Bridge, Bulldozer, Jaguar) | SDE: Sandy Bridge, which runs Intel's AVX SHA; denied, which runs other vendors' | denied | ctgrind: denied (`no-avx2`), but on GitHub's AMD runners not Intel's AVX SHA, [planned](/quest/m3/confidence/ct-tiers.md) |
| x86_64 | AES-NI without AVX (Westmere, Silvermont, Goldmont) | SDE: Westmere, Goldmont; denied | denied | ctgrind: denied (`no-avx`) |
| x86_64 | SSSE3 without AES-NI (Core 2, Nehalem) | SDE: Merom, Nehalem; denied | denied | ctgrind: denied (`no-aes`) |
| x86_64 | SSE2 (Pentium 4, `qemu64`) | SDE: Prescott; denied | denied | ctgrind: denied (`no-ssse3`) |
| aarch64 | crypto extension, SHA-512 and SHA-3 instructions (Graviton 3, Apple M, Cobalt 100) | `build.yml` on the arm64 runners | the arm64 runner | ctgrind on the arm64 runner, on the paths valgrind exposes, [planned](/quest/m3/confidence/ct-tiers.md) |
| aarch64 | crypto extension without SHA-3 (Graviton 2, Raspberry Pi 5) | denied | denied | ctgrind, where valgrind hides SHA-3, [planned](/quest/m3/confidence/ct-tiers.md) |
| aarch64 | no crypto extension (Raspberry Pi 4) | denied | denied | ctgrind: denied (`aarch64-portable`) |
| armv7 | crypto extension (most 32-bit Android) | `just armv7`: qemu `max` | none: `fuzz.yml` builds only on GitHub's hosted runners, [planned](/quest/m3/confidence/fuzz-tiers.md) | `admin/ct-qemu`: AES, AES-CBC, AES-KW, AES-GCM, HMAC |
| armv7 | NEON without the crypto extension | `just armv7`: qemu Cortex-A15 | none, as above | ctgrind on the arm64 runner, which valgrind hides the crypto extension from |
| armv7 | no NEON | `just armv7`: qemu Cortex-A15, denied | none, as above | ctgrind: denied (`no-neon`) |

## Primitives

A cell's "none" says why, or links the quest that fills it. Published vector
sets rind does not run yet are [their own quest](/quest/m3/confidence/vectors.md).
Verification and encryption under a public key handle no secret, so their
constant-time cell is empty by design.

| Primitive | Exports | Vectors | Fuzz target | Differential test | Constant time |
|---|---|---|---|---|---|
| AES-GCM | `aead::{Algorithm, Key, Nonce, Tag, AES_128_GCM, AES_192_GCM, AES_256_GCM}`, `aead::gcm::{Iv, Key, Tag, TagLength}` | `aes_gcm_test`, `aes_gmac_test`, `cavp/gcm` | `fuzz::aead`; for any IV or tag length, none, [planned](/quest/m3/confidence/fuzz-every-primitive.md) | `crosschecks::aead::aes_gcm`, `crosschecks::aead::aes_gcm_every_length`, `crosschecks::aead::aes_gcm_any_iv` | ctgrind: `low::x86_64::aes_gcm::paths_match`, `low::x86_64::aes_gcm::counter_wraps`, `low::aarch64::aes_gcm::kernels_match_composed`, armv7's key `mid::arm::aes_gcm::new`; SDE: `low::x86_64::aes_gcm::ct_sde_aes128_gcm`, `low::x86_64::aes_gcm::ct_sde_aes192_gcm`, `low::x86_64::aes_gcm::ct_sde_aes256_gcm`, `low::x86_64::aes_gcm::ct_sde_aes_gcm_vaes_avx2`; qemu: `mid::arm::aes_gcm::ct_qemu_aes_gcm` |
| ChaCha20-Poly1305 | `aead::{Algorithm, Key, Nonce, Tag, CHACHA20_POLY1305}` | `chacha20_poly1305_test`, RFC 8439: `mid::chacha20poly1305::test_vector` | `fuzz::aead` | `crosschecks::aead::chacha20_poly1305` | ctgrind: the key `mid::chacha20poly1305::new`, `low::x86_64::chacha20poly1305::paths_match`, `low::aarch64::chacha20poly1305::matches_separate_passes`, `low::arm::chacha_armv4::neon_matches_nohw`, `low::arm::poly1305::neon_matches_portable` |
| XChaCha20-Poly1305 | `aead::{RandomizedNonceKey, RandomNonce}` | `xchacha20_poly1305_test`, draft-irtf-cfrg-xchacha: `mid::xchacha20poly1305::test_vector` | `fuzz::xchacha` | `crosschecks::aead::xchacha20_poly1305` | ctgrind: the key `mid::xchacha20poly1305::new` |
| QUIC header protection | `aead::quic::{Algorithm, AES_128, AES_256, CHACHA20, HeaderProtectionKey, SAMPLE_LEN}` | RFC 9001: `aead::quic::rfc9001` | none, [planned](/quest/m3/confidence/fuzz-every-primitive.md) | `crosschecks::cipher::quic_header_protection_mask` | ctgrind: AES's key, as below, and ChaCha20's `mid::chacha20::new`; qemu: `mid::aes::ct_qemu_aes` |
| AES block | `cipher::{Aes, Algorithm, AES_128, AES_192, AES_256}` | `cavp/aes` | none, [planned](/quest/m3/confidence/fuzz-every-primitive.md) | `crosschecks::cipher::aes_block` | ctgrind: `mid::aes::expand_key`, `mid::aes::encrypt_block`; qemu: `mid::aes::ct_qemu_aes` |
| AES-CTR | `cipher::AesCtr` | SP 800-38A: `mid::aes::sp800_38a`, RFC 3686: `mid::aes::rfc3686`, RFC 3711: `mid::aes::srtp_aes_cm` | none, [planned](/quest/m3/confidence/fuzz-every-primitive.md) | `crosschecks::cipher::aes_ctr` | ctgrind: `mid::aes::expand_key`, `mid::aes::apply_keystream`; qemu: `mid::aes::ct_qemu_aes` |
| AES-CBC | `cipher::{AesCbcDecryptingKey, AesCbcEncryptingKey}` | `aes_cbc_pkcs5_test`, SP 800-38A: `mid::aes_cbc::sp800_38a` | `fuzz::aes_cbc` | `crosschecks::cipher::aes_cbc_pkcs7`, `crosschecks::cipher::aes_cbc_unpadded` | ctgrind: the key `mid::aes_cbc::new`; qemu: `mid::aes_cbc::ct_qemu_aes_cbc` |
| ChaCha20 | `cipher::ChaCha20` | `chacha20_counter_test`, RFC 8439: `mid::chacha20::rfc8439` | none, [planned](/quest/m3/confidence/fuzz-every-primitive.md) | `crosschecks::cipher::chacha20_keystream`, `crosschecks::cipher::chacha20_every_length` | ctgrind: the key `mid::chacha20::new`, `low::x86_64::chacha20::paths_match`, `low::arm::chacha_armv4::neon_matches_nohw` |
| AES-KW, AES-KWP | `key_wrap::{AesKek, AES_128, AES_192, AES_256}` | `aes_wrap_test`, `aes_kwp_test`, RFC 3394: `mid::aes_kw::rfc3394`, RFC 5649: `mid::aes_kw::rfc5649` | `fuzz::key_wrap`, but not AES-192, which aws-lc-rs lacks | `crosschecks::key_wrap::wrap_and_unwrap`, `crosschecks::key_wrap::wrap_and_unwrap_padded` | ctgrind: the key `mid::aes_kw::new`; qemu: `mid::aes_kw::ct_qemu_aes_kw` |
| MD5 | `digest::legacy::MD5` | RFC 1321: `mid::md5::rfc1321` | none, [planned](/quest/m3/confidence/fuzz-every-primitive.md) | `crosschecks::hashes_match_aws_lc_rs`, `crosschecks::hashes_every_length` | ctgrind: `high::digest::secret_message` |
| SHA-1 | `digest::legacy::SHA1` | `cavp-sha1` | `fuzz::sha1` | `crosschecks::hashes_match_aws_lc_rs`, `crosschecks::hashes_every_length` | ctgrind: `high::digest::secret_message`; SDE and qemu: through HMAC |
| SHA-2 | `digest::{Algorithm, Context, Digest, digest, SHA256, SHA384, SHA512, SHA512_256}` | `cavp/sha2` | `fuzz::sha2` | `crosschecks::hashes_match_aws_lc_rs`, `crosschecks::hashes_every_length` | ctgrind: `high::digest::secret_message`; SDE and qemu: through HMAC |
| SHA-3 | `digest::{SHA3_256, SHA3_384, SHA3_512}` | `cavp/sha3` | `fuzz::sha3` | `crosschecks::hashes_match_aws_lc_rs`, `crosschecks::hashes_every_length` | ctgrind: `high::digest::secret_message` |
| HMAC | `hmac::{Algorithm, Context, Key, Tag, sign, verify, HMAC_SHA256, HMAC_SHA384, HMAC_SHA512}`, `hmac::legacy::HMAC_SHA1` | `hmac_sha*_test`, `cavp/hmac` | `fuzz::sha1`, `fuzz::sha2` | `crosschecks::hmac_matches_aws_lc_rs` | ctgrind: `high::hmac::secret_key_and_message`; SDE: `high::hmac::ct_sde_hmac`; qemu: `high::hmac::ct_qemu_hmac` |
| HKDF | `hkdf::{Algorithm, KeyType, Okm, Prk, Salt, HKDF_SHA256, HKDF_SHA384, HKDF_SHA512}`, `hkdf::legacy::HKDF_SHA1` | `hkdf_sha*_test`, RFC 5869: `high::hkdf::rfc5869` | `fuzz::hkdf` | `crosschecks::hkdf::matches_aws_lc_rs`, `crosschecks::hkdf::keys` | ctgrind: `high::hkdf::secret_ikm` |
| PBKDF2 | `pbkdf2::{Algorithm, Secret, PBKDF2_HMAC_SHA256, PBKDF2_HMAC_SHA384, PBKDF2_HMAC_SHA512}`, `pbkdf2::legacy::PBKDF2_HMAC_SHA1` | `pbkdf2_hmacsha*_test` | `fuzz::pbkdf2` | `crosschecks::pbkdf2::matches_aws_lc_rs` | ctgrind: `high::pbkdf2::secret_password` |
| X25519 | `agreement::{Algorithm, PrivateKey, PublicKey, Scalar, SharedSecret, X25519}` | `x25519_test`, `x25519_asn_test` | `fuzz::kx`, `fuzz::keys` | `crosschecks::ecdh_scalars::x25519`, `crosschecks::ecdh_scalars::x25519_pkcs8` | ctgrind: the key `mid::x25519::from_bytes`, `mid::x25519::new_random`, `high::agreement::loads_in_constant_time`, `low::arm::curve25519::neon_matches_dalek` |
| ECDH P-256, P-384, P-521 | `agreement::{Algorithm, PrivateKey, PublicKey, Scalar, SharedSecret, ECDH_P256, ECDH_P384, ECDH_P521}` | `ecdh_secp*r1_test`, `ecdh_secp*r1_ecpoint_test`, `cavp/ecdsa` (key pairs and public key validation) | `fuzz::kx`, `fuzz::keys` | `crosschecks::ecdh`, `crosschecks::ecdh_stored`, `crosschecks::ecdh_scalars::p256` | ctgrind: the keys `mid::p256::from_bytes`, `mid::p256::generate`, `mid::p384::from_bytes`, `mid::p384::generate`, `mid::p521::from_bytes`, `mid::p521::generate`, `high::agreement::loads_in_constant_time` |
| ML-KEM-768 | `kem::{Algorithm, Ciphertext, DecapsulationKey, EncapsulationKey, SharedSecret, ML_KEM_768}` | `mlkem_768*_test` | `fuzz::kem`, `fuzz::keys` | `crosschecks::mlkem768::encapsulated_by_ours`, `high::kem::encapsulated_by_theirs` | ctgrind: `mid::mlkem768::keygen_internal`, `mid::mlkem768::encaps_internal` |
| Ed25519 signing | `signature::{Ed25519KeyPair, Ed25519Seed}` | RFC 8032: `mid::ed25519::test_rfc8032_test_vectors` | none, [planned](/quest/m3/confidence/fuzz-every-primitive.md); its seeds load in `fuzz::keys` | `crosschecks::ed25519::sign_verify`, `crosschecks::ed25519::seed_alone`, `crosschecks::ed25519::seed_and_public_key`, `crosschecks::ed25519_key_generation` | ctgrind: the seed `mid::ed25519::from_seed`, armv7's `mid::arm::ed25519::from_seed` |
| Ed25519 verification | `signature::{PublicKey, Signature, VerificationAlgorithm}`, `signature::verify::ED25519` | `ed25519_test` | `fuzz::verify`, `fuzz::keys` | `crosschecks::ed25519::small_order_public_keys` | |
| ECDSA signing | `signature::{EcdsaKeyPair, EcdsaScalar, EcdsaSigningAlgorithm}`, `signature::sign::{ECDSA_P256_SHA256_ASN1, ECDSA_P256_SHA256_FIXED, ECDSA_P384_SHA384_ASN1, ECDSA_P384_SHA384_FIXED, ECDSA_P521_SHA512_ASN1, ECDSA_P521_SHA512_FIXED}` | RFC 6979: `high::ecdsa::rfc6979_test_vectors`, `high::ecdsa::rfc6979_p521_test_vectors` | none, [planned](/quest/m3/confidence/fuzz-every-primitive.md); its keys load in `fuzz::keys` | `crosschecks::ecdsa`, `crosschecks::ecdsa_digest::theirs_verify_ours`, `crosschecks::pkcs8_attributes::ecdsa_and_rsa_refuse_v2`, `crosschecks::pkcs8_attributes::attributes` | ctgrind: the keys, as for ECDH, and `high::signature::ecdsa_signs_and_verifies_any_digest` |
| ECDSA verification | `signature::{PublicKey, Signature, VerificationAlgorithm}`, `signature::verify::{ECDSA_P256_SHA256_ASN1, ECDSA_P256_SHA256_FIXED, ECDSA_P256_SHA384_ASN1, ECDSA_P256_SHA512_ASN1, ECDSA_P384_SHA256_ASN1, ECDSA_P384_SHA384_ASN1, ECDSA_P384_SHA384_FIXED, ECDSA_P384_SHA512_ASN1, ECDSA_P521_SHA256_ASN1, ECDSA_P521_SHA384_ASN1, ECDSA_P521_SHA512_ASN1, ECDSA_P521_SHA512_FIXED}` | `ecdsa_secp*_test`, `cavp/ecdsa` | `fuzz::verify`, `fuzz::keys` | `crosschecks::public_key_forms`, `crosschecks::ecdsa_digest::ours_verify_theirs` | |
| RSA signing and key generation | `signature::{RsaKeyPair, RsaPssSaltLength, RsaSigningAlgorithm}`, `signature::sign::{RSA_PKCS1_SHA256, RSA_PKCS1_SHA384, RSA_PKCS1_SHA512, RSA_PSS_SHA256, RSA_PSS_SHA384, RSA_PSS_SHA512}`, `rsa::KeySize` | `rsa_pkcs1_*_sig_gen_test`, Wycheproof's primality tests: `mid::rsa_priv::generate::test_valid_primes` | none, [planned](/quest/m3/confidence/fuzz-every-primitive.md); its keys load in `fuzz::keys` | `crosschecks::rsa::sign_verify`, `crosschecks::rsa::pss_salt_lengths`, `crosschecks::rsa::key_generation_2048`, `crosschecks::rsa::key_generation_2048_soak`, `crosschecks::rsa::key_generation_3072`, `crosschecks::rsa::key_generation_4096`, `crosschecks::rsa::key_generation_6144`, `crosschecks::rsa::key_generation_8192`, `crosschecks::rsa::pkcs8_algorithms_agree` | ctgrind: private keys are marked when loaded, `mid::rsa_priv::generate::random_prime_one`; SDE: `low::x86_64::rsaz_avx512::ct_sde_rsa2048`, `low::x86_64::rsaz_avx512::ct_sde_rsa3072`, `low::x86_64::rsaz_avx512::ct_sde_rsa4096` |
| RSA verification | `signature::{PublicKey, RsaVerificationAlgorithm, Signature}`, `signature::verify::{RSA_PKCS1_SHA256, RSA_PKCS1_SHA384, RSA_PKCS1_SHA512, RSA_PSS_SHA256, RSA_PSS_SHA256_ANY_SALT, RSA_PSS_SHA384, RSA_PSS_SHA384_ANY_SALT, RSA_PSS_SHA512, RSA_PSS_SHA512_ANY_SALT}`, `signature::verify::legacy::{RSA_PKCS1_1024_SHA1, RSA_PKCS1_1024_SHA256, RSA_PKCS1_1024_SHA512, RSA_PKCS1_3072_SHA384, RSA_PKCS1_SHA1}`, `rsa::PublicKeyComponents` | `rsa_signature_*_test`, `rsa_pss_*_test`, `rsa_pkcs1_*_sig_gen_test` | `fuzz::verify`, `fuzz::keys` | `crosschecks::rsa::verification_agrees`, `crosschecks::rsa::refuses_modulus_below_2048_bits`, `crosschecks::rsa::refuses_exponent_over_33_bits`, `crosschecks::rsa::spki_forms_agree` | |
| RSA-OAEP | `rsa::{Ciphertext, DecryptingKey, EncryptingKey, OaepAlgorithm, Plaintext, OAEP_SHA256, OAEP_SHA384, OAEP_SHA512}`, `rsa::legacy::OAEP_SHA1` | `rsa_oaep_*_test` | `fuzz::oaep` | `crosschecks::rsa::encrypt_decrypt`, `crosschecks::rsa::decrypt_agrees` | ctgrind: private keys are marked when loaded, `high::oaep::stays_secret`, `high::pkcs1::encode_oaep`; SDE: as RSA signing |
| Key encodings | `encoding::{Pkcs8, Sec1, Spki}` | none: no published set, beyond the keys in the files above | `fuzz::keys` | `crosschecks::encodings` | none: a key is marked once parsed, and its DER's lengths are not secret |
| Constant-time comparison | `constant_time::verify` | none: no published set | none: it returns whether two slices are equal, which the differential test covers | `crosschecks::slice_comparison_matches_aws_lc_rs` | ctgrind: `high::constant_time::contents_stay_secret`, `low::generic::ct_equal::equiv` |
| Random bytes | `rand::fill` | none: the operating system's generator, which no vector can check | none, as for vectors | none, as for vectors | none: rind passes the bytes on |

Exports that are not primitives: `Error`, `KeyRejected`, `doc::inline_assembly_safety`, `cpu::Dit`, `cpu::MissingFeature`, `cpu::check`, `cpu::has_aes_hardware`.

[Wycheproof]: https://github.com/C2SP/wycheproof
