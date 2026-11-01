# Migrating from ring and aws-lc-rs

This guide maps each ring 0.17 and aws-lc-rs 1.x item to rind's name, to the
[quest](quest/README.md) that adds it, or to why rind refuses it, and
surveys the crates that pick a crypto backend for you. ring's names match
aws-lc-rs's except where noted. A crate on ring that cannot change its code
renames [rind-ring](#rind-ring), ring's API on rind, to `ring`.

## Across the API

| aws-lc-rs | rind |
|---|---|
| A `&'static` algorithm, or an `hmac::Algorithm` or `hkdf::Algorithm` by value | always `&'static` |
| A `&dyn SecureRandom` argument | none: rind draws from the system's random source itself |
| A `_FOR_LEGACY_USE_ONLY` suffix | a `legacy` submodule, such as `digest::legacy::SHA1` |
| An allocated `Document`, `Vec`, or `Box` output | an owned value of fixed capacity, such as `signature::Pkcs8` |
| `error::Unspecified`, `error::KeyRejected` | `rind::Error`, by kind of call (see [error](#error)) |

## digest

| aws-lc-rs | rind |
|---|---|
| `digest(alg, data)`, `Context::{new, update, finish}`, `Digest`'s bytes | the same |
| `SHA256`, `SHA384`, `SHA512`, `SHA512_256` | the same |
| `SHA1_FOR_LEGACY_USE_ONLY` | `legacy::SHA1` |
| `SHA224`, `SHA3_256`, `SHA3_384`, `SHA3_512` (not in ring) | none; [aws-lc-rs extras](quest/m3/parity/aws-lc-extras.md) |
| `Algorithm::output_len()` | the same |
| `Algorithm::block_len()`, `chaining_len()`, `MAX_BLOCK_LEN`, `MAX_CHAINING_LEN`, `MAX_OUTPUT_LEN`, `SHA*_OUTPUT_LEN` | none; `output_len()` gives each length |
| `Context::algorithm()`, `Digest::algorithm()` | none |
| `Digest::import_less_safe` | none |

## hmac

| aws-lc-rs | rind |
|---|---|
| `Key::new(HMAC_SHA256, key)` | `Key::new(&HMAC_SHA256, key)` |
| `Key::generate(alg, rng)` | `rand::fill` a `tag_len()`-byte key, then `Key::new` |
| `Key::algorithm()` | the same, as `&'static` |
| `Context::{with_key, update, sign}`, `sign`, `Tag` | the same |
| `verify(key, data, tag)` | the same, failing with `Error::BadSignature` |
| `HMAC_SHA256`, `HMAC_SHA384`, `HMAC_SHA512` | the same |
| `HMAC_SHA1_FOR_LEGACY_USE_ONLY` | `legacy::HMAC_SHA1` |
| `HMAC_SHA224` | none; [aws-lc-rs extras](quest/m3/parity/aws-lc-extras.md) |
| `Algorithm::digest_algorithm()` | none; `Algorithm::tag_len()` gives the output length |
| `Signature`, `SigningContext`, `SigningKey`, `VerificationKey` (deprecated) | `Tag`, `Context`, `Key` |

## hkdf

| aws-lc-rs | rind |
|---|---|
| `Salt::new(HKDF_SHA256, salt)`, `extract` | `Salt::new(&HKDF_SHA256, salt)`, `extract` |
| `Salt::none(alg)` | `Salt::new(&alg, &[])`, which extracts the same key as RFC 5869's absent salt |
| `HKDF_SHA256`, `HKDF_SHA384`, `HKDF_SHA512` | the same |
| `HKDF_SHA1_FOR_LEGACY_USE_ONLY` | `legacy::HKDF_SHA1` |
| `prk.expand(info, len)?` | `prk.expand(info, len)`, which cannot fail; `Okm::fill` checks a byte length |
| your own `KeyType` | none: it is sealed, for a `usize` byte length or an `aead`, `aead::quic`, or `hmac` algorithm |
| `UnboundKey::from(okm)`, `HeaderProtectionKey::from(okm)`, `hmac::Key::from(okm)` | `aead::Key::from(okm)`, `HeaderProtectionKey::from(okm)`, `hmac::Key::from(okm)` |
| `Okm::fill(out)` | the same, for a `usize` length only |
| `Salt::from(okm)`, `Prk::from(okm)`, `Prk::new_less_safe` | none |
| `Salt::algorithm()`, `Okm::len()`, `Algorithm::hmac_algorithm()` | none |

## pbkdf2

| aws-lc-rs | rind |
|---|---|
| `derive(alg, iterations, salt, secret, out)` | `Secret::new(&alg, secret).derive(iterations, salt, out)?`, which fails with `Error::WrongLength` where aws-lc-rs panics on an overlong `out` |
| `verify(alg, iterations, salt, secret, previous)` | `Secret::new(&alg, secret).verify(iterations, salt, previous)` |
| `PBKDF2_HMAC_SHA256`, `PBKDF2_HMAC_SHA384`, `PBKDF2_HMAC_SHA512` | the same |
| `PBKDF2_HMAC_SHA1` | `legacy::PBKDF2_HMAC_SHA1` |

A `Secret` keys HMAC once, so deriving or verifying with several salts
reuses it. `verify` refuses a stored value shorter than the HMAC output with
`Error::WrongLength`, where ring and aws-lc-rs compare any prefix.

## aead

| aws-lc-rs | rind |
|---|---|
| `LessSafeKey::new(UnboundKey::new(&alg, key)?)` | `Key::new(&alg, key)?` |
| `SealingKey`, `OpeningKey`, `BoundKey`, `NonceSequence`, `nonce_sequence::{Counter32, Counter64}` and their builders | `Key`, given a `Nonce` per call from a sequence number the protocol keeps |
| `seal_in_place_append_tag(nonce, Aad::from(aad), in_out)` | `seal_in_place_append_tag(nonce, aad, in_out)`, with `aad: &[u8]` |
| `seal_in_place_separate_tag`, `open_in_place` | the same, with `aad: &[u8]` |
| `open_in_place_separate_tag(nonce, aad, tag, in_out, range)` | `open_in_place_separate_tag(nonce, aad, Tag::try_from(tag)?, ciphertext)` |
| `open_within(nonce, aad, in_out, range)` | `open_in_place` on the ciphertext's subslice, which leaves the plaintext there rather than moving it to the front |
| `Aad::from(aad)`, `Aad::empty()` | `aad`, `&[]` |
| `Nonce::assume_unique_for_key` | the same |
| `Nonce::try_assume_unique_for_key`, `Nonce::from` | `assume_unique_for_key`, given a `[u8; 12]` |
| `Tag`, ring's `Tag::try_from` | `Tag`, from `TryFrom<&[u8]>`, failing with `Error::WrongLength` |
| `Algorithm::{key_len, tag_len, nonce_len}` | the same |
| `NONCE_LEN`, `MAX_TAG_LEN`, `algorithm()` on each key | none; the `Algorithm` methods give each length |
| `AES_128_GCM`, `AES_256_GCM`, `CHACHA20_POLY1305` | the same |
| `AES_192_GCM`, `AES_128_GCM_SIV`, `AES_256_GCM_SIV` | none; [aws-lc-rs extras](quest/m3/parity/aws-lc-extras.md) |
| `RandomizedNonceKey::new(&AES_256_GCM, key)`, with 96-bit random nonces | `RandomizedNonceKey::new(&key)`, XChaCha20-Poly1305 with 192-bit random nonces, which never collide in practice |
| `RandomizedNonceKey::{seal_in_place_append_tag, open_in_place}` | the same, with the nonce a `RandomNonce` |
| `RandomizedNonceKey::seal_in_place_separate_tag` | none |
| `TlsRecordSealingKey`, `TlsRecordOpeningKey`, `TlsProtocolId` | `Key`; rind has no FIPS mode whose nonce rules they check |
| `open_separate_gather`, `seal_in_place_scatter`, `seal_out_of_place_scatter`, `prepare_nonce`, `SealingKeyPreparedNonce`, `OpeningKeyPreparedNonce`, `seal_in_place` (deprecated) | none |
| `chacha20_poly1305_openssh::{SealingKey, OpeningKey, KEY_LEN, TAG_LEN}` | none: only SSH transports use it, and rind has no SSH consumer |

### aead::quic

| aws-lc-rs | rind |
|---|---|
| `HeaderProtectionKey::new(&alg, key)`, `HeaderProtectionKey::from(okm)` | the same |
| `new_mask(sample)?` | `mask(&sample)`, which takes a `[u8; SAMPLE_LEN]` and cannot fail |
| `Sample`, `Algorithm::sample_len()` | `[u8; SAMPLE_LEN]`, `SAMPLE_LEN` |
| `Algorithm::key_len()`, `AES_128`, `AES_256`, `CHACHA20` | the same |
| `HeaderProtectionKey::algorithm()` | none |

## cipher

aws-lc-rs's `cipher` offers AES in several modes; rind's offers only what
protocols with their own integrity protection need. ring has none.

| aws-lc-rs | rind |
|---|---|
| `UnboundCipherKey::new(&AES_128, key)` and `EncryptingKey::ctr` or `DecryptingKey::ctr` | `AesCtr::new(&AES_128, key)?` |
| `less_safe_encrypt(in_out, EncryptionContext::Iv128(iv))`, `decrypt` | `apply_keystream(nonce, counter, in_out)?`, with `iv` as a 12-byte nonce and a big-endian 32-bit counter, refused rather than carried into the nonce when it would wrap |
| `AES_128`, `AES_256` | the same |
| `EncryptingKey::encrypt`, which picks a random IV | none: pick the nonce with `rand::fill` |
| `AES_192`, `DES_EDE3_FOR_LEGACY_USE_ONLY` and the other DES, the CBC, ECB, CFB, and OFB modes, `PaddedBlockEncryptingKey`, `PaddedBlockDecryptingKey`, `StreamingEncryptingKey`, `StreamingDecryptingKey` | none; [aws-lc-rs extras](quest/m3/parity/aws-lc-extras.md) |
| none | `Aes::new(&alg, key)?.encrypt_block(block)`, one AES block |
| none | `ChaCha20::new(key).apply_keystream(nonce, counter, in_out)?` |

## agreement

rind's agreement keys are ephemeral: each agrees once, and none loads or
exports a private key.

| aws-lc-rs | rind |
|---|---|
| `EphemeralPrivateKey::generate(alg, rng)`, `PrivateKey::generate(alg)` | `PrivateKey::generate(&alg)?` |
| `compute_public_key()?` | `public_key()`, which cannot fail |
| `agree_ephemeral(key, &UnparsedPublicKey::new(alg, peer), err, kdf)` | `key.agree(peer)?`, returning a `SharedSecret` wiped on drop |
| `agree(&key, peer, err, kdf)` | `key.agree(peer)?`, which consumes the key |
| `UnparsedPublicKey`, `ParsedPublicKey`, `ParsedPublicKeyFormat` | none: `agree` parses the peer's bytes for the key's algorithm |
| `PublicKey`'s bytes | `PublicKey`'s bytes: an uncompressed point, or X25519's 32 bytes |
| `X25519`, `ECDH_P256`, `ECDH_P384`, `ECDH_P521` | the same |
| `PrivateKey::from_private_key_der`, `from_private_key`, `as_der`, `as_be_bytes`, `PublicKey::as_der`, `as_be_bytes` | none: no consumer stores an agreement key |
| `algorithm()` on each type | none |

`agree` refuses a compressed or DER-encoded peer key, which aws-lc-rs takes.

## kem

| aws-lc-rs | rind |
|---|---|
| `DecapsulationKey::generate(&ML_KEM_768)` | the same |
| `encapsulation_key()?`, then `EncapsulationKey::key_bytes()?` | `public_key()`, and its bytes through `AsRef<[u8]>` |
| `EncapsulationKey::new(alg, bytes)`, `encapsulate()` | the same |
| `decapsulate(Ciphertext::from(bytes))` | `decapsulate(bytes)`, which consumes the key |
| `DecapsulationKey::new(alg, bytes)`, `DecapsulationKey::key_bytes()` | none: decapsulation keys are ephemeral |
| `ML_KEM_512`, `ML_KEM_1024` | none; [aws-lc-rs extras](quest/m3/parity/aws-lc-extras.md) |
| `algorithm()`, `Algorithm::id()`, `AlgorithmId`, `AlgorithmIdentifier` | none |

ring has no `kem`.

## signature

| aws-lc-rs | rind |
|---|---|
| `UnparsedPublicKey::new(alg, bytes).verify(m, s)` | `PublicKey::new(alg, bytes)?.verify(m, s)` |
| `UnparsedPublicKey::parse`, `ParsedPublicKey::new(alg, bytes)`, `verify_sig` | `PublicKey::new(alg, bytes)`, `verify` |
| `RsaPublicKeyComponents::verify(alg, m, s)`, `to_parsed_public_key(alg)` | `components.to_public_key(alg)?.verify(m, s)` |
| `verify_digest`, `verify_digest_sig`, `sign_digest` | none: rind hashes the message itself |
| `ParsedPublicKey::algorithm()`, `as_der()` | none; the key's bytes through `AsRef<[u8]>`, or a key pair's `to_spki()` |
| `VerificationAlgorithm` trait, `EcdsaVerificationAlgorithm`, `EdDSAParameters` | `VerificationAlgorithm` |
| `RsaParameters` | `RsaVerificationAlgorithm`, which `PublicKey::new` also takes |
| `RsaParameters::{with_pss_salt_length, public_modulus_len, min_modulus_len, max_modulus_len}`, `RsaPssSaltLength` | none: a PSS salt is as long as its digest, aws-lc-rs's default |
| `EcdsaSigningAlgorithm`, `RsaEncoding`, `RsaSignatureEncoding` | `EcdsaSigningAlgorithm`, `RsaSigningAlgorithm` |
| `ECDSA_P256_SHA256_ASN1_SIGNING` and the other `_SIGNING` | `sign::ECDSA_P256_SHA256_ASN1` |
| `ECDSA_P256_SHA256_ASN1`, `ED25519`, and the other verification constants | `verify::ECDSA_P256_SHA256_ASN1`, `verify::ED25519` |
| ECDSA with SHA-1, SHA-224, or SHA-3, on secp256k1 (`P256K1`), or P-521 signing or `_FIXED` with another hash than SHA-512 | none; [aws-lc-rs extras](quest/m3/parity/aws-lc-extras.md) |
| `RSA_PKCS1_SHA256`, `RSA_PSS_SHA256`, and their SHA-384 and SHA-512 | `sign::RSA_PKCS1_SHA256`, `sign::RSA_PSS_SHA256`, and so on |
| `RSA_PKCS1_2048_8192_SHA256`, `RSA_PSS_2048_8192_SHA256`, and their SHA-384 and SHA-512 | `verify::RSA_PKCS1_SHA256`, `verify::RSA_PSS_SHA256`, and so on |
| `RSA_PKCS1_3072_8192_SHA384` | `verify::legacy::RSA_PKCS1_3072_SHA384` |
| `RSA_PKCS1_1024_8192_SHA1_FOR_LEGACY_USE_ONLY`, `_SHA256_`, `_SHA512_` | `verify::legacy::RSA_PKCS1_1024_SHA1`, `RSA_PKCS1_1024_SHA256`, `RSA_PKCS1_1024_SHA512` |
| `RSA_PKCS1_2048_8192_SHA1_FOR_LEGACY_USE_ONLY` | `verify::legacy::RSA_PKCS1_SHA1` |
| `KeyPair::public_key()`, ring's `RsaKeyPair::public()` | inherent `public_key()`, a `PublicKey`; `RsaKeyPair::public_key(&sign::X)` |
| `Ed25519PublicKey`, `EcdsaPublicKey`, `RsaSubjectPublicKey` | `PublicKey` |
| `generate_pkcs8(rng)`, `generate_pkcs8(alg, rng)`, `generate_pkcs8v1` | `generate(..)?.to_pkcs8()` |
| `EcdsaKeyPair::from_pkcs8(alg, der)`, ring's `(alg, der, rng)` | `from_pkcs8(&alg, der)` |
| `EcdsaKeyPair::from_private_key_and_public_key`, ring's with an `rng` | the same, with no random source |
| `EcdsaKeyPair::from_private_key_der` | `from_sec1`, which refuses PKCS#8 |
| `RsaKeyPair::from_der` | `from_pkcs1` |
| `RsaKeyPair::from_components`, `KeyPairComponents` | none: load the key as PKCS#1 or PKCS#8 |
| `Ed25519KeyPair::from_pkcs8_maybe_unchecked` | `from_pkcs8`, which takes v1 and v2 |
| `Ed25519KeyPair::from_seed_unchecked` | `from_seed_and_public_key`, which checks the public key |
| `to_pkcs8()`, `to_pkcs8v1()`, `public_key().as_der()`, each an allocated `Document` | `to_pkcs8()`, `to_spki()`, each of fixed capacity; `Pkcs8` is wiped on drop |
| `EcdsaKeyPair::sign(rng, m)`, `RsaKeyPair::sign(alg, rng, m, &mut sig)`, `Ed25519KeyPair::try_sign` | `sign(m)`, `sign(alg, m)`, which take no random source and return a `Signature` |
| `rsa::KeySize`, `RsaKeyPair::generate(size)` | `RsaKeySize`, which adds `Rsa6144`, and `generate(size)` |
| `EcdsaKeyPair::private_key().as_be_bytes()` (not in ring) | `to_scalar()`, an `EcdsaScalar` wiped on drop |
| `Ed25519KeyPair::seed()?.as_be_bytes()` (not in ring) | `to_seed()`, an `Ed25519Seed` wiped on drop |
| `EcdsaKeyPair::private_key().as_der()`, `public_modulus_len()`, `algorithm()`, `generate_fips` | none |
| `ED25519_PUBLIC_KEY_LEN` | none: always 32 |
| `rsa::PublicKey::from_der` | `PublicKey::new(&verify::RSA_PKCS1_SHA256, der)`, for one algorithm and PKCS#1 DER |
| `rsa::PublicKey::{modulus, exponent, modulus_len}`, `PublicKeyComponents::from(&key)` | none |
| `PqdsaKeyPair`, `ML_DSA_65` and the other ML-DSA items | none; [aws-lc-rs extras](quest/m3/parity/aws-lc-extras.md) |

`PublicKey::new` refuses a compressed ECDSA point and a
`SubjectPublicKeyInfo`, both of which aws-lc-rs takes.

Every private key loader refuses bytes after the encoded key, which
aws-lc-rs ignores and ring refuses.

## rsa

rind signs and verifies with RSA through `signature`, and encrypts with none.

| aws-lc-rs | rind |
|---|---|
| `OaepPublicEncryptingKey`, `OaepPrivateDecryptingKey`, `OAEP_SHA256_MGF1SHA256` and the other OAEP items, `PublicEncryptingKey`, `PrivateDecryptingKey`, `EncryptionAlgorithmId` | none; [aws-lc-rs extras](quest/m3/parity/aws-lc-extras.md) |
| `Pkcs1PublicEncryptingKey`, `Pkcs1PrivateDecryptingKey` | none: PKCS#1 v1.5 encryption invites padding-oracle attacks |

## constant_time

| aws-lc-rs | rind |
|---|---|
| `verify_slices_are_equal(a, b)` | `verify(a, b)`, failing with `Error::WrongLength` for unequal lengths and `Error::NotEqual` for unequal contents |

## rand

No rind call takes a random source, so there is nothing to pass one to.

| aws-lc-rs | rind |
|---|---|
| `SystemRandom::new().fill(out)`, `rand::fill(out)` | `rand::fill(out)` |
| `generate::<[u8; N]>(rng)?.expose()` | `rand::fill` into a `[u8; N]` |
| `SecureRandom`, `RandomlyConstructable`, `Random` | none |

## error

aws-lc-rs's `error::Unspecified` and `error::KeyRejected` become one
`rind::Error`, whose variant depends on the kind of call. ring's names match.
`Error` is `#[non_exhaustive]`, so a `match` on it needs a wildcard arm.

| aws-lc-rs | rind |
|---|---|
| `KeyRejected`, from loading a key pair | `Error::KeyRejected` |
| `Unspecified`, from a peer's or public key that is malformed, off the curve, or the wrong length | `Error::KeyRejected`, from `PublicKey::new`, `agree`, or `EncapsulationKey::new` |
| `KeyRejected::description_()` | `KeyRejected`'s `Display` |
| `Unspecified`, from `verify`, `hmac::verify`, or `pbkdf2::verify` | `Error::BadSignature` |
| `Unspecified`, from `open_in_place` | `Error::DecryptFailed` |
| `Unspecified`, from a symmetric key, nonce, tag, or output of the wrong length | `Error::WrongLength` |
| `Unspecified`, from `SystemRandom::fill` or `generate` | `Error::RngFailed` |
| `Unspecified`, from `constant_time::verify_slices_are_equal` | `Error::NotEqual` |
| `Unspecified`, from RSA signing or ECDH when an internal check fails | `Error::Fault` |

## cpu

ring and aws-lc-rs detect CPU features and fall back to slower code. rind
requires its features (see the README's Limitations), panics on a CPU
missing one, and has no fallback.

| aws-lc-rs | rind |
|---|---|
| none | `cpu::check()`, at startup, returns `cpu::MissingFeature` naming the feature |
| none | `cpu::has_aes_hardware()`, for preferring ChaCha20-Poly1305 where AES runs in software |

## Other modules

| aws-lc-rs | rind |
|---|---|
| `cmac`, `key_wrap`, `kdf` (KBKDF and SSKDF), `tls_prf` | none; [aws-lc-rs extras](quest/m3/parity/aws-lc-extras.md) |
| `pkcs8::Document` | `signature::Pkcs8`, `signature::Spki` |
| `encoding`'s `AsDer`, `AsBigEndian`, and `AsRawBytes` | `to_pkcs8()` and `to_spki()`; an ECDSA key pair's `to_scalar()` and an Ed25519 key pair's `to_seed()`; other raw keys none |
| `io::Positive`, `io::der`, `iv::FixedLength`, `test`, `test_file!`, `unstable`, and ring's `deprecated_test` | none |
| `init`, `try_fips_mode`, `fips_mode`, `try_fips_self_test`, `fips_version`, `try_fips_cpu_jitter_entropy`, `fips_cpu_jitter_entropy`, `awslc_version` | none: rind has no C library to initialize and no FIPS module |

## Adapter crates

Each `rind-*` crate stands in for a crate's aws-lc-rs or ring backend. rind
panics on a CPU missing a feature it requires, so every adapter entry point
that is a function refuses one with `rind::cpu::MissingFeature` instead. A
static that the upstream crate requires, such as `DEFAULT_PROVIDER`, cannot,
and neither can rind-ring, whose signatures are ring's, so call
`rind::cpu::check()` before using them.

### rind-ring

rind-ring offers ring 0.17's API name for name, so a crate on ring swaps it
in with `ring = { package = "rind-ring", version = "0.1" }` and no code
changes. The rename reaches only that crate: a dependency that names ring,
such as rustls with its `ring` feature, still builds ring, since Cargo cannot
patch it with a crate of another name. It panics wherever ring panics, so
its signatures stay ring's. Its [README](rind-ring/README.md) lists the
items it leaves out and the inputs it refuses where ring takes them.

### rind-rustls

rind-rustls mirrors the layout of rustls's own providers.

| rustls `crypto::aws_lc_rs` | rind-rustls |
|---|---|
| `default_provider()` | `default_provider()?` |
| `DEFAULT_CIPHER_SUITES`, `ALL_CIPHER_SUITES` | the same, preferring AES-128-GCM to AES-256-GCM; `default_provider()` puts ChaCha20-Poly1305 first where rind runs AES without CPU instructions |
| `DEFAULT_KX_GROUPS` | the same: X25519MLKEM768, X25519, P-256, then P-384 |
| `ALL_KX_GROUPS` | X25519MLKEM768, SECP256R1MLKEM768, X25519, P-256, P-384, P-521, then MLKEM768 |
| `cipher_suite::*` | the same nine suites |
| `kx_group::X25519`, `SECP256R1`, `SECP384R1`, `X25519MLKEM768`, `SECP256R1MLKEM768`, `MLKEM768` | the same, plus `SECP521R1` |
| `kx_group::MLKEM1024` | none; [rustls provider parity](quest/m3/parity/rustls.md) |
| `Ticketer::new()` | the same, which also refuses a CPU missing a feature |
| `sign::any_supported_type` and the other `sign` loaders, `hpke` | none; load keys through the provider's `key_provider` |

rind-rustls signs with RSA, ECDSA P-256, P-384, and P-521, and Ed25519 keys,
and verifies what aws-lc-rs's provider does, short of ML-DSA, which it neither
signs nor verifies; see [rustls provider parity](quest/m3/parity/rustls.md).

### rind-rcgen

`rind_rcgen::KeyPair` replaces `rcgen::KeyPair` for ECDSA P-256 and P-384,
Ed25519, and RSA with PKCS#1 v1.5. It cannot sign with P-521: rcgen names
those algorithms only with its `aws_lc_rs` feature.

| rcgen | rind-rcgen |
|---|---|
| `KeyPair::generate()` | `KeyPair::generate(&PKCS_ECDSA_P256_SHA256)` |
| `KeyPair::generate_for(alg)` | `KeyPair::generate(alg)`; RSA fails with `KeyGenerationUnavailable` |
| `KeyPair::from_pkcs8_der_and_sign_algo(der, alg)` | `KeyPair::from_pkcs8(alg, der)` |
| `KeyPair::from_der_and_sign_algo`, `from_pem`, `TryFrom` | none; convert the key to PKCS#8 and pass its algorithm |
| `serialize_der()`, `serialized_der()`, `PrivatePkcs8KeyDer::from(&key)` | `to_pkcs8()`, wiped on drop |
| `Error::RingKeyRejected`, `RingUnspecified` | the same variants, with rind's reason for a refused key |

### rind-dimpl, rind-object-store, rind-jsonwebtoken, and rind-instant-acme

| aws-lc-rs backend | rind |
|---|---|
| dimpl's `crypto::aws_lc_rs::default_provider()` | `rind_dimpl::default_provider()?` |
| object_store's `aws`, `azure`, and `gcp` features | the `*-base` features, with `with_crypto_provider(rind_object_store::default_provider()?)` |
| jsonwebtoken's `crypto::aws_lc::DEFAULT_PROVIDER` | `rind_jsonwebtoken::DEFAULT_PROVIDER`, after `rind::cpu::check()?` |
| instant-acme's built-in provider | `Account::builder(http, &rind_instant_acme::DEFAULT_PROVIDER)`, after `rind::cpu::check()?` |

## Crates with their own crypto backend

Surveyed on 2026-10-31 against each crate's latest release, by reading its
features and source; none were built. A migrated graph should give no output
from `cargo tree -e normal,build -i ring` or `-i aws-lc-sys`.

"Install" means calling `rind_rustls::default_provider()?.install_default()`
before the crate builds its TLS config. Crates that read rustls's process
default panic without one, and a few (jsonrpsee, pingora, tauri on mobile)
install ring's if nothing is installed first.

- **rind-rustls**: TLS runs through rustls. Pick the listed features and
  install or pass rind-rustls's provider.
- **rind-x**: an existing adapter crate covers it.
- **Pure Rust**: its default build, or the listed features, use neither.
- **Adapter**: a new `rind-*` crate could cover it through a public hook.
  [Adapters](#adapters) says which are worth building.
- **Unsupported**: ring or aws-lc-rs is hard-wired. The cell names the
  alternative or the upstream change that would fix it.

### TLS and HTTP

| Crate | What ties it | On rind |
|---|---|---|
| rustls 0.23 | `ring` and `aws_lc_rs` features pick a provider | **rind-rustls**: `default-features = false`, `std`, `tls12` |
| rustls-webpki 0.103 | `ring` and `aws-lc-rs` fill `ALL_VERIFICATION_ALGS` | **rind-rustls**: no features; direct callers pass the provider's `signature_verification_algorithms.all` |
| rustls-platform-verifier 0.7 | none | **rind-rustls**: `Verifier::new(provider)` |
| tokio-rustls 0.26, futures-rustls 0.26 | default `aws_lc_rs` | **rind-rustls**: `default-features = false`, `logging`, `tls12` |
| hyper-rustls 0.27 | default `aws-lc-rs` | **rind-rustls**: `default-features = false` and a `with_provider_and_*` builder; `with_native_roots()` and its siblings need ring or aws-lc-rs |
| reqwest 0.13 | default `rustls` is aws-lc-rs | **rind-rustls**: `rustls-no-provider`, install. `http3` always enables aws-lc-rs |
| ureq 3 | default `rustls` is ring | **rind-rustls**: `rustls-no-provider` (marked unstable) and a roots feature |
| axum-server 0.8 | `tls-rustls` is aws-lc-rs | **rind-rustls**: `tls-rustls-no-provider`, install |
| actix-web 4, actix-tls 3 | none | **rind-rustls**: `rustls-0_23`, with a config built on rind-rustls |
| tonic 0.14 | `tls-ring`, `tls-aws-lc` | **rind-rustls**: `tls-native-roots` or `tls-webpki-roots` alone (a server-only build needs `_tls-any`), install |
| tungstenite 0.30, tokio-tungstenite 0.30 | none | **rind-rustls**: a `rustls-tls-*-roots` feature, install |
| tokio-websockets 0.13 | handshake SHA-1 from ring, aws-lc-rs, or OpenSSL | **rind-rustls**: `sha1_smol` and `rustls-bring-your-own-connector` |
| lettre 0.11 | `rustls-tls` is ring | **rind-rustls**: `rustls-no-provider`, install |
| kube 4 | default `rustls-tls` with `ring` | **rind-rustls**: `client` and `rustls-tls`, install. `oidc` and `oauth` need ring |
| async-nats 0.51 | default `ring`; `crypto` hashes with it | **rind-rustls**: without `ring`, `crypto`, or `object-store`, install |
| mysql_async 0.37 | `default-rustls` is aws-lc-rs | **rind-rustls**: `default-rustls-no-provider`, install |
| tokio-postgres-rustls 0.14 | optional, off by default | **rind-rustls**: default features |
| bollard 0.21 | `ssl` is ring | **rind-rustls**: `ssl_providerless`, install |
| ldap3 0.12 | `tls-rustls-*`; `gssapi` and `ntlm` call ring | **rind-rustls**: `tls-rustls` and `rustls-provider`, install; not `gssapi` or `ntlm` |
| metrics-exporter-prometheus 0.18 | `push-gateway` is aws-lc-rs | **rind-rustls**: `push-gateway-no-tls-provider`, install |
| tauri 2 | mobile `rustls-tls` installs ring | **rind-rustls**: desktop needs nothing; mobile skips `rustls-tls`; tauri-plugin-http goes through reqwest 0.12's `rustls-tls-native-roots-no-provider` |
| AWS SDK: aws-config 1, aws-smithy-http-client 1 | `default-https-client` is aws-lc-rs; the legacy `rustls` default is ring | **rind-rustls** only under `--cfg aws_sdk_unstable`, through `CryptoMode::Custom`; otherwise Adapter. Request signing (aws-sigv4) is pure Rust |
| poem 3 | `rustls` calls aws-lc-rs; `acme*` calls ring | Adapter: a TLS `Acceptor` over tokio-rustls |
| sqlx 0.9 | `tls-rustls-*` hard-code ring's or aws-lc-rs's provider | Unsupported: needs a no-provider feature upstream |
| mongodb 3 | hard-codes the provider | Unsupported: needs a no-provider feature upstream |
| fred 10 | rustls only behind `enable-rustls` (aws-lc-rs) or `enable-rustls-ring` | Unsupported: needs a no-provider feature upstream |
| rskafka 0.6 | `transport-tls` enables ring | Unsupported: `tls_config` takes a rind-rustls config, but ring stays linked |
| jsonrpsee 0.26 | `tls` enables and installs ring | Unsupported over TLS |
| pingora 0.9 | pingora-rustls depends on ring | Unsupported |
| tiny_http 0.12 | `ssl-rustls` is rustls 0.20 | Unsupported over TLS |
| webpki 0.22, sct 0.7 | ring, unconditionally | Unsupported: legacy; move to rustls 0.23 and rustls-webpki |

### QUIC, WebRTC, and peer-to-peer

| Crate | What ties it | On rind |
|---|---|---|
| quinn 0.11, quinn-proto 0.11, h3-quinn | `rustls` is an alias for `rustls-ring`; the Retry tag, reset key, and token key call ring or aws-lc-rs | Unsupported: use noq, or ask quinn for a provider-only `rustls` feature |
| noq 1.4 | default `ring` | **rind-rustls**: `rustls` without `ring`, plus the caller's `HmacKey` and `HandshakeTokenKey` on rind's HMAC, HKDF, and AES-256-GCM |
| iroh 1.4 | default `tls-ring` picks the provider | **rind-rustls**: `default-features = false`, `Endpoint::builder().crypto_provider(..)`. iroh-relay's `server` enables ring |
| wtransport 0.7 | needs `ring` or `aws-lc-rs`, and quinn's defaults | Unsupported |
| s2n-quic 1 | s2n-quic-crypto always links aws-lc-rs | Unsupported |
| quiche 0.30 | BoringSSL | Unsupported: C |
| dimpl 0.9 | default aws-lc-rs | **rind-dimpl** |
| str0m | default aws-lc-rs; its provider interface is unreleased | Adapter: rind-str0m covered it and was removed for lack of a consumer |
| webrtc 0.21 (rtc 0.21) | default `crypto-ring`, or `crypto-aws-lc-rs` | Unsupported: `RTCCryptoProvider` could carry an adapter, but none is planned without a consumer |
| webrtc-dtls 0.12, stun 0.17, turn 0.17 | ring, unconditionally | Unsupported: move to webrtc 0.21 |
| libp2p-tls 0.7, libp2p-quic 0.14, libp2p-noise 0.47 | aws-lc-rs and ring, unconditionally | Unsupported: needs a provider hook upstream |
| snow 0.10 | opt-in `ring-resolver` | **Pure Rust** by default. Adapter through `CryptoResolver`, once rind loads static X25519 keys |
| boringtun 0.7 | ring's ChaCha20-Poly1305 and constant-time comparison | Unsupported |

### DNS

| Crate | What ties it | On rind |
|---|---|---|
| hickory-proto, hickory-net, hickory-resolver 0.26 | TLS, HTTPS, and QUIC need a `*-ring` or `*-aws-lc-rs` feature; DNSSEC validation calls them internally | Unsupported: `with_tls_config` takes a rind-rustls config, but ring stays linked. Plain DNS is unaffected. rind has every primitive DNSSEC needs |
| domain 0.12 | DNSSEC and TSIG need ring or OpenSSL | Unsupported: its backend is a closed enum |

### Certificates, ACME, and tokens

| Crate | What ties it | On rind |
|---|---|---|
| rcgen 0.14 | default `ring`, or `aws_lc_rs`, gates `KeyPair` | **rind-rcgen**: ECDSA P-256 and P-384, Ed25519, and loaded RSA keys. Without rcgen's `crypto` feature, set the serial number and `key_identifier_method` yourself, or the subject key identifier is empty |
| instant-acme | 0.8 calls aws-lc-rs or ring; the unreleased 0.9 takes a `CryptoProvider` | **rind-instant-acme** on 0.9. `Order::finalize` needs ring or aws-lc-rs; call `finalize_csr` with a CSR from rcgen on rind-rcgen |
| rustls-acme 0.15, tokio-rustls-acme 0.9 | account keys and CSRs call ring or aws-lc-rs | Unsupported: use instant-acme on rind-instant-acme |
| x509-parser 0.18 | `verify` is ring, `verify-aws` aws-lc-rs | Unsupported: verify `tbs_certificate` with `rind::signature` instead |
| x509-certificate 0.25, cryptographic-message-syntax 0.28 | ring types in their public API | Unsupported |
| sigstore 0.14, tough 0.24 | aws-lc-rs, unconditionally | Unsupported |
| jsonwebtoken 11 | optional `aws_lc_rs` | **rind-jsonwebtoken**, every algorithm. `rust_crypto` is the pure-Rust alternative |
| jwtk 0.5 | default `aws-lc` for RSA verification and JWK conversion | Adapter, for caller-held keys only |
| biscuit 0.8, rusty_paseto 0.10, paseto 2 | ring, unconditionally | Unsupported |
| passkey 0.6 (passkey-crypto) | optional `aws-lc-rs` | **Pure Rust** by default |
| tame-oauth 0.10 | `jwt` is ring | Unsupported |
| gcp_auth 0.12 | default `ring` for TLS and service-account signing | **rind-rustls** without `ring` or `aws-lc-rs`; service-account keys need a signing hook upstream |
| google-cloud-auth 1 | defaults are aws-lc-rs | **rind-rustls**: `default-features = false`, install; signing loads keys through the installed provider. `idtoken` also installs rind-jsonwebtoken |
| yup-oauth2 12 | default `ring` for TLS and service-account signing | **rind-rustls** for user flows, through `with_client` and hyper-rustls; service accounts need a signing hook upstream |
| matrix-sdk-crypto 0.19 | opt-in `rust-x509-verifier-impl` | **Pure Rust** without it |

### Storage, databases, and other

| Crate | What ties it | On rind |
|---|---|---|
| object_store 0.14 | `aws`, `gcp`, `azure` and `http` enable aws-lc-rs | **rind-object-store**, with the `*-base` features; HTTPS through reqwest on rind-rustls |
| parquet 60 | `encryption` calls ring | Unsupported |
| russh 0.65 | default `aws-lc-rs`, or `ring`, for its AES-GCM and ChaCha20-Poly1305 transport | Unsupported: its cipher trait is private |
| scram 0.6 | ring, unconditionally | Unsupported |
| ethereum_hashing 0.8 | default `ring` for SHA-256 | **Pure Rust** on x86_64; other targets need ring |

## Adapters

No new adapter is planned (maintainer, 2026-10-31):

- **quinn**: its rustls integration cannot be built without ring or
  aws-lc-rs, so an adapter would carry its own port of quinn's
  `crypto::rustls` session. noq, quinn's fork, already runs on rind-rustls.
- **webrtc**: `rtc_crypto::RTCCryptoProvider` covers all of its crypto, and
  rind lacks only MD5 (for TURN's long-term credentials) and the AES-CCM and
  AES-CBC DTLS suites, but no consumer asks for it.

Nor are these worth a crate:

- **AWS SDK**: the adapter would be a whole HTTP client; stabilizing
  `CryptoMode::Custom` upstream needs none.
- **snow**: its default backend is already pure Rust, and rind cannot yet
  load a static X25519 key or hash with BLAKE2.
- **poem** and **jwtk**: each is a few lines of the caller's code over
  tokio-rustls or rind's signatures.
