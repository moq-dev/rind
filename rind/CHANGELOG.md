# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.6](https://github.com/moq-dev/rind/compare/rind-v0.1.5...rind-v0.1.6) - 2026-11-02

### Fixed

- build on the declared MSRV, raised to 1.90 ([#199](https://github.com/moq-dev/rind/pull/199))
- *(hash)* admin/structure reports only real layering edges ([#197](https://github.com/moq-dev/rind/pull/197))
- *(rsa)* redraw q when it is within 2^(nlen/2 - 100) of p ([#204](https://github.com/moq-dev/rind/pull/204))
- *(fuzz)* allow the PKCS#8 v2 refusal without a public key for ECDSA and RSA ([#198](https://github.com/moq-dev/rind/pull/198))

### Other

- drop the redundant RSA key generation tests from the gate ([#201](https://github.com/moq-dev/rind/pull/201))
- *(x86-cpu)* run one SDE model per dispatch path set ([#205](https://github.com/moq-dev/rind/pull/205))

## [0.1.5](https://github.com/moq-dev/rind/compare/rind-v0.1.4...rind-v0.1.5) - 2026-11-01

### Other

- *(aarch64)* aws-lc's Montgomery multiplication for RSA at other sizes ([#179](https://github.com/moq-dev/rind/pull/179))

## [0.1.4](https://github.com/moq-dev/rind/compare/rind-v0.1.3...rind-v0.1.4) - 2026-11-01

### Fixed

- constant-time in debug builds ([#189](https://github.com/moq-dev/rind/pull/189))
- *(bench)* time forced CPU paths in release builds ([#181](https://github.com/moq-dev/rind/pull/181))

### Other

- aws-lc's one-pass ChaCha20-Poly1305 on x86_64 and aarch64 ([#190](https://github.com/moq-dev/rind/pull/190))
- *(x86_64)* square by bn_sqrx8x_internal, zeroing its scratch first ([#187](https://github.com/moq-dev/rind/pull/187))
- *(x86_64)* aws-lc's mulx and nohw Montgomery routines for RSA at every size ([#183](https://github.com/moq-dev/rind/pull/183))

## [0.1.3](https://github.com/moq-dev/rind/compare/rind-v0.1.2...rind-v0.1.3) - 2026-11-01

### Fixed

- *(rsa)* generate keys in constant time ([#182](https://github.com/moq-dev/rind/pull/182))
- fuzz the key loaders, take compressed key pair points, refuse ECDSA and RSA PKCS#8 v2 ([#166](https://github.com/moq-dev/rind/pull/166))

## [0.1.2](https://github.com/moq-dev/rind/compare/rind-v0.1.1...rind-v0.1.2) - 2026-11-01

### Added

- *(x86_64)* run on CPUs without SSSE3 ([#178](https://github.com/moq-dev/rind/pull/178))
- *(x86_64)* AES and GHASH without AVX or AES-NI ([#172](https://github.com/moq-dev/rind/pull/172))
- *(x86_64)* run on CPUs without AVX2 ([#171](https://github.com/moq-dev/rind/pull/171))
- *(x86_64)* run on CPUs without ADX ([#169](https://github.com/moq-dev/rind/pull/169))

### Fixed

- refuse trailing bytes after a PKCS#8 key ([#164](https://github.com/moq-dev/rind/pull/164))

### Other

- *(x86_64)* aws-lc's RSAZ for RSA-2048 without ADX ([#177](https://github.com/moq-dev/rind/pull/177))
- *(x86_64)* SSE-encoded AES-GCM and GHASH on every CPU ([#176](https://github.com/moq-dev/rind/pull/176))
- *(x86_64)* aws-lc's AES-NI CTR with AVX too ([#173](https://github.com/moq-dev/rind/pull/173))
- *(x86_64)* aws-lc's Montgomery multiplication for RSA without ADX ([#170](https://github.com/moq-dev/rind/pull/170))
- *(sha256)* aws-lc's AVX routine on Intel without SHA-NI ([#165](https://github.com/moq-dev/rind/pull/165))

## [0.1.1](https://github.com/moq-dev/rind/compare/rind-v0.1.0...rind-v0.1.1) - 2026-11-01

### Added

- *(aarch64)* run on CPUs without the crypto extension ([#157](https://github.com/moq-dev/rind/pull/157))
- accept 33-bit RSA public exponents ([#161](https://github.com/moq-dev/rind/pull/161))
- load PKCS#8 keys carrying attributes ([#160](https://github.com/moq-dev/rind/pull/160))
- *(signature)* export an ECDSA key's scalar and an Ed25519 key's seed ([#158](https://github.com/moq-dev/rind/pull/158))
- *(ring)* add rind-ring, ring 0.17's API on rind ([#151](https://github.com/moq-dev/rind/pull/151))
- *(hkdf)* HKDF-SHA384, HKDF-SHA512, and legacy HKDF-SHA1 ([#149](https://github.com/moq-dev/rind/pull/149))

### Other

- cheaper ECDSA and RSA key loads and ECDSA verification ([#159](https://github.com/moq-dev/rind/pull/159))

## [0.1.0](https://github.com/moq-dev/rind/compare/rind-v0.0.0...rind-v0.1.0) - 2026-10-31

### Added

- [**breaking**] errors by role, and RSA components take only an RSA algorithm ([#142](https://github.com/moq-dev/rind/pull/142))
- *(signature)* [**breaking**] one PublicKey, sign and verify constants, owned encodings, RSA key checks ([#140](https://github.com/moq-dev/rind/pull/140))
- [**breaking**] aead::Key, typed tags, legacy submodules, infallible HKDF expand ([#139](https://github.com/moq-dev/rind/pull/139))
- ECDH and ECDSA on P-521 ([#133](https://github.com/moq-dev/rind/pull/133))
- *(agreement,kem)* [**breaking**] PrivateKey::agree, public_key(), slice ciphertexts ([#137](https://github.com/moq-dev/rind/pull/137))
- *(pbkdf2)* PBKDF2-HMAC over SHA-1, SHA-256, SHA-384, and SHA-512 ([#127](https://github.com/moq-dev/rind/pull/127))
- *(signature)* legacy RSA verification and keys from components ([#130](https://github.com/moq-dev/rind/pull/130))
- *(aead)* QUIC header-protection keys ([#132](https://github.com/moq-dev/rind/pull/132))
- *(digest)* SHA-512/256 ([#128](https://github.com/moq-dev/rind/pull/128))
- constant-time slice comparison ([#131](https://github.com/moq-dev/rind/pull/131))
- SHA-384/512 from aws-lc's assembly on every backend ([#107](https://github.com/moq-dev/rind/pull/107))
- [**breaking**] rind::rand, deviation docs, and the aws-lc-rs API surface audit ([#94](https://github.com/moq-dev/rind/pull/94))
- *(rustls)* prefer ChaCha20-Poly1305 without AES hardware ([#92](https://github.com/moq-dev/rind/pull/92))
- [**breaking**] signature key pairs bound to algorithm constants ([#89](https://github.com/moq-dev/rind/pull/89))
- *(hkdf)* [**breaking**] typed HKDF output bound to an algorithm constant ([#90](https://github.com/moq-dev/rind/pull/90))
- *(aarch64)* AES-GCM from s2n-bignum's verified kernels ([#86](https://github.com/moq-dev/rind/pull/86))
- *(arm)* ARMv8 crypto extension for AES, GHASH, and SHA on armv7 ([#84](https://github.com/moq-dev/rind/pull/84))
- *(hmac)* [**breaking**] reusable HMAC keys bound to an algorithm constant ([#83](https://github.com/moq-dev/rind/pull/83))
- [**breaking**] agreement and kem modules with algorithm constants ([#79](https://github.com/moq-dev/rind/pull/79))
- *(aead)* [**breaking**] AEAD and cipher keys bound to an algorithm constant ([#75](https://github.com/moq-dev/rind/pull/75))
- [**breaking**] digest constants replace the Hash trait ([#77](https://github.com/moq-dev/rind/pull/77))
- [**breaking**] fold unnameable key errors into an exported KeyRejected ([#76](https://github.com/moq-dev/rind/pull/76))
- [**breaking**] rename truncated_ct_equal to verify_truncated and return a Result instead of panicking ([#53](https://github.com/moq-dev/rind/pull/53))
- *(aead)* [**breaking**] AesGcm::new refuses a bad key length ([#43](https://github.com/moq-dev/rind/pull/43))
- [**breaking**] AEADs refuse over-long messages ([#34](https://github.com/moq-dev/rind/pull/34))
- P-384 on armv7 over fiat-crypto's arithmetic ([#23](https://github.com/moq-dev/rind/pull/23))
- raw AES, AES-CTR, and ChaCha20 on armv7 ([#21](https://github.com/moq-dev/rind/pull/21))
- RSA key generation on armv7 ([#22](https://github.com/moq-dev/rind/pull/22))
- build armv7 on a libcrux backend ([#8](https://github.com/moq-dev/rind/pull/8))
- public CPU check naming the missing feature ([#12](https://github.com/moq-dev/rind/pull/12))
- [**breaking**] SHA-1 and HMAC-SHA1 for legacy protocols ([#7](https://github.com/moq-dev/rind/pull/7))
- HKDF under rind::hashing::hkdf ([#13](https://github.com/moq-dev/rind/pull/13))
- *(jsonwebtoken)* add rind-jsonwebtoken ([#9](https://github.com/moq-dev/rind/pull/9))
- raw AES, AES-CTR, and ChaCha20 under rind::cipher ([#6](https://github.com/moq-dev/rind/pull/6))
- [**breaking**] bootstrap rind from graviola ([#1](https://github.com/moq-dev/rind/pull/1))

### Fixed

- *(rind)* [**breaking**] declare the crate's license with every copied source ([#91](https://github.com/moq-dev/rind/pull/91))
- *(ed25519)* wipe the hashed seed and signing nonce, as aws-lc does ([#81](https://github.com/moq-dev/rind/pull/81))
- inherited wipes match aws-lc ([#73](https://github.com/moq-dev/rind/pull/73))
- *(rsa)* verify and sign with moduli of any bit length ([#68](https://github.com/moq-dev/rind/pull/68))
- wipe only what aws-lc wipes in the remaining paths ([#60](https://github.com/moq-dev/rind/pull/60))
- wipe only what aws-lc wipes ([#58](https://github.com/moq-dev/rind/pull/58))
- *(mlkem)* wipe ML-KEM intermediates and SHA-3 state on drop ([#52](https://github.com/moq-dev/rind/pull/52))
- *(hash)* wipe the SHA message schedule after each compress call ([#41](https://github.com/moq-dev/rind/pull/41))
- wipe HMAC and HMAC-DRBG state on drop ([#42](https://github.com/moq-dev/rind/pull/42))
- wipe HMAC's padded key block ([#30](https://github.com/moq-dev/rind/pull/30))
- refuse P-256 and P-384 coordinates at or above the field prime ([#25](https://github.com/moq-dev/rind/pull/25))

### Other

- README describes rind's own API, and MIGRATING.md maps every ring and aws-lc-rs item ([#145](https://github.com/moq-dev/rind/pull/145))
- *(signature)* check every ECDSA constant against aws-lc-rs ([#129](https://github.com/moq-dev/rind/pull/129))
- *(arm)* X25519 shared secret on BoringSSL's NEON ladder ([#120](https://github.com/moq-dev/rind/pull/120))
- *(x86_64)* AES-GCM on BoringSSL's VAES kernels for long messages ([#124](https://github.com/moq-dev/rind/pull/124))
- *(x86_64)* AES-GCM tails in one masked pass, hashed with one reduction ([#116](https://github.com/moq-dev/rind/pull/116))
- *(arm)* run aws-lc's ChaCha20 and NEON Poly1305 on armv7 ([#106](https://github.com/moq-dev/rind/pull/106))
- *(lints)* walk the in-place aarch64 AES-GCM kernels in the codegen job ([#117](https://github.com/moq-dev/rind/pull/117))
- *(arm)* X25519 and Ed25519 from curve25519-dalek ([#113](https://github.com/moq-dev/rind/pull/113))
- *(ec)* multiply secret P-256 and P-384 scalars by s2n-bignum ([#108](https://github.com/moq-dev/rind/pull/108))
- *(aarch64)* run s2n-bignum's by-8 AES-256-GCM kernels on cores with SHA3 ([#114](https://github.com/moq-dev/rind/pull/114))
- *(quest)* drop two low-payoff fastest quests, plan aarch64 alt kernels ([#112](https://github.com/moq-dev/rind/pull/112))
- *(aarch64)* run s2n-bignum's AES-GCM kernels in place ([#110](https://github.com/moq-dev/rind/pull/110))
- mark unverified code that measured faster than a verified alternative ([#105](https://github.com/moq-dev/rind/pull/105))
- *(p384)* multiply the generator by an affine comb ([#102](https://github.com/moq-dev/rind/pull/102))
- *(arm)* cache RSA's Montgomery setup and compute it in six squarings ([#101](https://github.com/moq-dev/rind/pull/101))
- run the armv7 job locally with `just armv7` ([#96](https://github.com/moq-dev/rind/pull/96))
- close the verified aarch64 AES-GCM setup quest ([#97](https://github.com/moq-dev/rind/pull/97))
- attribute every algorithm's source and license ([#88](https://github.com/moq-dev/rind/pull/88))
- stop clearing vector registers after secret operations ([#80](https://github.com/moq-dev/rind/pull/80))
- [**breaking**] stop tracking graviola ([#87](https://github.com/moq-dev/rind/pull/87))
- ctgrind on armv7, fixing what it finds in the arm backend ([#36](https://github.com/moq-dev/rind/pull/36))
- *(sha1)* run the AVX2 path's rounds in plain Rust ([#71](https://github.com/moq-dev/rind/pull/71))
- *(sha256)* AVX2 message schedule on x86_64 without SHA-NI ([#74](https://github.com/moq-dev/rind/pull/74))
- *(sha1)* AVX2 message schedule on x86_64 without SHA-NI ([#64](https://github.com/moq-dev/rind/pull/64))
- close the verification gaps, fixing two RSA signing bugs they found ([#62](https://github.com/moq-dev/rind/pull/62))
- *(hkdf)* key the PRK's HMAC once at extract ([#63](https://github.com/moq-dev/rind/pull/63))
- follow the move to moq-dev/rind ([#50](https://github.com/moq-dev/rind/pull/50))
- ctgrind ML-KEM, ECDSA nonces, and AES key setup ([#39](https://github.com/moq-dev/rind/pull/39))
- one workspace rust-version ([#33](https://github.com/moq-dev/rind/pull/33))
- ctgrind the adapter crates' secret paths ([#19](https://github.com/moq-dev/rind/pull/19))
- start rind at 0.1.0 and enable releases ([#2](https://github.com/moq-dev/rind/pull/2))
- update MLKEM impl strategy
- Add an ML-KEM performance note in README
- Update README to reflect the new aarch64 stitched AES-GCM.
- Update README for ML-KEM and SHA3
- Implement SHA3-256, SHA3-512, SHAKE128 and SHAKE256
- add ed25519
- Small usability improvements for the unit tests:
- 16-wide AVX512 AES-CTR
- Document and check intel adx CPU feature bit requirement
- Add a note about RSA keygen
- Correct misuse of wNAF terminology
- cut 0.2.0
- Improve SHA512 small input performance
- add badges
- update aarch64 gcm details
- Prepare 0.2.0-alpha.0
- Tone-down cautious language
- Remove misunderstanding about what s2n-bignum verifies
- add notes on CPUs
- Allow testing for optional CPU features
- Fix invalid SPDX expression
- Improve crate docs
- more
- updates
- Improve aarch64 ghash performance
- add technical details
- adjustments
- add p384
- update with chacha20
- remove cryptogams usage
- Support RSA-PSS signatures
- randomised deterministic signing
- rev
- Add logo?
- Add license tags to each new file
- aarch64 sha256 using intrinsics
- Provide RSA on aarch64
- Add readme
