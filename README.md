<h1 align="center">rind</h1>
<img width="40%" align="right" src="https://raw.githubusercontent.com/moq-dev/rind/main/admin/picture.png">

> **rind** is a compendium of **high quality**,
> **fast** and **easy to build** cryptography for Rust, aimed
> at use with [rustls](https://github.com/rustls/rustls) and
> [MoQ](https://github.com/moq-dev/moq).

rind began as a fork of [Graviola](https://github.com/ctz/graviola) by Joe
Birr-Pixton, and no longer tracks it. It adds what MoQ needs to drop C
cryptography entirely; the plan lives in [`quest/`][quests]. Coming from
ring or aws-lc-rs? [MIGRATING.md][migrating] maps their API to rind's, and
[rind-ring][] offers ring's API as is.

*High quality*: rind incorporates assembler routines
from the [s2n-bignum] project.  These have been formally proven
to correctly implement the desired mathematical operation.

*Fast*: rind beats or is competitive with other cryptography
libraries for Rust.  `cargo bench` compares it with aws-lc-rs, *ring*,
and RustCrypto.

*Easy and fast to build*: no C compiler, assembler or other tooling
needed: just the Rust compiler.  Compiles in seconds.

## Status

This project is very new, so exercise due caution.  The overriding
goal of this crate is for use with `rustls` via [rind-rustls][],
but there is also a public API for general-purpose use.

[![Build Status](https://img.shields.io/github/actions/workflow/status/moq-dev/rind/build.yml)](https://github.com/moq-dev/rind/actions/workflows/build.yml?query=branch%3Amain)
[![Latest release](https://img.shields.io/crates/v/rind)](https://crates.io/crates/rind)
[![Documentation](https://img.shields.io/docsrs/rind)](https://docs.rs/rind/)

## Goals

- [x] Fast and simple compilation
    - [x] `cargo build` takes seconds, and requires only rustc
- [x] Competitive performance (with *ring*, aws-lc-rs, and rustcrypto)
- [x] Uses formally-verified code from other projects (where it is as fast)
- [x] Intended to provide algorithms in wide use on web
- [x] Intended for use as a rustls `CryptoProvider`, via [rind-rustls][].

## Limitations

`aarch64`, `x86_64`, and 32-bit `arm` architectures only.

- `aarch64` requires the `neon` CPU feature. Where the CPU has the crypto
  extension (`aes`, `pmull`, and `sha2`), as the Raspberry Pi 5 and most
  aarch64 servers and phones do, AES, GHASH, SHA1, and SHA256 run on its
  instructions. Without it, as on the Raspberry Pi 4, CM4, and Zero 2 W, they
  run [aws-lc]'s NEON and scalar assembly instead (see
  [Algorithms](#algorithms)), `rind::cpu::has_aes_hardware()` is false, and
  rind-rustls and rind-dimpl prefer ChaCha20-Poly1305.
- `x86_64` runs on every x86_64 CPU. Without `aes` and `pclmulqdq`, as on
  Core 2 and Nehalem, AES and GHASH run [aws-lc]'s SSSE3 assembly instead
  (see [Algorithms](#algorithms)), `rind::cpu::has_aes_hardware()` is false,
  and rind-rustls and rind-dimpl prefer ChaCha20-Poly1305. Without `avx2`, as
  on Sandy Bridge, Ivy Bridge, and AMD's Bulldozer and Jaguar cores,
  ChaCha20-Poly1305 runs [aws-lc]'s SSE4.1 assembly, ChaCha20, SHA1, and
  SHA256 its SSSE3 assembly, or for SHA its AVX assembly on Intel's cores,
  ML-KEM's arithmetic runs a Rust port of [mlkem-native]'s portable C, and
  table lookups use SSE2 (see [Algorithms](#algorithms)). Without `sse4.1`,
  as on the first Core 2s and Atoms and AMD's Bobcat, ChaCha20 and Poly1305
  run in separate passes.
  Without `ssse3` either, as on Intel's CPUs before Core 2, AMD's before
  Bobcat and Bulldozer, and QEMU's default `qemu64` model, AES and GHASH run
  Rust ports of [aws-lc]'s constant-time SSE2 and integer C, and ChaCha20,
  SHA1, and SHA256 its integer assembly.
  Without `adx`, as on Haswell and AMD's cores before Zen, [s2n-bignum]'s
  `_alt` routines replace those that use it, and [aws-lc]'s Montgomery
  multiplication replaces its Karatsuba routines for RSA; with `avx2` there,
  as on Haswell, RSA-2048 signing runs aws-lc's RSAZ exponentiation.
- 32-bit `arm` (tested on `armv7-unknown-linux-gnueabihf`, and built for
  `armv7-linux-androideabi`) runs portable Rust instead, mostly from
  [libcrux] (see [Algorithms](#algorithms)), and needs no CPU features. Where
  the CPU has the ARMv8 crypto extension, as most 32-bit Android devices do,
  AES, GHASH, SHA1, and SHA256 run [aws-lc]'s assembly for it instead.
  Without it, `rind::cpu::has_aes_hardware()` is false, and rind-rustls and
  rind-dimpl prefer ChaCha20-Poly1305, which is faster there: ChaCha20 runs
  aws-lc's assembly, and so does Poly1305 where the CPU has NEON. SHA-384,
  SHA-512, and SHA-512/256 always run aws-lc's assembly, with NEON where the
  CPU has it, and with NEON, X25519's shared secret runs [BoringSSL]'s
  assembly.

Every operation panics on a CPU missing one of these. Call `rind::cpu::check()`
at startup to get an error naming the missing feature instead.

## Building and Testing

Compile:
```shell
cargo build --release
```

Run tests:
```shell
git submodule update --init thirdparty/cavp
git submodule update --init thirdparty/wycheproof
cargo test
```

Run performance benchmarks:
```shell
cargo bench
```

With [Nix](https://nixos.org), `nix develop` (or direnv) provides CI's
toolchain, and `just check` runs CI's gate over what the branch changed.
On Linux, `just armv7` runs the nightly armv7 job: it builds and lints for
32-bit ARM, then runs the tests under qemu with the ARMv8 crypto extension,
with NEON alone, and with NEON denied.

## Algorithms

Each cell names whose code runs for that algorithm on that backend: the
[sources](#sources) below, rind's own code, or Graviola's own Rust and
intrinsics. A ✓ marks code its source formally verifies, to the extent
[Sources](#sources) states. A ⚡ marks unverified code chosen because it
measured faster than a verified alternative; other unverified code has none,
or a [quest][quests] covers it. The table describes
`main`, and changes alongside the code it describes.

| Algorithm | x86_64 | aarch64 | armv7 |
|---|---|---|---|
| AES-128-GCM, AES-256-GCM | VAES: [BoringSSL] interleaved AES-CTR and GHASH (copied) ⚡, on 512-bit vectors from 2 KB with AVX-512 and 256-bit vectors from 256 bytes without; otherwise, and for the key schedule, single-block AES, and GHASH of the AAD and lengths: Graviola, SSE-encoded; without AES-NI and PCLMULQDQ: [aws-lc] SSSE3 AES and GHASH (copied), rind GCM; without SSSE3 either: [aws-lc] SSE2 AES and integer GHASH (ported), rind GCM | crypto extension: [s2n-bignum] CTR and GHASH of whole blocks ⚡, by-8 for AES-256 on cores with SHA3, run in place, which its proofs exclude; Graviola key schedule, H powers, single-block AES (H, the tag mask, and a final partial block), and GHASH of the AAD, final partial block, and lengths; otherwise: [aws-lc] NEON AES and GHASH (copied), rind GCM | crypto extension: [aws-lc] AES and GHASH (copied), rind GCM; otherwise: [libcrux-aes] |
| AES block (header protection), AES-CTR (SRTP) | AES-NI: Graviola block, [aws-lc] CTR (copied); otherwise: [aws-lc] SSSE3 block and CTR (copied); without SSSE3: [aws-lc] SSE2 block and CTR (ported) | crypto extension: Graviola block, rind CTR; otherwise: [aws-lc] NEON block and CTR (copied) | crypto extension: [aws-lc] block and CTR (copied); otherwise: [libcrux-aes] block (copied), rind CTR |
| ChaCha20 (header protection) | AVX2: Graviola; [HACL\*]'s block function measured level for one block, so it isn't worth a libcrux dependency here; otherwise: [aws-lc] SSSE3 and integer, or integer alone without SSSE3 (copied) ⚡ | Graviola; [HACL\*]'s block function measured level for one block | [aws-lc] (copied) ⚡ |
| ChaCha20-Poly1305, XChaCha20-Poly1305 | SSE4.1: [aws-lc] one-pass ChaCha20 and Poly1305 (copied) ⚡, with AVX2 where the CPU has it; otherwise: [aws-lc] ChaCha20 (copied) ⚡, Graviola Poly1305 and AEAD ⚡; Graviola HChaCha20 ⚡ | [aws-lc] one-pass ChaCha20 and Poly1305 (copied) ⚡; Graviola HChaCha20 ⚡ | [aws-lc] ChaCha20 (copied) ⚡; NEON: [aws-lc] Poly1305 (copied) ⚡; otherwise: [HACL\*] Poly1305 ✓; Graviola AEAD; rind HChaCha20 over [HACL\*] rounds ✓ (copied) |
| SHA-1 (legacy only) | SHA-NI or AVX2: rind; otherwise, Intel: [aws-lc] AVX (copied); otherwise: [aws-lc] SSSE3 (copied); without SSSE3: [aws-lc] integer (copied) | crypto extension: rind; otherwise: [aws-lc] scalar (copied) | crypto extension: [aws-lc] (copied); otherwise: rind |
| SHA-256 | SHA-NI: Graviola ⚡; Intel: [aws-lc] AVX (copied) ⚡; AVX2: rind ⚡; otherwise: [aws-lc] SSSE3 (copied) ⚡; without SSSE3: [aws-lc] integer (copied) ⚡ | crypto extension: Graviola ⚡; otherwise: [aws-lc] scalar (copied) | crypto extension: [aws-lc] (copied) ⚡; otherwise: Graviola ⚡ |
| SHA-384, SHA-512, SHA-512/256 | Intel: [aws-lc] AVX (copied) ✓; otherwise: [aws-lc] scalar (copied) ⚡ | SHA-512 instructions: [aws-lc] (copied) ✓; otherwise: [aws-lc] scalar (copied) ✓ | NEON: [aws-lc] (copied) ⚡; otherwise: [aws-lc] scalar (copied) ⚡ |
| HMAC | Graviola ⚡ | Graviola ⚡ | Graviola ⚡ |
| HKDF | rind ⚡ | rind ⚡ | rind ⚡ |
| PBKDF2 | rind; SHA as in its rows | rind; SHA as in its rows | rind; SHA as in its rows |
| Constant-time comparison | Graviola | Graviola | rind |
| X25519 | [s2n-bignum] ✓ | [s2n-bignum] ✓ | NEON: [BoringSSL] shared secret (copied) ⚡, [curve25519-dalek] public key ⚡; otherwise: [curve25519-dalek] ⚡ |
| Ed25519 | [s2n-bignum] point and scalar arithmetic ✓; Graviola EdDSA ⚡; SHA-512 as in its row | [s2n-bignum] point and scalar arithmetic ✓; Graviola EdDSA ⚡; [aws-lc] SHA-512 ✓ | [curve25519-dalek] point and scalar arithmetic ⚡; rind EdDSA ⚡; SHA-512 as in its row |
| P-256 ECDH, ECDSA | [s2n-bignum] field and point arithmetic, and secret scalar multiplication ✓; Graviola verification's scalar multiplication ⚡ and ECDSA ⚡ | [s2n-bignum] field and point arithmetic, and secret scalar multiplication ✓; Graviola verification's scalar multiplication ⚡ and ECDSA ⚡ | [HACL\*] ✓; Graviola ECDSA nonce |
| P-384 ECDH, ECDSA | [s2n-bignum] field and point arithmetic, and other secret scalar multiplication ✓; rind comb multiplication of the generator ⚡; Graviola verification's other scalar multiplication ⚡, and ECDSA | [s2n-bignum] field and point arithmetic, and other secret scalar multiplication ✓; rind comb multiplication of the generator ⚡; Graviola verification's other scalar multiplication ⚡, and ECDSA | [fiat-crypto] field and scalar arithmetic ✓; scalar multiplication over it ⚡, from rind point formulas, inversion, table lookup, and comb multiplication of the generator, and Graviola other scalar multiplication; Graviola ECDSA |
| P-521 ECDH, ECDSA | [s2n-bignum] field and point arithmetic, and other scalar multiplication ✓; rind comb multiplication of the generator ⚡; Graviola ECDSA | [s2n-bignum] field and point arithmetic, and other secret scalar multiplication ✓; rind comb multiplication of the generator ⚡, and verification's other scalar multiplication ⚡; Graviola ECDSA | [fiat-crypto] field arithmetic ✓; rind arithmetic mod the group order ⚡; scalar multiplication over them ⚡, from rind point formulas, inversion, table lookup, and comb multiplication of the generator; Graviola ECDSA |
| ML-KEM-768 | AVX2: [s2n-bignum] polynomial arithmetic and Keccak-f ✓; Graviola FIPS 203 and AVX-512 sampling ⚡; otherwise: rind port of [mlkem-native] polynomial arithmetic ⚡, [s2n-bignum] Keccak-f ✓, Graviola FIPS 203 ⚡ | [s2n-bignum] polynomial arithmetic and Keccak-f ✓; Graviola FIPS 203 ⚡ | [libcrux-ml-kem] ✓, except its SHA-3 |
| RSA PKCS#1 v1.5 and PSS signatures, key generation | Exponentiation: [aws-lc] RSAZ (copied) ⚡ for 1024-bit primes with AVX2 but without ADX, otherwise Graviola ⚡ over Montgomery multiplication: [s2n-bignum] Karatsuba for 1024- and 2048-bit moduli with ADX ✓, otherwise [aws-lc] (copied) ⚡; other [s2n-bignum] bignum arithmetic ✓; Graviola CRT, padding, and prime search; rind private exponents and Miller-Rabin | Graviola exponentiation ⚡ over Montgomery multiplication: [s2n-bignum] Karatsuba for 1024- and 2048-bit moduli ✓, [aws-lc] (copied) ⚡ for 1536-, 3072-, and 4096-bit moduli, otherwise [s2n-bignum] ✓; other [s2n-bignum] bignum arithmetic ✓; Graviola CRT, padding, and prime search; rind private exponents and Miller-Rabin | [HACL\*] bignum arithmetic and exponentiation ✓; rind CRT and key generation; Graviola padding |

The tests use [Wycheproof]'s vectors.

### Sources

| Source | How rind uses it | License | What is verified |
|---|---|---|---|
| [Graviola] | copied: rind began as a copy of it, and rind-rustls of its rustls-graviola; its aarch64 ChaCha20 and its Poly1305 began as [cifra], CC0-1.0 | Apache-2.0 OR ISC OR MIT-0 | nothing |
| rind | its own code | Apache-2.0 OR ISC OR MIT-0 | nothing |
| [s2n-bignum] | copied: its assembly, transliterated into Rust `asm!` by `admin/parse-asm`, which ends each x86_64 routine using 256-bit registers with `vzeroupper` | Apache-2.0 OR ISC OR MIT-0; its ML-KEM and aarch64 Keccak-f routines (from mlkem-native) Apache-2.0 OR ISC OR MIT; its x86_64 Keccak-f (from OpenSSL) Apache-2.0 | HOL Light proofs ([x86_64](https://github.com/awslabs/s2n-bignum/tree/main/x86/proofs), [aarch64](https://github.com/awslabs/s2n-bignum/tree/main/arm/proofs)) that each routine's object code computes its specified result for all inputs. They check s2n-bignum's own build, not rind's transliteration, and do not cover memory safety. |
| [HACL\*] | dependency, through libcrux-hacl-rs, libcrux-p256, and libcrux-poly1305; copied: the ChaCha20 rounds, for HChaCha20, from libcrux-chacha20poly1305 | Apache-2.0 | [F\* proofs](https://github.com/hacl-star/hacl-star) of memory safety, functional correctness, and secret independence of the F\* source. libcrux's Rust is compiled mechanically from HACL\*'s verified C, and that step is not itself verified. |
| [libcrux-ml-kem] | dependency | Apache-2.0 | [hax and F\* proofs](https://github.com/cryspen/libcrux/blob/main/libcrux-ml-kem/proofs/verification_status.md) of panic freedom and functional correctness for its portable arithmetic, NTT, serialization, and high-level code. Its SHA-3, from libcrux-sha3, is unverified. |
| [mlkem-native] | ported: its portable C polynomial arithmetic (the NTT, inverse NTT, base multiplication, reductions, packing, and rejection sampling), to Rust, for x86_64 CPUs without AVX2 | Apache-2.0 OR ISC OR MIT | [CBMC proofs](https://github.com/pq-code-package/mlkem-native/tree/main/proofs/cbmc) of memory safety and coefficient bounds for its C. They do not cover rind's port. |
| [libcrux-aes] | dependency for AES-GCM; copied: the block cipher | Apache-2.0 | nothing: libcrux marks it pre-verification |
| [aws-lc] | copied, by `admin/import-aws-lc`: its SHA-384/512 assembly for x86_64 and aarch64, its x86_64 AVX SHA-256 routine, Montgomery multiplication (with one deliberate change: rind's `bn_sqr8x_mont` zeroes two scratch words its `mulx` branch reads unwritten, which valgrind reports though results and timing do not depend on them), RSAZ exponentiation, AES-NI AES-CTR, and SSE4.1 and AVX2 ChaCha20-Poly1305 (with one deliberate change: rind's copy reads the choice of AVX2 from the block rind passes it rather than aws-lc's `OPENSSL_ia32cap_P`), its aarch64 NEON ChaCha20-Poly1305, its x86_64 assembly for CPUs without AVX2 (SSSE3 and integer ChaCha20, SSSE3 and AVX SHA-1, and SSSE3 SHA-256) without AES-NI (SSSE3 AES and GHASH), and without SSSE3 (integer SHA-1 and SHA-256), its aarch64 Montgomery multiplication, and its aarch64 assembly for CPUs without the crypto extension (NEON AES, NEON GHASH, and scalar SHA-1 and SHA-256), as Rust naked functions; its 32-bit ARM assembly for ChaCha20, SHA-384/512, the ARMv8 crypto extension (AES, GHASH, SHA-1, SHA-256), and NEON Poly1305, in Rust `global_asm!`; and the C that drives that Poly1305 and RSAZ, that sets up its x86_64 SSSE3 GHASH table, and that computes its constant-time SSE2 AES and integer GHASH for x86_64 CPUs without SSSE3, ported to Rust. aws-lc takes its Poly1305, ChaCha20-Poly1305, SSSE3 GHASH, and constant-time AES and GHASH from BoringSSL and the rest from OpenSSL | Apache-2.0; Poly1305, ChaCha20-Poly1305, SSSE3 and integer GHASH, and constant-time AES ISC | [SAW and NSym proofs](https://github.com/awslabs/aws-lc-verification) that its x86_64 AVX and aarch64 (with and without the SHA-512 instructions) SHA-384/512 routines compute their specified result for all inputs. They check aws-lc's own build, not rind's copy, and do not cover its 32-bit ARM code. |
| [BoringSSL] | copied, by `admin/import-boringssl`: its x86_64 VAES AES-GCM assembly, `aes-gcm-avx2-x86_64` and `aes-gcm-avx512-x86_64`, as Rust naked functions; its 32-bit ARM NEON X25519 assembly, in Rust `global_asm!`, which BoringSSL takes from [SUPERCOP]'s `neon2`, public domain | Apache-2.0 | nothing |
| [curve25519-dalek] | dependency, with its serial 32-bit backend | BSD-3-Clause | nothing: that backend's field arithmetic is hand-written. Its `fiat` backend would run [fiat-crypto]'s verified field arithmetic instead, but only a `--cfg` flag for the whole build selects it, so rind refuses it rather than let the build pick. |
| [fiat-crypto] | dependency | MIT OR Apache-2.0 OR BSD-1-Clause | [Coq proofs](https://github.com/mit-plv/fiat-crypto) that each generated field operation is correct. rind's point formulas, inversion, and table lookup over them are not covered. |

rind's own code is licensed under Apache-2.0 OR ISC OR MIT-0. Copied code
keeps its source's copyright and license, which [LICENSE] lists with the
texts they require; dependencies ship their own. Every file under
`rind/src` names its license in a `SPDX-License-Identifier` comment, and
files Graviola wrote keep their `Written for Graviola by ...` header. The
`rind` crate as a whole is therefore `(Apache-2.0 OR ISC OR MIT-0) AND
(Apache-2.0 OR ISC OR MIT) AND Apache-2.0 AND ISC`. The adapter crates copy
nothing under another license, so they stay `Apache-2.0 OR ISC OR MIT-0`.
rind-ring runs ring's own tests, which keep ring's licenses and stay out of
the published crate.

A change that copies code from a new source, or moves an algorithm to a
different one, updates this table and [LICENSE] in the same PR.

[Graviola]: https://github.com/ctz/graviola
[cifra]: https://github.com/ctz/cifra
[s2n-bignum]: https://github.com/awslabs/s2n-bignum
[HACL\*]: https://github.com/hacl-star/hacl-star
[libcrux-ml-kem]: https://github.com/cryspen/libcrux/tree/main/libcrux-ml-kem
[libcrux-aes]: https://github.com/cryspen/libcrux/tree/main/crates/algorithms/aes
[mlkem-native]: https://github.com/pq-code-package/mlkem-native
[libcrux]: https://github.com/cryspen/libcrux
[aws-lc]: https://github.com/aws/aws-lc
[fiat-crypto]: https://github.com/mit-plv/fiat-crypto
[BoringSSL]: https://boringssl.googlesource.com/boringssl
[SUPERCOP]: https://bench.cr.yp.to/supercop.html
[curve25519-dalek]: https://github.com/dalek-cryptography/curve25519-dalek
[Wycheproof]: https://github.com/C2SP/wycheproof
[LICENSE]: https://github.com/moq-dev/rind/blob/main/LICENSE
[rind-rustls]: https://crates.io/crates/rind-rustls
[rind-ring]: https://github.com/moq-dev/rind/tree/main/rind-ring
[quests]: https://github.com/moq-dev/rind/blob/main/quest/README.md
[migrating]: https://github.com/moq-dev/rind/blob/main/MIGRATING.md

## Assorted technical details

### RSA
On x86_64 and aarch64, the arithmetic is provided by s2n-bignum, under the
exponentiation described below, except that x86_64 runs aws-lc's Montgomery
multiplication as aws-lc's `bn_mul_mont` picks it (`bn_mul4x_mont` for moduli
whose width in 64-bit words is a multiple of four, `bn_sqr8x_mont` for
squaring a multiple of eight, each by `mulx` with ADX, and `bn_mul_mont_nohw`
for other widths), other than 1024- and 2048-bit moduli on CPUs with ADX,
where s2n-bignum's Karatsuba routines are as fast or faster. aarch64 runs
aws-lc's `bn_mul_mont`, which picks its own squaring or 4x routine by the
width, for 1536-, 3072-, and 4096-bit moduli, where it measured twice as fast
as s2n-bignum's generic routines on a Neoverse-N2. 1024- and 2048-bit moduli
run s2n-bignum's Karatsuba routines, and other sizes its generic ones. armv7
uses HACL\*'s arithmetic and exponentiation instead. On x86_64 CPUs with AVX2
but without ADX, the private operation's exponentiation modulo each 1024-bit
prime of RSA-2048 runs aws-lc's RSAZ, as aws-lc does there: Montgomery
products on AVX2 over 29-bit limbs, and a 5-bit fixed window whose table
entry is gathered by masking all 32 entries.

The RSA private operation always uses the CRT optimisation.

Modular exponentiation uses 4-bit fixed exponent window, and the term is selected by
the exponent bits from the table of base powers in a side-channel-free way.
The private operation is always followed by the public operation to verify the result
(and the result compared in a side-channel-free way).

Only RSA signing and verification are provided.  Signing keys have 2048- to
8192-bit moduli; verification also takes 1024-bit moduli and SHA-1, but only
under `signature::verify::legacy`.  Every key refuses a public exponent that
is even, 1, or over 33 bits, and a private key whose components disagree is
refused when it loads, as aws-lc's `RSA_check_key` does.  RSA encryption is not provided:
OAEP waits on a consumer, and PKCS#1 v1.5 encryption, which invites
padding-oracle attacks, is refused.

RSA key generation is supported for five fixed key sizes between 2048-8192-bits.
All generated keys have e = 0x10001 and, as in aws-lc, d reduced mod
lcm(p - 1, q - 1).  Generation runs in constant time in the primes, revealing
only which candidates it discards.

### ECC
On x86_64 and aarch64, all ECC field and scalar arithmetic are provided by
s2n-bignum, and the rest of this section describes those backends.

P256 base point multiplication uses a 7-bit exponent window with Booth encoding
(this costs a 148KB constant table).
Variable point multiplication uses a 5-bit exponent window with Booth encoding.
Both use the same exponent representations for "public" and "secret" exponents --
however the table selection for "public" exponents is specialized at compile-time.

P384 base point multiplication uses a comb of 20 tables of 16 affine points
(a 30KB constant table) over 5-bit Booth windows, as aws-lc does. Variable
point multiplication is s2n-bignum's `p384_montjscalarmul`, except for ECDSA
verification's public scalar, which uses a 5-bit Booth window over the
multiples of the public key, computed once when the key is parsed.

P521's prime is a Mersenne prime, so its field arithmetic is direct rather
than Montgomery's. Base point multiplication uses a comb of 27 tables of 16
affine points (a 62KB constant table) over 5-bit Booth windows, as aws-lc
does. Variable point multiplication is s2n-bignum's `p521_jscalarmul`, for
ECDSA verification's public scalar too, except on aarch64, where a 5-bit Booth
window over the point's cached multiples measured faster for that one.
s2n-bignum's P521 point addition requires points that are not at infinity,
equal, or opposite, so the comb and the window keep to that, and select or
branch around the cases they reach.

ECDSA follows RFC6979 for generation of `k`, but adds additional non-critical random input.
We do this to avoid the theoretical fragility of RFC6979 under fault conditions.
This is allowed for by RFC6979, and the HMAC-DRBG that it builds on.
The code is structured such that we pass the RFC6979 test vectors.

The code which selects a term from a table of points is non-verified,
and is written in AVX2/Neon intrinsics.

On x86_64 and aarch64, X25519 directly uses the s2n-bignum implementation.

### ML-KEM-768
On aarch64, and on x86_64 CPUs with AVX2, the core polynomial arithmetic -- the NTT, inverse NTT, base multiplication
and reduction -- is provided by s2n-bignum (contributed by the mlkem-native
developers).  The surrounding FIPS-203 construction (key generation,
encapsulation and decapsulation) is written in Rust.

x86_64 CPUs without AVX2 run the same construction over a Rust port of
mlkem-native's portable C arithmetic instead, in natural coefficient order as
aarch64 keeps it, and Keccak-f four states one at a time, chosen once per
process. It measured 1.3x faster than libcrux's portable ML-KEM for key
generation and encapsulation there, and 2x for decapsulation.

Compression and decompression are division-free, avoiding the variable-time
division behind the KyberSlash attacks.

For sampling, which is a significant factor in ML-KEM performance, we
have some different options depending on CPU features:

- We have a `SampleNTT()` which does 8-wide Keccak-f permutation followed by
  rejection sampling using AVX-512 (F, BW, VBMI, VBMI2) on x86-64.
- We have a 4-wide Keccak-f using AVX2 on x86-64.
- We have a 2-wide Keccak-f using Neon+SHA3 on aarch64.
- We have a basic Keccak-f using scalar instructions on aarch64.

### Symmetric cryptography
SHA1 and SHA256 have straightforward implementations using hashing intrinsics
(aka "SHA-NI" on x86_64, "sha" extension on aarch64). Without SHA-NI, x86_64
selects at runtime an AVX2 message schedule with scalar rounds for SHA1, as
aws-lc does. For SHA256 it runs aws-lc's AVX routine on Intel, as aws-lc
picks, and the same AVX2 approach elsewhere, since the AVX routine rotates with
`shrd`, which pre-Zen AMD runs slowly. Without AVX2 either, both run aws-lc's
AVX routines on Intel and its SSSE3 ones elsewhere, as aws-lc picks; they are
2.2x (SHA256) and 1.7x (SHA1) faster than the pure Rust ones on Intel.
Without SSSE3 too, both run aws-lc's integer routines, as aws-lc does: 2.2x
(SHA256) and 1.25x (SHA1) faster than the pure Rust ones, and 1.3-1.5x
faster than HACL*'s SHA256.
aarch64 without the crypto extension runs aws-lc's
scalar SHA1 and SHA256 assembly. 32-bit `arm` runs aws-lc's SHA1 and SHA256 assembly
where the CPU has the crypto extension, and the pure Rust SHA1 and SHA256
otherwise: libcrux has no SHA1, and the pure Rust SHA256 is faster than
libcrux's.

SHA384, SHA512, and SHA512/256 run aws-lc's assembly everywhere. On x86_64,
its AVX routine on Intel and its scalar routine on other CPUs, as aws-lc picks:
the AVX routine is 1.1x faster than the scalar one on Intel, and 1.5x slower on
AMD's Zen. On aarch64, its routine for the SHA-512 instructions where the CPU
has them, and its scalar routine otherwise; on 32-bit `arm`, its NEON routine
where the CPU has NEON, and its scalar routine otherwise.

x86_64 decides once per process whether the CPU has AES-NI and PCLMULQDQ,
and SSSE3. Without the first two, as on Core 2 and Nehalem, AES and AES-CTR
run aws-lc's `vpaes-x86_64` assembly and GHASH its `ghash-ssse3-x86_64`,
composed into AES-GCM as aws-lc composes them, taking turns over 3 KB; both
modes measured level with aws-lc's. Without SSSE3 either, as on QEMU's
`qemu64`, they run Rust ports of the C aws-lc runs there: `aes_nohw.c`, which
bitslices eight blocks into SSE2 registers and computes the S-box as a
circuit, and `gcm_nohw.c`, which multiplies with integer multiplies of
operands masked to every fourth bit, so no carry reaches a bit it keeps.
Neither branches or indexes memory by a secret. Composed the same way,
AES-GCM and AES-CTR measured 0.82-0.92x aws-lc's time; libcrux's portable
AES-GCM measured 3-7x slower, and its bitsliced block level with the port's
for one block. With AES-NI and PCLMULQDQ, AES-CTR runs aws-lc's
`aes_hw_ctr32_encrypt_blocks`, 1.1-2x faster than rind's by-8 intrinsics at
every length, with or without AVX.

AES-GCM has a stitched by-8 AES-CTR and a by-8 GHASH (they are not currently
interleaved; this is future work), SSE-encoded on every CPU: VEX encoding
measured no faster with AVX, and without it, as on Westmere and the Goldmont
and Tremont Atoms, this is 1.02-1.28x faster than aws-lc's SSE `aesni-x86_64`
and `ghash-x86_64` routines. Every 256- and 512-bit kernel rind runs ends with
`vzeroupper`, so SSE code after one pays no AVX-SSE transition or false
dependency. There is also an optional AVX-512 by-16 AES-CTR
and GHASH.  It uses dynamic CPU feature detection, so AVX-512 is not required at runtime.
On cores with VAES, BoringSSL's kernels, which interleave AES-CTR and GHASH, take
long messages: its 512-bit kernel from 2 KB where the CPU has AVX-512 (the by-16
path is quicker below that), and its 256-bit kernel from 256 bytes otherwise.
The key picks its kernel once, when it is made.

aarch64 decides once per process whether the CPU has the crypto extension.
With it, AES-GCM runs s2n-bignum's kernels, which interleave a by-4 AES-CTR
and GHASH over whole blocks. An AES-256 key made on a core with SHA3 runs their
by-8 kernels instead, which use its three-way XOR. They run in place, outside
their proofs, which assume separate input and output buffers.
`admin/parse-asm/inplace.py` walks them at every length to 64 blocks, checking
that each block is loaded before it is stored and that their branches and
addresses depend only on the length.

Without it, AES runs aws-lc's `vpaes-armv8`, Mike Hamburg's vector permutation
AES, whose S-box is NEON `tbl` lookups into registers, and GHASH runs aws-lc's
`ghash-neon-armv8`, which builds each product from NEON's 8-bit polynomial
multiplies; neither reads memory or branches by a secret. AES-GCM runs AES-CTR
and GHASH over each eight blocks in turn, as aws-lc composes them.

32-bit `arm` decides once per process from `AT_HWCAP2`: with the crypto
extension, AES and AES-GCM keys use aws-lc's `aesv8-armx` and `ghashv8-armx`
assembly, composed as aws-lc does on that architecture; without it, libcrux's
bitsliced AES and AES-GCM.

x86_64 CPUs without AVX2 run ChaCha20 on aws-lc's `chacha-x86_64` assembly,
as aws-lc picks: its integer routine up to 128 bytes, and its SSSE3 routine,
four blocks at a time, above that. Both measured faster than the pure Rust
block function at every length: 1.7x for one block, and 4.5x from 256 bytes.
Without SSSE3, the integer routine runs at every length, as in aws-lc, and
measured 1.2x faster than HACL*'s ChaCha20 at every length, and HChaCha20,
for XChaCha20, rotates with SSE2 shifts rather than SSSE3's byte shuffles.

ChaCha20-Poly1305, and XChaCha20-Poly1305 after HChaCha20, run aws-lc's
`chacha20_poly1305` assembly, which interleaves ChaCha20 with Poly1305 in one
pass: on x86_64, its AVX2 half where the CPU has AVX2 and BMI2 and its SSE4.1
half otherwise, as aws-lc picks them, and on aarch64, its NEON routine.
aws-lc's x86_64 routine reads its pick from `OPENSSL_ia32cap_P`; rind's copy
reads the same bits from the block rind passes it, so the path is decided
once per process like rind's others. Without SSE4.1, ChaCha20 and Poly1305
run in separate passes, as in aws-lc.

32-bit `arm` runs ChaCha20 on aws-lc's `chacha-armv4` assembly, switching from
its integer routine to its NEON one at 192 bytes as aws-lc does, where
`AT_HWCAP` reports NEON. Poly1305 runs aws-lc's NEON code there too, and
HACL*'s verified Poly1305 without NEON.

## Architecture

rind's API is its own, shaped so that misuse fails to compile rather than at
run time. [MIGRATING.md][migrating] maps each ring and aws-lc-rs item to it.

- Each module takes an algorithm as a `&'static` constant, such as
  `aead::AES_128_GCM` or `signature::verify::ECDSA_P256_SHA256_ASN1`, and has
  one key type per role.
- Algorithms only old protocols should use sit in `legacy` submodules, such
  as `digest::legacy::SHA1`.
- Key pairs name the DER format they load or encode (`from_pkcs8`,
  `from_sec1`, `to_spki`), and every private key returns its public half
  from `public_key()`.
- Encodings, signatures, and shared secrets are owned values of fixed
  capacity, such as `signature::Pkcs8`, rather than caller buffers or
  allocations. Keys wipe their secrets on drop.
- No call takes a random source: rind draws from the system's when it needs
  one, and `rand::fill` gives callers the same.
- Fallible calls return `rind::Error`, whose variant says which kind of call
  failed, such as `KeyRejected` or `BadSignature`.

The modules:

- `aead`: AES-GCM and ChaCha20-Poly1305 keys with caller nonces, an
  XChaCha20-Poly1305 key that picks random nonces, and QUIC header-protection
  keys.
- `cipher`: bare AES, AES-CTR, and ChaCha20, for DTLS record number
  protection and SRTP.
- `agreement`: ephemeral X25519 and ECDH on P-256, P-384, and P-521.
- `kem`: ML-KEM-768.
- `signature`: ECDSA on P-256, P-384, and P-521, RSA PKCS#1 v1.5 and PSS, and
  Ed25519 key pairs and verification, plus RSA keys given as their
  components, and SHA-1 and 1024-bit RSA for verifying old signatures.
- `digest`: SHA-1 (legacy only), SHA-256, SHA-384, SHA-512, and SHA-512/256.
- `hmac`: HMAC over those digests, keyed once and reused.
- `hkdf`: HKDF over those HMACs, whose output becomes an `aead`, QUIC header-protection, or `hmac` key.
- `pbkdf2`: PBKDF2 over those HMACs, deriving or verifying a key from a password.
- `constant_time`: comparing secrets such as MACs without a timing leak.
- `rand`: random bytes from the system.
- `cpu`: the startup check for required CPU features, and whether AES runs
  in hardware.

The public modules wrap three private layers:

- `low`: low level primitives. platform-specific. unsafe allowed. minimal std and alloc.
- `mid`: constructions, protocols and encodings. platform agnostic. no unsafe. minimal std and alloc.
- `high`: high level encodings and operations. platform agnostic. no unsafe.

`low` code should not refer to `mid`, nor `mid` to `high`.

`low` must present the same interface irrespective of platform.  To this end,
`low::generic` contains pure-rust polyfills for items we don't have assembler-
or intrinsic-based implementations for a certain platform.
