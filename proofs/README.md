# Proofs of rind's Rust

Lean proofs that rind's own Rust computes its specified result, composed with
the published proofs of the routines it imports, so that an operation's whole
computation is proven. [Charon](https://github.com/AeneasVerif/charon) and
[Aeneas](https://github.com/AeneasVerif/aeneas) translate the Rust to Lean, and
the theorems are about that translation.

`nix develop .#prove --command admin/prove` translates the Rust and checks
every proof against the translation. The `prove` workflow runs it nightly and
on pull requests that change rind's source or these files.

## What is proven

X25519 on x86_64 and aarch64, from the agreement API's `PrivateKey` to
s2n-bignum's routines, in `Rind/X86_64/X25519.lean`, which `admin/prove` also
writes for aarch64:

- `x25519_generate`: the key's scalar is the 32 drawn bytes, read
  little-endian, and a failed draw is refused;
- `x25519_from_scalar`: a loaded key's scalar is the 32 given bytes, read
  little-endian, and any other length is refused;
- `x25519_public_key`: the public key is the 32 little-endian bytes of
  `rfcx25519(scalar, 9)`;
- `x25519_agree`: a peer key that is not 32 bytes is refused, so is an
  all-zero result, and otherwise the secret is the 32 little-endian bytes of
  `rfcx25519(scalar, u)`, for the peer's bytes `u` read little-endian;
- `x25519_shared_secret`: the secret's bytes are those.

`rfcx25519` is HOL Light's RFC 7748 X25519, clamping and masking included.

P-256 ECDH on aarch64, from the same `PrivateKey` to s2n-bignum's routines, in
`Rind/Aarch64/P256.lean`:

- `p256_generate`: the key's scalar is the first of up to 64 draws whose
  bytes, read big-endian, are in [1, n), and the key is refused if a draw
  fails before one is, or none is;
- `p256_from_scalar`: a loaded key's scalar is the 32 given bytes, read
  big-endian, refused unless they are 32 bytes and in [1, n);
- `p256_public_key`: the public key is the X9.62 uncompressed encoding of the
  scalar times G, for a scalar in [1, n), as every key's is;
- `p256_agree`: a peer key is refused unless it is a 65-byte uncompressed
  point whose coordinates are below p and on the curve, and otherwise the
  secret is the 32 big-endian bytes of the x-coordinate of the scalar times
  that point, or a fault unless that is a finite point on the curve;
- `p256_shared_secret`: the secret's bytes are those.

`p256Pow` is HOL Light's `group_pow p256_group`, defined as HOL Light does,
and `Rind/P256Group.lean` proves it is multiplication in Mathlib's group of
points on the curve. `Rind/P256Multiples.lean` proves G's order n: the kernel
computes (n - 1)·G by doubling and adding, checking each step's coordinates
against the group law, and finds -G, and `Rind/N256Prime.lean` proves n
prime. So a scalar in [1, n) times G is a finite point. That the same holds
for the peer's point, so the fault never happens, needs every point's order,
which follows from the group having n points, a count these theorems do not
prove.

P-256 ECDSA with SHA-256 and fixed-length signatures on aarch64, from the
signature API's `EcdsaKeyPair` and `PublicKey` to s2n-bignum's routines, in
`Rind/Aarch64/P256Signature.lean` over `Rind/Aarch64/P256Ecdsa.lean`:

- `p256_ecdsa_generate`: the key pair's scalar is in [1, n), and generation
  is refused only if the system source's draws fail;
- `p256_ecdsa_from_scalar_and_public_key`: a scalar that is not 32 bytes
  is refused, so is one outside [1, n), and so is a public key that is neither
  X9.62 encoding, uncompressed or compressed, of the scalar times G, and
  otherwise the key pair's scalar is the scalar;
- `p256_ecdsa_sign`: a signature signing returns is 64 bytes, the big-endian
  r and s of the ECDSA signature of the message's SHA-256 under the scalar,
  for some nonce in [1, n), neither zero, and signing is refused only if the
  nonce's random input cannot be drawn;
- `p256_ecdsa_key_pair_public_key`: the public key's bytes are the X9.62
  uncompressed encoding of the scalar times G;
- `p256_ecdsa_public_key_new`: a public key is refused unless it is a 65-byte
  uncompressed point whose coordinates are below p and on the curve, and
  otherwise its `verify` accepts exactly the signatures ECDSA verifies with
  that point: 64 bytes, r and s in [1, n), and the x-coordinate of
  e/s·G + r/s·Q, a finite point, equal to r mod n;
- `p256_ecdsa_key_pair_verify`: a key pair's public key verifies the same
  way, with its point the scalar times G.

`ecdsaP256Sign` and `ecdsaP256Verifies` in `Rind/Spec.lean` are FIPS 186-5's,
over `p256Pow` and `p256Add`. `Rind/P256Multiples.lean` proves, from
`Rind/P256Group.lean`'s group, the laws by which the twin multiplication's
windowed sum is e/s·G + r/s·Q, and `Rind/N256Prime.lean` that n is prime, so
every nonzero scalar has an inverse. The sum also needs Q's order n. A key
pair's Q is its scalar times G, whose order follows from G's, but a parsed
public key's is any point on the curve, so `p256_ecdsa_public_key_new` takes
`P256Order`: every finite point on the curve has order n, as HOL Light's
`P256_GROUP_ELEMENT_ORDER` proves from the group's size, which Mathlib cannot
count yet. Key generation and signing need only G's order. The message's SHA-256 is the digest rind's
`Sha256` impl computes (`Sha256E`), which `sha256_hash` proves is FIPS
180-4's in a module these cannot import, as `Rind/HashSpec.lean` and
`Rind/Sha2.lean` share names. Signing draws nonces until r and s are both
nonzero, with no bound, so `p256_ecdsa_sign` says what a returned signature
is, not that one returns. The nonces come from RFC 6979's HMAC-DRBG, hedged
with 16 bytes from the system source; its update takes a slice of borrowed
slices, which Aeneas cannot translate, so it is opaque, and the theorems
assume `Drbg`: it seeds and draws without panicking, and a draw never fails.
They also assume `Fills`, that the system source returns, `Held`, that the
entry guard holds, and `Cached`: a verifying key's lock-free caches of P to
15P and 17P to 31P, and a signing key's of its encoded public key, whose
atomics Aeneas cannot translate, are built from the key's own point or
scalar.

ChaCha20 QUIC header protection on x86_64 and aarch64, from
`HeaderProtectionKey` to HACL*'s rounds, in `Rind/X86_64/ChaCha20.lean`:

- `chacha20_new`: a key that is not 32 bytes is refused, and otherwise the
  key holds its bytes;
- `chacha20_mask`: the mask is RFC 9001's, the first five bytes of RFC 8439's
  keystream block for the key, with the sample's first four bytes as the
  little-endian block counter and the rest as the nonce.

HACL*'s rounds are Rust, so they are translated and proven with the rest, and
no axiom stands in for HACL*'s proof of them.

Theorems that run an entry guard assume `Runs`: rind's CPU-feature checks
pass, which no input affects. `Rind/Aarch64/P256Table.lean` proves that
rind's generator table holds the multiples of G that s2n-bignum's proof of
`p256_scalarmulbase` assumes, so `p256_public_key` assumes nothing of it.
`Rind/<Arch>/Axioms.lean` checks the axioms each theorem rests on.

SHA-1 and SHA-256's padding and finalization, and HMAC's keyed states over
any hash, on x86_64 and aarch64, in `Rind/X86_64/{Blockwise,Sha,Hmac}.lean`,
against FIPS 180-4 and RFC 2104 as `Rind/HashSpec.lean` transliterates them:

- `sha256_hash`, `sha1_hash`: a message's digest, one-shot, and
  `sha256_hashSpec`, `sha1_hashSpec`: every method of each `Hash` impl,
  streaming included;
- `hmac_key_new_spec`, `hmac_sign_spec`, `hmac_start_spec`,
  `hmac_update_spec`, `hmac_finish_spec`: `HmacKey` and `Hmac` over any hash
  meeting `HashSpec`, and `hmac_sha256_sign`, `hmac_sha1_sign` over SHA-256
  and SHA-1.

No proof covers a SHA-1 or SHA-256 block function rind runs on either target,
so these theorems take `ShaBlocks` as a hypothesis, in each target's own
`Rind/<Arch>/ShaBlocks.lean`: each routine computes FIPS 180-4's block
function, x86_64's SHA extensions' routines for SHA-1's padded last blocks
and SHA-256's finish pad, and SHA-256's encodes, as FIPS 180-4 does, and
rind's checks pass. They add no axiom, which
`Rind/<Arch>/HashAxioms.lean` checks. An input is at most `maxInput`
(2^61 - 1) bytes, under FIPS 180-4's 2^64-bit limit. `Rind/HashSpecTest.lean`
checks the transliterations against FIPS 180-4's, RFC 4231's, RFC 5869's, and
RFC 6070's vectors.

`PrivateKey` reaches each curve's `Agree` impl through function pointers
(`Algorithm`'s `generate` and `load`, and `Keyed`'s `Ops`), and `HeaderProtectionKey` each
cipher's `Mask` impl (`Algorithm`'s `new` and `Masker`'s `mask`), which Aeneas
cannot translate. `Rind/X86_64/Dispatch.lean` models that dispatch by hand, in
Lean definitions beside the Rust they model. P-256's key generation draws
through a `dyn RandomSource`, which Aeneas cannot translate either, and
`Rind/Aarch64/P256Dispatch.lean` models it and the `ECDH_P256` static the same
way. The signature API's `EcdsaKeyPair` reaches each curve's code, and
`PublicKey` each ECDSA key's parser and verifier, through function pointers,
and P-256's ECDSA key generation draws through a `dyn RandomSource`;
`Rind/Aarch64/EcdsaDispatch.lean` models them for P-256 with SHA-256 and
fixed-length signatures.

SHA-384, SHA-512, and SHA-512/256, from the digest API to aws-lc's block
routine, in `Rind/X86_64/Sha512.lean`, which `admin/prove` also writes for
aarch64:

- `sha512_family_digest`: `digest`'s bytes are the hash of the message;
- `sha512_family_context`: a `Context` given the message in any chunks, then
  finished, returns its hash, for messages under 2^64 bytes.

The hash is cryptol-specs' FIPS 180-4 SHA-512, in `Rind/Sha2.lean`, with its
block compression `processBlock_Common` opaque. Each theorem assumes
`RunsSha512`: on x86_64 that rind picks aws-lc's AVX routine, on an Intel CPU
with AVX but without AVX2, and on aarch64 its scalar routine, on a CPU without the SHA-512
instructions; those are the routines whose proofs state their result. The
digest API reaches each hash through function pointers too, which
`Rind/X86_64/DigestDispatch.lean` models, and `Rind/X86_64/DigestAlgorithm.lean`
models the `Algorithm` statics that hold them, and `Digest`, whose
`&'static Algorithm` Aeneas cannot end a borrow of `Digest` across.

Ed25519 on x86_64 and aarch64, from the signature API's `Ed25519KeyPair` and
`PublicKey` to s2n-bignum's routines and the SHA-512 proof above, in
`Rind/X86_64/Ed25519.lean`, which `admin/prove` also writes for aarch64:

- `ed25519_generate`: the key pair's seed is the 32 drawn bytes, and a failed
  draw is refused;
- `ed25519_from_seed_and_public_key`: a seed that is not 32 bytes is refused,
  so is a public key that is not the seed's, and otherwise the key pair's
  seed is the seed;
- `ed25519_sign`: the signature's bytes are RFC 8032's PureEd25519 signature
  of the message under the seed;
- `ed25519_key_pair_public_key`: the public key's bytes are RFC 8032's public
  key of the seed;
- `ed25519_public_key_new`: a public key is refused unless it is 32 bytes,
  refused if its low 255 bits are one of libsodium's seven small-order
  y-coordinates, refused unless it encodes a point of the group, and
  otherwise its `verify` accepts exactly the signatures RFC 8032 verifies with
  that point: 64 bytes, S below L, and R the encoding of SB - kA;
- `ed25519_key_pair_verify`: a key pair's public key verifies the same way,
  with its point the base point times its secret scalar, for a scalar whose
  multiple is a point of the group.

The spec, in `Rind/Ed25519.lean`, is RFC 8032 over HOL Light's
`edwards25519_group`, whose multiplication and power stay opaque, with
s2n-bignum's `ed25519_encode` and `ed25519_decode` of its points. Each theorem
assumes `Runs` and `RunsSha512`, and each with a message bounds it at
2^64 - 64 bytes. The two that verify also assume `RunsDouble`: on x86_64
that a CPU without ADX lacks AVX2 too, since with it rind runs a port of
curve25519-dalek's AVX2 backend, which nothing proves, and on aarch64
nothing. That a multiple of the base point is a point of the group,
which `ed25519_key_pair_verify` assumes, is the group's theory, which these
theorems do not import. `PublicKey` reaches each algorithm's key parser, and
each parsed key its verification, through function pointers, which
`Rind/X86_64/SignatureDispatch.lean` models.

AES-128-GCM and AES-256-GCM on x86_64 CPUs with AVX and MOVBE but no VAES,
from the AEAD API's `Key` to HACL*'s Vale AES-GCM routines, in
`Rind/X86_64/AesGcm.lean`:

- `aes_gcm_new`: a key that is not the algorithm's length is refused, and
  otherwise the key holds FIPS 197's round keys for its bytes, as Vale's
  `key_to_round_keys_LE` lays them out, and the GHASH key powers Vale's
  `hkeys_reqs_pub` requires of `E_K(0)`;
- `aes_gcm_seal`: for AAD under 2^32 bytes and messages of 129 bytes up to
  that, the ciphertext in place and the tag are Vale's `gcm_encrypt_LE` of the
  key, nonce, message, and AAD;
- `aes_gcm_seal_append_tag`: the same for a seal that appends the tag to any
  buffer: the ciphertext lands in the view its `as_mut` gives, and the call
  returns what its `extend` makes of that, handed the tag; and
  `aes_gcm_seal_append_tag_vec`: a `Vec<u8>` with room for the tag becomes
  the ciphertext followed by the tag, assuming `VecAsMut` and `VecExtend`,
  that std's impls view the whole vector and append the tag as
  `extend_from_slice` does;
- `aes_gcm_open_separate_tag` and `aes_gcm_open`: for AAD and messages under
  2^32 bytes, the call succeeds exactly when Vale's `gcm_decrypt_LE` accepts
  the tag, leaving its plaintext in place, and otherwise fails, leaving zeros.

Longer AAD or messages run the by-8 code, which no proof covers, as do
seals of messages under 129 bytes, where it is faster, and AES-192 keys, for
which Vale has no routine. The key setup is rind's: its AES-NI key expansion and block cipher, and its
PCLMULQDQ GHASH key powers, whose Karatsuba product and reduction
`Rind/Gf128.lean` proves to be Vale's `gf128_mul_rev` of the shifted keys
(`mul_shiftKey1`). The rest is the Rust around Vale's routines, which
zero-pads the partial blocks and picks the six-block loop's share, as
EverCrypt's proven Low* wrapper does. It pads them with GHASH's
`load_partial` and `store_partial`, whose overlapping loads and stores
`Rind/X86_64/PartialBlock.lean` proves are the bytes at every length. The theorems assume `RunsValeAesGcm`: rind's CPU-feature
checks pick Vale's tier. `Rind/X86_64/AeadDispatch.lean` models the AEAD API's
function pointers (`Algorithm`'s `expand` and `Sealer`'s `Ops`), and
`seal_in_place_append_tag`, which is generic over its buffer.

`admin/prove` fails if a hand model's quote no longer matches the source, if
the source names `Ops`, builds a `Masker`, or writes its `mask` outside the
dispatch models' quotes, if it builds a digest `Algorithm` outside
`DigestAlgorithm.lean`'s, if it mentions `Verification::Ed25519(` or
`Parsed::Ed25519(` outside `SignatureDispatch.lean`'s, or if it mentions
`Verification::Ecdsa(`, `EcdsaP256`, or `EcdsaKey::`, builds an `EcdsaOps` or
`EcdsaPair`, or reads an `ops` outside the signature models' quotes.

## Layout

- `Rind/<Arch>/{Types,Funs}.lean`: Aeneas's translation, which `admin/prove`
  writes and git ignores.
- `Rind/<Arch>/{Types,Funs}External.lean` and `Rind/Core.lean`: what the
  translation leaves opaque, and models of the few `core` items Aeneas's
  library lacks.
- `Rind/<Arch>/S2nBignum.lean`, `Rind/<Arch>/AwsLc.lean`, and
  `Rind/X86_64/ValeAesGcm.lean`: s2n-bignum's, aws-lc-verification's, and
  Vale's theorems, restated as axioms about the routines' Rust wrappers.
- `Rind/X86_64/Simd.lean` and `Rind/X86_64/AesNi.lean`: models of the x86_64
  intrinsics rind's AES-GCM setup and partial blocks call, and of its AES-NI
  key expansion and block cipher, which load and store through raw pointers.
- `Rind/Spec.lean` and `Rind/Bytes.lean`: the elliptic-curve and ChaCha20
  specs and byte-conversion lemmas; `Rind/Sha2.lean` and
  `Rind/Sha2Lemmas.lean`: SHA-512's; `Rind/Ed25519.lean`: Ed25519's;
  `Rind/HashSpec.lean`: SHA-1's, SHA-256's, HMAC's, HKDF's, and PBKDF2's, and
  `Rind/HashSpecTest.lean`, their known-answer tests; `Rind/Vale.lean`,
  `Rind/ValeBytes.lean`, and `Rind/Gf128.lean`: Vale's AES and GF(2^128) specs
  and their lemmas.
- `Rind/X86_64/{Dispatch,DigestDispatch,DigestAlgorithm,SignatureDispatch,AeadDispatch}.lean`:
  the hand models of the agreement, header-protection, digest, signature, and
  AEAD APIs' dispatch.
- `Rind/X86_64/{X25519,Sha512,ChaCha20,Ed25519}.lean`: the X25519, SHA-512,
  ChaCha20, and Ed25519 proofs, and `Rind/X86_64/{Blockwise,Sha,Hmac}.lean`,
  SHA-1's, SHA-256's, and HMAC's; `Rind/X86_64/{AesKey,Ghash,PartialBlock,AesGcmGlue,AesGcm}.lean`:
  the AES-GCM proof, on x86_64 alone.
- `Rind/<Arch>/ShaBlocks.lean`: SHA-1 and SHA-256's block functions on each
  target, SHA-1's padded last blocks, and SHA-256's padded last blocks and
  finish.
- `admin/prove` copies the other `Rind/X86_64/` models and proofs to
  `Rind/Aarch64/` with the target renamed.
- `Rind/P256Group.lean`: that `p256` is prime, by a Pratt certificate, and
  that `p256Add` is the addition of Mathlib's group of points on the curve;
  `Rind/N256Prime.lean`: that `n256` is prime; `Rind/P256Multiples.lean`: the
  group laws and multiples ECDSA's twin multiplication relies on.
- `Rind/Aarch64/P256Dispatch.lean`, `Rind/Aarch64/P256Table.lean`, and
  `Rind/Aarch64/P256.lean`: the hand model of P-256's key generation, the
  generator table's proof, and the P-256 ECDH proof.
- `Rind/Aarch64/EcdsaDispatch.lean`, `Rind/Aarch64/P256Ecdsa.lean`, and
  `Rind/Aarch64/P256Signature.lean`: the hand model of ECDSA's dispatch and
  key generation, the proof of `high::ecdsa` and `mid::p256`'s ECDSA at
  P-256, and the signature API's theorems.

## Trust base

Beyond Lean's kernel:

- Charon and Aeneas's translation, and Aeneas's models of `core`, with
  `Rind/Core.lean`'s.
- That each hand model computes what the Rust it quotes does. They add no
  axiom.
- That `Rind/HashSpec.lean` transliterates FIPS 180-4, RFC 2104, RFC 5869,
  and RFC 8018.
- The restatement of each s2n-bignum and aws-lc-verification theorem as an
  axiom, under the composition rule in the
  [verification epic](/quest/m3/verified/README.md), and on aarch64 the
  caveats aws-lc-verification lists for its NSym proof. It lets a
  group-membership fact a proof must decide be its defining equation, so
  `group_carrier p256_group` is the curve equation that HOL Light's
  [`P256_GROUP`](https://github.com/jrh13/hol-light/blob/217dd32e798d98926d3ab81ed3dfcdf435831e1f/EC/nistp256.ml#L82)
  proves it is, and `group_carrier edwards25519_group` the one
  [`EDWARDS25519_GROUP`](https://github.com/jrh13/hol-light/blob/217dd32e798d98926d3ab81ed3dfcdf435831e1f/EC/edwards25519.ml#L92)
  does. A function a proof must compute, such as `group_pow p256_group`, is
  its HOL Light definition, transliterated, rather than opaque, so `p256Add`,
  `p256Pow`, and `p256Inv` in `Rind/Spec.lean` are trusted to be
  `weierstrass_add`, `group_pow`, and `ring_inv` on `p256_group`.
- That `Rind/Sha2.lean` restates cryptol-specs' SHA-512 around
  `processBlock_Common`.
- That `Rind/Spec.lean`'s ChaCha20 transliterates RFC 8439 and RFC 9001, its
  ECDSA FIPS 186-5, and
  `Rind/Ed25519.lean` RFC 8032 and s2n-bignum's encoding and decoding of
  edwards25519 points, whose `ed25519_decode` picks by Hilbert's choice as
  Lean's `Classical.epsilon` does.
- That `Rind/Vale.lean` transliterates Vale's AES and GF(2^128) specs and
  `hkeys_reqs_pub`, with the round functions Vale's AES spec assumes read as
  FIPS 197's, the S-box and `MixColumns` opaque.
- That `Rind/X86_64/Simd.lean`'s intrinsics compute what Intel's manual
  defines their instructions to, as an instruction model is trusted for
  s2n-bignum's and Vale's own proofs.
- That rind's inline assembly is s2n-bignum's, aws-lc's, and Vale's object
  code, as for `benchmarks/verified.toml`'s other entries.
- The translation ignores drops, which here wipe keys and keyed state and
  restore CPU state, and computes nothing an output depends on.
