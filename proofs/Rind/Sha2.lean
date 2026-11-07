module
public import Aeneas
@[expose] public section
open Aeneas Aeneas.Std

/-!
# What rind's SHA-512 computes

FIPS 180-4's SHA-512, SHA-384, and SHA-512/256 of a message of bytes, as
cryptol-specs' `Primitive::Keyless::Hash::SHA` defines them at the revision
aws-lc-verification's proofs import (fba861b8): the message padded, parsed into
128-byte blocks of sixteen big-endian words, each compressed into the chaining
value in turn from the initial value, which is then written out big-endian and
truncated. Its compression function, `processBlock_Common`, stays opaque, so
nothing here assumes how it compresses a block: aws-lc-verification's
theorems, restated in `Rind.<Arch>.AwsLc`, are what tie it to rind's routines.
-/

namespace rind.spec

/-- The word that eight big-endian bytes encode. -/
def beWord (b : List U8) : U64 :=
  ⟨(BitVec.fromBEBytes (b.map (·.bv))).setWidth 64⟩

/-- The bytes `u64::to_be_bytes` writes. -/
def beBytes (w : U64) : List U8 :=
  w.bv.toBEBytes.map (@UScalar.mk UScalarTy.U8)

/-- A 128-byte block's sixteen big-endian words: Cryptol's
`split (join block) : [16][64]`. -/
def blockWords (block : List U8) : List U64 :=
  (List.range 16).map fun i => beWord ((block.drop (8 * i)).take 8)

/-- SHA-512's compression function, of the eight-word chaining value and a
block's sixteen words: cryptol-specs' `processBlock_Common`, defined in
`Primitive/Keyless/Hash/SHA.cry` at
https://github.com/GaloisInc/cryptol-specs/blob/fba861b858fc62e6f77e7bc033d81eff6c0af9df/Primitive/Keyless/Hash/SHA.cry#L65
with `SHA512.cry`'s constants and sigma functions, as FIPS 180-4 6.4.2 does.

It is opaque here: nothing is assumed of it beyond the routine contracts in
`Rind.<Arch>.AwsLc`, which restate aws-lc-verification's theorems about it. -/
opaque processBlock : List U64 → List U64 → List U64

/-- The chaining value `h` takes after each 128-byte block of `bytes` in
turn: cryptol-specs' `processBlocks h bytes 0 (len / 128)` for at least one
block, which processes blocks from index 0 until `num * 128`, and the identity
for none. -/
def compress (h : List U64) (bytes : List U8) : List U64 :=
  if 128 ≤ bytes.length then
    compress (processBlock h (blockWords (bytes.take 128))) (bytes.drop 128)
  else h
termination_by bytes.length

/-- FIPS 180-4 5.1.2's padding of a message of bytes: a one bit, as the byte
0x80, then the fewest zeros that end it 128 bits short of a whole block, then
its length in bits as 128 big-endian bits. Cryptol's `pad`, for a message of
fewer than 2^125 bytes, whose length in bits fits. -/
def sha512Pad (m : List U8) : List U8 :=
  m ++ 0x80#u8 :: List.replicate ((239 - m.length % 128) % 128) 0#u8 ++
    (BitVec.ofNat 128 (8 * m.length)).toBEBytes.map (@UScalar.mk UScalarTy.U8)

/-- SHA-512's initial value, `SHA512.cry`'s `H0`. -/
def sha512Iv : List U64 :=
  [0x6a09e667f3bcc908#u64, 0xbb67ae8584caa73b#u64, 0x3c6ef372fe94f82b#u64, 0xa54ff53a5f1d36f1#u64,
   0x510e527fade682d1#u64, 0x9b05688c2b3e6c1f#u64, 0x1f83d9abfb41bd6b#u64, 0x5be0cd19137e2179#u64]

/-- SHA-384's initial value, `SHA384.cry`'s `H0`. -/
def sha384Iv : List U64 :=
  [0xcbbb9d5dc1059ed8#u64, 0x629a292a367cd507#u64, 0x9159015a3070dd17#u64, 0x152fecd8f70e5939#u64,
   0x67332667ffc00b31#u64, 0x8eb44a8768581511#u64, 0xdb0c2e0d64f98fa7#u64, 0x47b5481dbefa4fa4#u64]

/-- SHA-512/256's initial value, `SHA512_256.cry`'s `H0`. -/
def sha512_256Iv : List U64 :=
  [0x22312194fc2bf72c#u64, 0x9f555fa3c84c64c2#u64, 0x2393b86b6f53b151#u64, 0x963877195940eabd#u64,
   0x96283ee2a88effe3#u64, 0xbe5e1e2553863992#u64, 0x2b0199fc2c85b8aa#u64, 0x0eb72ddc81c52ca2#u64]

/-- The SHA-512 family's chaining value after a message, from initial value
`iv`, written out big-endian: Cryptol's `join (SHA_2_Common' ...)`. -/
def sha512Words (iv : List U64) (m : List U8) : List U8 :=
  (compress iv (sha512Pad m)).flatMap beBytes

/-- SHA-512, Cryptol's `SHA512::sha` on a message of bytes. -/
def sha512 (m : List U8) : List U8 := sha512Words sha512Iv m

/-- SHA-384, Cryptol's `SHA384::sha`: the first 48 bytes from its own
initial value. -/
def sha384 (m : List U8) : List U8 := (sha512Words sha384Iv m).take 48

/-- SHA-512/256, Cryptol's `SHA512_256::sha`: the first 32 bytes from its own
initial value. -/
def sha512_256 (m : List U8) : List U8 := (sha512Words sha512_256Iv m).take 32

end rind.spec
