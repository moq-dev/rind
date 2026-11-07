import Rind.X86_64.X25519
import Rind.X86_64.Sha512
import Rind.X86_64.ChaCha20
import Rind.X86_64.AesGcm
import Rind.X86_64.Ed25519
open rind.x86_64

/-!
The axioms each theorem rests on, beyond Lean's own: s2n-bignum's contracts
in `Rind.X86_64.S2nBignum` for X25519 and Ed25519, aws-lc's in
`Rind.X86_64.AwsLc` for the SHA-512 family and Ed25519's hashes, Vale's in
`Rind.X86_64.ValeAesGcm` for AES-GCM, and nothing else. A change here is a
change to the trust base.
-/

/-- info: 'rind.x86_64.x25519_generate' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms x25519_generate

/-- info: 'rind.x86_64.x25519_from_scalar' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms x25519_from_scalar

/-- info: 'rind.x86_64.x25519_public_key' depends on axioms: [propext,
 Classical.choice,
 Quot.sound,
 curve25519_x25519base_alt_spec,
 curve25519_x25519base_spec] -/
#guard_msgs in
#print axioms x25519_public_key

/-- info: 'rind.x86_64.x25519_agree' depends on axioms: [propext,
 Classical.choice,
 Quot.sound,
 bignum_eq_spec,
 curve25519_x25519_alt_spec,
 curve25519_x25519_spec] -/
#guard_msgs in
#print axioms x25519_agree

/-- info: 'rind.x86_64.x25519_shared_secret' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms x25519_shared_secret

/-- info: 'rind.x86_64.sha512_family_digest' depends on axioms: [propext, Classical.choice, Quot.sound, compress_avx_spec] -/
#guard_msgs in
#print axioms sha512_family_digest

/-- info: 'rind.x86_64.sha512_family_context' depends on axioms: [propext, Classical.choice, Quot.sound, compress_avx_spec] -/
#guard_msgs in
#print axioms sha512_family_context

/-- info: 'rind.x86_64.chacha20_new' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms chacha20_new

/-- info: 'rind.x86_64.chacha20_mask' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms chacha20_mask

/-- info: 'rind.x86_64.aes_gcm_new' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms aes_gcm_new

/-- info: 'rind.x86_64.aes_gcm_seal' depends on axioms: [propext,
 Classical.choice,
 Quot.sound,
 counter_block_spec,
 gcm128_encrypt_opt_spec,
 gcm256_encrypt_opt_spec] -/
#guard_msgs in
#print axioms aes_gcm_seal

/-- info: 'rind.x86_64.aes_gcm_seal_append_tag' depends on axioms: [propext,
 Classical.choice,
 Quot.sound,
 counter_block_spec,
 gcm128_encrypt_opt_spec,
 gcm256_encrypt_opt_spec] -/
#guard_msgs in
#print axioms aes_gcm_seal_append_tag

/-- info: 'rind.x86_64.aes_gcm_seal_append_tag_vec' depends on axioms: [propext,
 Classical.choice,
 Quot.sound,
 counter_block_spec,
 gcm128_encrypt_opt_spec,
 gcm256_encrypt_opt_spec] -/
#guard_msgs in
#print axioms aes_gcm_seal_append_tag_vec

/-- info: 'rind.x86_64.aes_gcm_open_separate_tag' depends on axioms: [propext,
 Classical.choice,
 Quot.sound,
 counter_block_spec,
 gcm128_decrypt_opt_spec,
 gcm256_decrypt_opt_spec] -/
#guard_msgs in
#print axioms aes_gcm_open_separate_tag

/-- info: 'rind.x86_64.aes_gcm_open' depends on axioms: [propext,
 Classical.choice,
 Quot.sound,
 counter_block_spec,
 gcm128_decrypt_opt_spec,
 gcm256_decrypt_opt_spec] -/
#guard_msgs in
#print axioms aes_gcm_open

/-- info: 'rind.x86_64.ed25519_generate' depends on axioms: [propext,
 Classical.choice,
 Quot.sound,
 compress_avx_spec,
 edwards25519_scalarmulbase_alt_spec,
 edwards25519_scalarmulbase_spec] -/
#guard_msgs in
#print axioms ed25519_generate

/-- info: 'rind.x86_64.ed25519_from_seed_and_public_key' depends on axioms: [propext,
 Classical.choice,
 Quot.sound,
 compress_avx_spec,
 edwards25519_scalarmulbase_alt_spec,
 edwards25519_scalarmulbase_spec] -/
#guard_msgs in
#print axioms ed25519_from_seed_and_public_key

/-- info: 'rind.x86_64.ed25519_sign' depends on axioms: [propext,
 Classical.choice,
 Quot.sound,
 bignum_madd_n25519_alt_spec,
 bignum_madd_n25519_spec,
 bignum_mod_n25519_spec,
 compress_avx_spec,
 edwards25519_scalarmulbase_alt_spec,
 edwards25519_scalarmulbase_spec] -/
#guard_msgs in
#print axioms ed25519_sign

/-- info: 'rind.x86_64.ed25519_key_pair_public_key' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms ed25519_key_pair_public_key

/-- info: 'rind.x86_64.ed25519_key_pair_verify' depends on axioms: [propext,
 Classical.choice,
 Quot.sound,
 bignum_cmp_lt_spec,
 bignum_mod_n25519_spec,
 bignum_neg_p25519_spec,
 compress_avx_spec,
 edwards25519_scalarmuldouble_alt_spec,
 edwards25519_scalarmuldouble_spec] -/
#guard_msgs in
#print axioms ed25519_key_pair_verify

/-- info: 'rind.x86_64.ed25519_public_key_new' depends on axioms: [propext,
 Classical.choice,
 Quot.sound,
 bignum_cmp_lt_spec,
 bignum_eq_spec,
 bignum_mod_n25519_spec,
 bignum_neg_p25519_spec,
 compress_avx_spec,
 edwards25519_decode_alt_spec,
 edwards25519_decode_spec,
 edwards25519_scalarmuldouble_alt_spec,
 edwards25519_scalarmuldouble_spec] -/
#guard_msgs in
#print axioms ed25519_public_key_new
