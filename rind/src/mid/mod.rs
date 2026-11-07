// Written for Graviola by Joe Birr-Pixton, 2024.
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

#![deny(unsafe_code)]

// libcrux exposes whole operations rather than the field and bignum
// arithmetic these build on, so 32-bit ARM swaps them at this layer.
#[cfg_attr(target_arch = "arm", path = "arm/aes_gcm.rs")]
pub(super) mod aes_gcm;
#[cfg_attr(target_arch = "arm", path = "arm/ed25519.rs")]
pub(super) mod ed25519;

pub(super) mod aes;
pub(super) mod aes_cbc;
pub(super) mod aes_kw;
pub(super) mod chacha20;
pub(super) mod chacha20poly1305;
pub(super) mod md5;
pub(super) mod mlkem768;
pub(super) mod p256;
pub(super) mod p384;
pub(super) mod p521;
pub(super) mod rng;
pub(super) mod rsa_key_size;
pub(super) mod rsa_priv;
pub(super) mod rsa_pub;
pub(super) mod sha1;
pub(super) mod sha2;
pub(super) mod sha3;
pub(super) mod util;
pub(super) mod x25519;
pub(super) mod xchacha20poly1305;
