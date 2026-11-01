// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

//! ChaCha20-Poly1305: aws-lc's `chacha20_poly1305_armv8`, which interleaves
//! NEON ChaCha20 with scalar Poly1305 in one pass, imported by
//! `admin/import-aws-lc`.
//!
//! The aws-lc assembly is not formally verified: its correctness rests on its
//! use and testing in BoringSSL and aws-lc, and on rind's tests of it against
//! RFC 8439, Wycheproof, aws-lc-rs, and separate ChaCha20 and Poly1305
//! passes.

/// Encrypts `inout` in place, returning the tag over `aad` and the ciphertext.
pub(crate) fn seal(key: &[u8; 32], nonce: &[u8; 12], aad: &[u8], inout: &mut [u8]) -> [u8; 16] {
    let mut data = Data::new(key, nonce);
    let ptr = inout.as_mut_ptr();
    // SAFETY: `inout` is `inout.len()` readable and writable bytes, which the
    // routine allows to alias exactly, `aad` is `aad.len()` readable bytes,
    // and `data` is the block it reads and writes. rind requires NEON.
    unsafe { chacha20_poly1305_seal(ptr, ptr, inout.len(), aad.as_ptr(), aad.len(), &mut data) };
    data.tag()
}

/// Decrypts `inout` in place, returning the tag over `aad` and the
/// ciphertext, which the caller checks.
pub(crate) fn open(key: &[u8; 32], nonce: &[u8; 12], aad: &[u8], inout: &mut [u8]) -> [u8; 16] {
    let mut data = Data::new(key, nonce);
    let ptr = inout.as_mut_ptr();
    // SAFETY: as in `seal`.
    unsafe { chacha20_poly1305_open(ptr, ptr, inout.len(), aad.as_ptr(), aad.len(), &mut data) };
    data.tag()
}

/// The routines' argument block: aws-lc's `chacha20_poly1305_seal_data`,
/// whose first 48 bytes are its `chacha20_poly1305_open_data`. On return,
/// the tag overwrites the start of the key.
#[repr(C, align(16))]
struct Data {
    key: [u8; 32],
    counter: u32,
    nonce: [u8; 12],
    extra_ciphertext: *const u8,
    extra_ciphertext_len: usize,
}

impl Data {
    fn new(key: &[u8; 32], nonce: &[u8; 12]) -> Self {
        Self {
            key: *key,
            // Block 0 keys Poly1305.
            counter: 0,
            nonce: *nonce,
            extra_ciphertext: core::ptr::null(),
            extra_ciphertext_len: 0,
        }
    }

    fn tag(&self) -> [u8; 16] {
        let mut tag = [0u8; 16];
        tag.copy_from_slice(&self.key[..16]);
        tag
    }
}

/// The ChaCha20 constant, the counter increments, a rotation mask, and the
/// Poly1305 clamp, which the routines load at once.
#[repr(C, align(128))]
struct Consts([u8; 64]);

static CHACHA20_CONSTS: Consts = Consts(include!(
    "aws_lc/chacha20_poly1305_armv8.chacha20_consts.rs"
));

/// Defines a naked function running an imported routine, which reaches its
/// table and helper through the `sym` operands listed.
macro_rules! routine {
    ($name:ident($($arg:ident: $ty:ty),*) { $($op:ident = $sym:ident),* }) => {
        #[unsafe(naked)]
        unsafe extern "C" fn $name($($arg: $ty),*) {
            #[cfg(not(target_vendor = "apple"))]
            core::arch::naked_asm!(
                include_str!(concat!("aws_lc/", stringify!($name), ".linux.s"))
                $(, $op = sym $sym)*
            );
            #[cfg(target_vendor = "apple")]
            core::arch::naked_asm!(
                include_str!(concat!("aws_lc/", stringify!($name), ".apple.s"))
                $(, $op = sym $sym)*
            );
        }
    };
}

routine!(chacha20_poly1305_seal(
    out: *mut u8,
    input: *const u8,
    len: usize,
    aad: *const u8,
    aad_len: usize,
    data: *mut Data
) {
    chacha20_consts = CHACHA20_CONSTS,
    poly_hash_ad_internal = poly_hash_ad_internal
});
routine!(chacha20_poly1305_open(
    out: *mut u8,
    input: *const u8,
    len: usize,
    aad: *const u8,
    aad_len: usize,
    data: *mut Data
) {
    chacha20_consts = CHACHA20_CONSTS,
    poly_hash_ad_internal = poly_hash_ad_internal
});

// Hashes the AAD into the Poly1305 state the routines keep in registers, so
// only they call it.
routine!(poly_hash_ad_internal() { poly_hash_ad_internal = poly_hash_ad_internal });

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::low::ct;
    use crate::low::generic::chacha20poly1305 as separate;

    // Every message length through the routines' eight-block loop and the
    // tails after it, AAD lengths around their 16-byte blocks, and a long
    // message, against separate ChaCha20 and Poly1305 passes, under a key
    // `admin/ctgrind` keeps secret.
    #[test]
    fn matches_separate_passes() {
        let key = core::array::from_fn(|i| i as u8);
        ct::secret_slice(&key);
        let nonce = core::array::from_fn(|i| (i * 7) as u8);
        let input: Vec<u8> = (0..16384 + 15).map(|i| (i * 13 + 5) as u8).collect();
        let lens = (0..=1100)
            .map(|len| (len, 13))
            .chain((0..=48).map(|aad| (300, aad)));
        for (len, aad_len) in lens.chain([(16384 + 15, 13)]) {
            let aad = &input[..aad_len];
            let mut sealed = input[..len].to_vec();
            let tag = ct::into_public(separate::seal(&key, &nonce, aad, &mut sealed));
            ct::public_slice(&sealed);
            let mut ours = input[..len].to_vec();
            let ours_tag = ct::into_public(seal(&key, &nonce, aad, &mut ours));
            ct::public_slice(&ours);
            assert_eq!(ours_tag, tag, "seal tag, {len} bytes, {aad_len} of AAD");
            assert_eq!(ours, sealed, "seal, {len} bytes, {aad_len} of AAD");
            let ours_tag = ct::into_public(open(&key, &nonce, aad, &mut ours));
            ct::public_slice(&ours);
            assert_eq!(ours_tag, tag, "open tag, {len} bytes, {aad_len} of AAD");
            assert_eq!(ours, input[..len], "open, {len} bytes, {aad_len} of AAD");
        }
    }
}
