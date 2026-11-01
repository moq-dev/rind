// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

//! AES on NEON alone, using aws-lc's `vpaes-armv8` routines, for CPUs without
//! the AES instructions.
//!
//! The assembly is aws-lc's, imported by `admin/import-aws-lc`. Its S-box is
//! Mike Hamburg's vector permutation AES, which computes with `tbl` lookups
//! into registers, never memory, so its timing is independent of the key and
//! data. It is not formally verified: its correctness rests on its use and
//! testing in OpenSSL, BoringSSL, and aws-lc, and on rind's tests of it
//! against the AES instructions, Wycheproof, and aws-lc-rs.

use crate::low;

/// An expanded AES-128 or AES-256 encryption key, in vpaes's own format:
/// aws-lc's `AES_KEY`.
#[repr(C, align(16))]
pub(crate) struct VpaesKey {
    rd_key: [u32; 60],
    rounds: u32,
}

impl VpaesKey {
    /// Expands a 16- or 32-byte key.
    pub(crate) fn new(key: &[u8]) -> Self {
        let bits = match key.len() {
            16 => 128,
            32 => 256,
            _ => unreachable!("callers check the AES key length"),
        };
        let mut r = Self {
            rd_key: [0; 60],
            rounds: 0,
        };
        // SAFETY: `key` holds `bits / 8` bytes and `r` is an `AES_KEY`. The
        // routines need only NEON, which rind requires.
        let ret = unsafe { vpaes_set_encrypt_key(key.as_ptr(), bits, &mut r) };
        // aws-lc's always succeeds.
        debug_assert_eq!(ret, 0);
        r
    }

    /// Encrypts one block in place.
    pub(crate) fn encrypt_block(&self, inout: &mut [u8; 16]) {
        // SAFETY: `inout` is one readable and writable block, which aws-lc
        // allows to alias, and `self` an expanded key.
        unsafe { vpaes_encrypt(inout.as_ptr(), inout.as_mut_ptr(), self) }
    }

    /// XORs counter-mode keystream into whole blocks.
    ///
    /// The counter blocks are `ivec`, then `ivec` with its last four bytes,
    /// a big-endian counter, incremented with 32-bit wrapping.
    pub(crate) fn ctr32(&self, ivec: &[u8; 16], inout: &mut [[u8; 16]]) {
        // SAFETY: `inout` is `inout.len()` readable and writable blocks, which
        // aws-lc allows to alias, and `self` an expanded key. The routine
        // returns at once for zero blocks.
        unsafe {
            vpaes_ctr32_encrypt_blocks(
                inout.as_ptr().cast(),
                inout.as_mut_ptr().cast(),
                inout.len(),
                self,
                ivec,
            )
        }
    }
}

impl Drop for VpaesKey {
    fn drop(&mut self) {
        low::zeroise_value(self);
    }
}

impl low::generic::zeroise::Zeroable for VpaesKey {}

/// aws-lc's `_vpaes_consts`. `_vpaes_schedule_mangle` steps through its
/// `.Lk_sr` rows by masking an address, which needs them 128-byte aligned.
#[repr(C, align(128))]
struct Consts([u64; 94]);

static VPAES_CONSTS: Consts = Consts(include!("aws_lc/vpaes-armv8.vpaes_consts.rs"));

/// Defines a naked function running an imported routine, which reaches its
/// table and helpers through the `sym` operands listed.
macro_rules! vpaes_routine {
    ($name:ident($($arg:ident: $ty:ty),*) $(-> $ret:ty)? { $($op:ident = $sym:ident),* }) => {
        #[unsafe(naked)]
        unsafe extern "C" fn $name($($arg: $ty),*) $(-> $ret)? {
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

vpaes_routine!(vpaes_set_encrypt_key(user_key: *const u8, bits: u32, key: *mut VpaesKey) -> i32 {
    vpaes_schedule_core = vpaes_schedule_core
});
vpaes_routine!(vpaes_encrypt(input: *const u8, output: *mut u8, key: *const VpaesKey) {
    vpaes_encrypt_preheat = vpaes_encrypt_preheat,
    vpaes_encrypt_core = vpaes_encrypt_core
});
vpaes_routine!(vpaes_ctr32_encrypt_blocks(
    input: *const u8,
    output: *mut u8,
    blocks: usize,
    key: *const VpaesKey,
    ivec: *const [u8; 16]
) {
    vpaes_encrypt_preheat = vpaes_encrypt_preheat,
    vpaes_encrypt_core = vpaes_encrypt_core,
    vpaes_encrypt_2x = vpaes_encrypt_2x
});

// The routines' helpers, which pass their arguments in registers of their
// own choosing rather than by the C ABI, so only the routines call them.
vpaes_routine!(vpaes_encrypt_preheat() { vpaes_consts = VPAES_CONSTS });
vpaes_routine!(vpaes_encrypt_core() { vpaes_consts = VPAES_CONSTS });
vpaes_routine!(vpaes_encrypt_2x() { vpaes_consts = VPAES_CONSTS });
vpaes_routine!(vpaes_key_preheat() { vpaes_consts = VPAES_CONSTS });
vpaes_routine!(vpaes_schedule_core() {
    vpaes_consts = VPAES_CONSTS,
    vpaes_key_preheat = vpaes_key_preheat,
    vpaes_schedule_192_smear = vpaes_schedule_192_smear,
    vpaes_schedule_round = vpaes_schedule_round,
    vpaes_schedule_low_round = vpaes_schedule_low_round,
    vpaes_schedule_transform = vpaes_schedule_transform,
    vpaes_schedule_mangle = vpaes_schedule_mangle
});
vpaes_routine!(vpaes_schedule_192_smear() {});
vpaes_routine!(vpaes_schedule_round() {});
vpaes_routine!(vpaes_schedule_low_round() {});
vpaes_routine!(vpaes_schedule_transform() {});
vpaes_routine!(vpaes_schedule_mangle() {});
