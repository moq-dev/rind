// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

//! X25519: the shared secret on BoringSSL's `x25519-asm-arm` NEON ladder
//! where the CPU has NEON, and everything else on the portable backend's
//! curve25519-dalek, whose precomputed Edwards table beats the NEON ladder
//! for the public key. Both clamp the scalar and mask the point's top bit as
//! RFC7748 requires.
//!
//! The assembly is BoringSSL's, imported by `admin/import-boringssl`, which
//! took it from SUPERCOP's `neon2`. It is not formally verified: its
//! correctness rests on its use and testing in BoringSSL and ring, and on
//! rind's tests of it against dalek, Wycheproof, and aws-lc-rs.

use super::cpu::HaveNeon;
use crate::low::portable::curve25519::{self as portable, from_bytes, to_bytes};

// curve25519-dalek chooses its backend from cfgs that a build's RUSTFLAGS set
// for every crate, rind included, so refuse those that would replace the
// serial 32-bit backend it picks for this target.
#[cfg(any(curve25519_dalek_bits = "64", curve25519_dalek_backend = "fiat"))]
compile_error!(
    "rind runs curve25519-dalek's serial 32-bit backend on 32-bit ARM: \
     remove the curve25519_dalek_bits and curve25519_dalek_backend cfgs"
);

unsafe extern "C" {
    #[link_name = aws_lc_symbol!("x25519_NEON")]
    fn x25519_neon(out: *mut [u8; 32], scalar: *const [u8; 32], point: *const [u8; 32]);
}

// ARM mode, so Thumb callers reach it through interworking; the file sets
// `.fpu neon` itself, and restoring `.fpu` afterwards keeps the object's
// build attributes at the target's VFPv3, as in `aesv8_armx`.
core::arch::global_asm!(
    ".code 32",
    include_str!("boringssl/x25519-asm-arm.s"),
    ".fpu vfpv3",
    x25519_NEON = sym x25519_neon,
);

/// res := X25519(scalar, point), in little-endian words.
pub(crate) fn curve25519_x25519(res: &mut [u64; 4], scalar: &[u64; 4], point: &[u64; 4]) {
    match HaveNeon::check() {
        Some(neon) => *res = from_bytes(&ladder_neon(neon, &to_bytes(scalar), &to_bytes(point))),
        None => portable::curve25519_x25519(res, scalar, point),
    }
}

fn ladder_neon(_: HaveNeon, scalar: &[u8; 32], point: &[u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    // SAFETY: each pointer is to 32 bytes, and the token proves the CPU has
    // NEON.
    unsafe { x25519_neon(&mut out, scalar, point) };
    out
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use curve25519_dalek::montgomery::MontgomeryPoint;

    use super::*;
    use crate::low;

    // Every other test sees only the path the CPU picks, so the NEON ladder is
    // checked against dalek's here, with the scalar marked secret so ctgrind
    // checks both: unclamped scalars, and points at and beyond the field's
    // edges, including a set top bit, which both must ignore.
    #[test]
    fn neon_matches_dalek() {
        let Some(neon) = HaveNeon::check() else {
            return;
        };
        let mut points = vec![[0u8; 32], [0xff; 32]];
        // p - 1, p, and p + 1, which reduces to 1.
        for low in [0xec, 0xed, 0xee] {
            let mut p = [0xff; 32];
            p[0] = low;
            p[31] = 0x7f;
            points.push(p);
        }
        let mut basepoint = [0u8; 32];
        basepoint[0] = 9;
        points.push(basepoint);
        let mut x = 0x9e3779b9u32;
        for _ in 0..8 {
            points.push(core::array::from_fn(|_| {
                x = x.wrapping_mul(1664525).wrapping_add(1013904223);
                (x >> 24) as u8
            }));
        }

        for (i, point) in points.iter().enumerate() {
            let scalar: [u8; 32] = core::array::from_fn(|j| (i * 37 + j * 101) as u8 ^ 0xa5);
            let scalar = low::ct::into_secret(scalar);
            let want = low::ct::into_public(MontgomeryPoint(*point).mul_clamped(scalar).0);
            let got = low::ct::into_public(ladder_neon(neon, &scalar, point));
            assert_eq!(got, want, "point {i}");
        }
    }
}
