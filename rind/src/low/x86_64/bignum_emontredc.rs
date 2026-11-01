// generated source. do not edit.
#![allow(non_upper_case_globals, unused_macros, unused_imports)]
use crate::low::macros::*;

// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

// ----------------------------------------------------------------------------
// Extended Montgomery reduce, returning results in input-output buffer
// Inputs z[2*k], m[k], w; outputs function return (extra result bit) and z[2*k]
//
//    extern uint64_t bignum_emontredc(uint64_t k, uint64_t *z, const uint64_t *m,
//                                     uint64_t w);
//
// Assumes that z initially holds a 2k-digit bignum z_0, m is a k-digit odd
// bignum and m * w == -1 (mod 2^64). This function also uses z for the output
// as well as returning a carry c of 0 or 1. This encodes two numbers: in the
// lower half of the z buffer we have q = z[0..k-1], while the upper half
// together with the carry gives r = 2^{64k}*c + z[k..2k-1]. These values
// satisfy z_0 + q * m = 2^{64k} * r, i.e. r gives a raw (unreduced) Montgomery
// reduction while q gives the multiplier that was used. Another way of
// thinking of it is that if z' is the output z with the lower half replaced
// with zeros, then z_0 + q * m = 2^{128k} * c + z'.
//
// Standard x86-64 ABI: RDI = k, RSI = z, RDX = m, RCX = w, returns RAX
// Microsoft x64 ABI:   RCX = k, RDX = z, R8 = m, R9 = w, returns RAX
// ----------------------------------------------------------------------------

// Argument m comes in in rdx but we copy it to r8

macro_rules! k {
    () => {
        "rdi"
    };
}
macro_rules! z {
    () => {
        "rsi"
    };
}
macro_rules! m {
    () => {
        "r8"
    };
}
macro_rules! w {
    () => {
        "rcx"
    };
}

// General temp, low part of product and mul input
macro_rules! a {
    () => {
        "rax"
    };
}
// General temp, High part of product
macro_rules! b {
    () => {
        "rdx"
    };
}
// Home for i'th digit or Montgomery multiplier
macro_rules! d {
    () => {
        "rbx"
    };
}

// Outer loop counter
macro_rules! i {
    () => {
        "r9"
    };
}
// Inner loop counter
macro_rules! j {
    () => {
        "r10"
    };
}

macro_rules! h {
    () => {
        "r11"
    };
}
macro_rules! e {
    () => {
        "r12"
    };
}
macro_rules! t {
    () => {
        "r13"
    };
}
macro_rules! c {
    () => {
        "r14"
    };
}

macro_rules! cshort {
    () => {
        "r14d"
    };
}
macro_rules! jshort {
    () => {
        "r10d"
    };
}

/// Extended Montgomery reduce, returning results in input-output buffer
///
/// Inputs z[2*k], m[k], w; outputs function return (extra result bit) and z[2*k]
///
/// Assumes that z initially holds a 2k-digit bignum z_0, m is a k-digit odd
/// bignum and m * w == -1 (mod 2^64). This function also uses z for the output
/// as well as returning a carry c of 0 or 1. This encodes two numbers: in the
/// lower half of the z buffer we have q = z[0..k-1], while the upper half
/// together with the carry gives r = 2^{64k}*c + z[k..2k-1]. These values
/// satisfy z_0 + q * m = 2^{64k} * r, i.e. r gives a raw (unreduced) Montgomery
/// reduction while q gives the multiplier that was used. Another way of
/// thinking of it is that if z' is the output z with the lower half replaced
/// with zeros, then z_0 + q * m = 2^{128k} * c + z'.
pub(crate) fn bignum_emontredc(z: &mut [u64], m: &[u64], w: u64) -> u64 {
    let ret: u64;
    debug_assert!(z.len() == m.len() * 2);
    // SAFETY: inline assembly. see [crate::low::inline_assembly_safety] for safety info.
    unsafe {
        core::arch::asm!(

        Q!("    endbr64         " ),

        // Save registers

        Q!("    push            " "rbx"),
        Q!("    push            " "r12"),
        Q!("    push            " "r13"),
        Q!("    push            " "r14"),

        // Initialize top carry to zero immediately to catch the k = 0 case

        Q!("    xor             " c!() ", " c!()),

        // If k = 0 the whole operation is trivial

        Q!("    test            " k!() ", " k!()),
        Q!("    jz              " Label!("Lbignum_emontredc_end", 2, After)),

        // Move m into its permanent home since we need RDX for muls

        Q!("    mov             " m!() ", rdx"),

        // Launch into the outer loop

        Q!("    xor             " i!() ", " i!()),
        Q!(Label!("Lbignum_emontredc_outerloop", 3) ":"),
        Q!("    mov             " e!() ", [" z!() "]"),
        Q!("    mov             " d!() ", " w!()),
        Q!("    imul            " d!() ", " e!()),
        Q!("    mov             " a!() ", [" m!() "]"),
        Q!("    mul             " d!()),
        Q!("    mov             " "[" z!() "], " d!()),
        Q!("    add             " a!() ", " e!()),
        Q!("    mov             " h!() ", rdx"),
        Q!("    mov             " jshort!() ", 1"),
        Q!("    mov             " t!() ", " k!()),
        Q!("    dec             " t!()),
        Q!("    jz              " Label!("Lbignum_emontredc_montend", 4, After)),

        // JCC erratum (SKX102): pad so this loop's
        Q!("    .byte           " "0x66, 0x90"),
        // back-edge does not straddle a 32-byte boundary at 0-mod-32 entry
        Q!(Label!("Lbignum_emontredc_montloop", 5) ":"),
        Q!("    adc             " h!() ", [" z!() "+ 8 * " j!() "]"),
        Q!("    sbb             " e!() ", " e!()),
        Q!("    mov             " a!() ", [" m!() "+ 8 * " j!() "]"),
        Q!("    mul             " d!()),
        Q!("    sub             " "rdx, " e!()),
        Q!("    add             " a!() ", " h!()),
        Q!("    mov             " "[" z!() "+ 8 * " j!() "], " a!()),
        Q!("    mov             " h!() ", rdx"),
        Q!("    inc             " j!()),
        Q!("    dec             " t!()),
        Q!("    jnz             " Label!("Lbignum_emontredc_montloop", 5, Before)),

        Q!(Label!("Lbignum_emontredc_montend", 4) ":"),
        Q!("    adc             " h!() ", " c!()),
        Q!("    mov             " cshort!() ", 0"),
        Q!("    adc             " c!() ", 0"),
        Q!("    mov             " a!() ", [" z!() "+ 8 * " k!() "]"),
        Q!("    add             " a!() ", " h!()),
        Q!("    mov             " "[" z!() "+ 8 * " k!() "], " a!()),
        Q!("    adc             " c!() ", 0"),

        // End of outer loop.

        Q!("    add             " z!() ", 8"),
        Q!("    inc             " i!()),
        Q!("    cmp             " i!() ", " k!()),
        Q!("    jc              " Label!("Lbignum_emontredc_outerloop", 3, Before)),

        Q!(Label!("Lbignum_emontredc_end", 2) ":"),

        // Put the top carry in the expected place, restore registers and return

        Q!("    mov             " "rax, " c!()),
        Q!("    pop             " "r14"),
        Q!("    pop             " "r13"),
        Q!("    pop             " "r12"),
        Q!("    pop             " "rbx"),
        inout("rdi") m.len() => _,
        inout("rsi") z.as_mut_ptr() => _,
        inout("rdx") m.as_ptr() => _,
        inout("rcx") w => _,
        out("rax") ret,
        // clobbers
        out("r10") _,
        out("r11") _,
        out("r12") _,
        out("r13") _,
        out("r14") _,
        out("r8") _,
        out("r9") _,
            )
    };
    ret
}
