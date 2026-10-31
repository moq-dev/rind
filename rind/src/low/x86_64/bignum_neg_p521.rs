// generated source. do not edit.
#![allow(non_upper_case_globals, unused_macros, unused_imports)]
use crate::low::macros::*;

// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

// ----------------------------------------------------------------------------
// Negate modulo p_521, z := (-x) mod p_521, assuming x reduced
// Input x[9]; output z[9]
//
//    extern void bignum_neg_p521(uint64_t z[static 9], const uint64_t x[static 9]);
//
// Standard x86-64 ABI: RDI = z, RSI = x
// Microsoft x64 ABI:   RCX = z, RDX = x
// ----------------------------------------------------------------------------

macro_rules! z {
    () => {
        "rdi"
    };
}
macro_rules! x {
    () => {
        "rsi"
    };
}

macro_rules! p {
    () => {
        "rax"
    };
}
macro_rules! d0 {
    () => {
        "rcx"
    };
}
macro_rules! d1 {
    () => {
        "rdx"
    };
}
macro_rules! d2 {
    () => {
        "r8"
    };
}
macro_rules! d3 {
    () => {
        "r9"
    };
}
macro_rules! d4 {
    () => {
        "r10"
    };
}
macro_rules! d5 {
    () => {
        "r11"
    };
}

/// Negate modulo p_521, z := (-x) mod p_521, assuming x reduced
///
/// Input x[9]; output z[9]
pub(crate) fn bignum_neg_p521(z: &mut [u64; 9], x: &[u64; 9]) {
    // SAFETY: inline assembly. see [crate::low::inline_assembly_safety] for safety info.
    unsafe {
        core::arch::asm!(

        Q!("    endbr64         " ),

        // Load most inputs (into the limited registers) and OR all of them to get p

        Q!("    mov             " d0!() ", [" x!() "]"),
        Q!("    mov             " p!() ", " d0!()),
        Q!("    mov             " d1!() ", [" x!() "+ 8]"),
        Q!("    or              " p!() ", " d1!()),
        Q!("    mov             " d2!() ", [" x!() "+ 16]"),
        Q!("    or              " p!() ", " d2!()),
        Q!("    mov             " d3!() ", [" x!() "+ 24]"),
        Q!("    or              " p!() ", " d3!()),
        Q!("    mov             " d4!() ", [" x!() "+ 32]"),
        Q!("    or              " p!() ", " d4!()),
        Q!("    mov             " d5!() ", [" x!() "+ 40]"),
        Q!("    or              " p!() ", " d5!()),
        Q!("    or              " p!() ", [" x!() "+ 48]"),
        Q!("    or              " p!() ", [" x!() "+ 56]"),
        Q!("    or              " p!() ", [" x!() "+ 64]"),

        // Turn p into a bitmask for "input is nonzero", so that we avoid doing
        // -0 = p_521 and hence maintain strict modular reduction

        Q!("    neg             " p!()),
        Q!("    sbb             " p!() ", " p!()),

        // Since p_521 is all 1s, the subtraction is just an exclusive-or with p
        // to give an optional inversion, with a slight fiddle for the top digit.

        Q!("    xor             " d0!() ", " p!()),
        Q!("    mov             " "[" z!() "], " d0!()),
        Q!("    xor             " d1!() ", " p!()),
        Q!("    mov             " "[" z!() "+ 8], " d1!()),
        Q!("    xor             " d2!() ", " p!()),
        Q!("    mov             " "[" z!() "+ 16], " d2!()),
        Q!("    xor             " d3!() ", " p!()),
        Q!("    mov             " "[" z!() "+ 24], " d3!()),
        Q!("    xor             " d4!() ", " p!()),
        Q!("    mov             " "[" z!() "+ 32], " d4!()),
        Q!("    xor             " d5!() ", " p!()),
        Q!("    mov             " "[" z!() "+ 40], " d5!()),
        Q!("    mov             " d0!() ", [" x!() "+ 48]"),
        Q!("    xor             " d0!() ", " p!()),
        Q!("    mov             " "[" z!() "+ 48], " d0!()),
        Q!("    mov             " d1!() ", [" x!() "+ 56]"),
        Q!("    xor             " d1!() ", " p!()),
        Q!("    mov             " "[" z!() "+ 56], " d1!()),
        Q!("    mov             " d2!() ", [" x!() "+ 64]"),
        Q!("    and             " p!() ", 0x1FF"),
        Q!("    xor             " d2!() ", " p!()),
        Q!("    mov             " "[" z!() "+ 64], " d2!()),

        // Return

        inout("rdi") z.as_mut_ptr() => _,
        inout("rsi") x.as_ptr() => _,
        // clobbers
        out("r10") _,
        out("r11") _,
        out("r8") _,
        out("r9") _,
        out("rax") _,
        out("rcx") _,
        out("rdx") _,
            )
    };
}
