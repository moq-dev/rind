// generated source. do not edit.
#![allow(non_upper_case_globals, unused_macros, unused_imports)]
use crate::low::macros::*;

// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

// ----------------------------------------------------------------------------
// Add modulo p_521, z := (x + y) mod p_521, assuming x and y reduced
// Inputs x[9], y[9]; output z[9]
//
//    extern void bignum_add_p521(uint64_t z[static 9], const uint64_t x[static 9],
//                                const uint64_t y[static 9]);
//
// Standard x86-64 ABI: RDI = z, RSI = x, RDX = y
// Microsoft x64 ABI:   RCX = z, RDX = x, R8 = y
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
macro_rules! y {
    () => {
        "rdx"
    };
}

macro_rules! d0 {
    () => {
        "rax"
    };
}
macro_rules! d1 {
    () => {
        "rcx"
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
macro_rules! d6 {
    () => {
        "r12"
    };
}
macro_rules! d7 {
    () => {
        "rbx"
    };
}

// Re-use the input pointers as other variables once safe to do so

macro_rules! d8 {
    () => {
        "rsi"
    };
}
macro_rules! m {
    () => {
        "rdx"
    };
}

/// Add modulo p_521, z := (x + y) mod p_521, assuming x and y reduced
///
/// Inputs x[9], y[9]; output z[9]
pub(crate) fn bignum_add_p521(z: &mut [u64; 9], x: &[u64; 9], y: &[u64; 9]) {
    // SAFETY: inline assembly. see [crate::low::inline_assembly_safety] for safety info.
    unsafe {
        core::arch::asm!(

        Q!("    endbr64         " ),

        // Save more registers to play with

        Q!("    push            " "rbx"),
        Q!("    push            " "r12"),

        // Force carry-in to get s = [d8;d7;d6;d5;d4;d3;d2;d1;d0] = x + y + 1.
        // We ignore the carry-out, assuming inputs are reduced so there is none.

        Q!("    stc             " ),
        Q!("    mov             " d0!() ", [" x!() "]"),
        Q!("    adc             " d0!() ", [" y!() "]"),
        Q!("    mov             " d1!() ", [" x!() "+ 8]"),
        Q!("    adc             " d1!() ", [" y!() "+ 8]"),
        Q!("    mov             " d2!() ", [" x!() "+ 16]"),
        Q!("    adc             " d2!() ", [" y!() "+ 16]"),
        Q!("    mov             " d3!() ", [" x!() "+ 24]"),
        Q!("    adc             " d3!() ", [" y!() "+ 24]"),
        Q!("    mov             " d4!() ", [" x!() "+ 32]"),
        Q!("    adc             " d4!() ", [" y!() "+ 32]"),
        Q!("    mov             " d5!() ", [" x!() "+ 40]"),
        Q!("    adc             " d5!() ", [" y!() "+ 40]"),
        Q!("    mov             " d6!() ", [" x!() "+ 48]"),
        Q!("    adc             " d6!() ", [" y!() "+ 48]"),
        Q!("    mov             " d7!() ", [" x!() "+ 56]"),
        Q!("    adc             " d7!() ", [" y!() "+ 56]"),
        Q!("    mov             " d8!() ", [" x!() "+ 64]"),
        Q!("    adc             " d8!() ", [" y!() "+ 64]"),

        // Now x + y >= p_521 <=> s = x + y + 1 >= 2^521
        // Make m = 512 * [x + y >= p_521]

        Q!("    mov             " m!() ", 512"),
        Q!("    and             " m!() ", " d8!()),

        // Now if x + y >= p_521, we want (x + y) - p_521 = s - 2^521
        // while otherwise we want x + y = s - 1
        // We use the mask m both as an operand and to generate the dual carry
        // Write back the results as generated

        Q!("    cmp             " m!() ", 512"),

        Q!("    sbb             " d0!() ", 0"),
        Q!("    mov             " "[" z!() "], " d0!()),
        Q!("    sbb             " d1!() ", 0"),
        Q!("    mov             " "[" z!() "+ 8], " d1!()),
        Q!("    sbb             " d2!() ", 0"),
        Q!("    mov             " "[" z!() "+ 16], " d2!()),
        Q!("    sbb             " d3!() ", 0"),
        Q!("    mov             " "[" z!() "+ 24], " d3!()),
        Q!("    sbb             " d4!() ", 0"),
        Q!("    mov             " "[" z!() "+ 32], " d4!()),
        Q!("    sbb             " d5!() ", 0"),
        Q!("    mov             " "[" z!() "+ 40], " d5!()),
        Q!("    sbb             " d6!() ", 0"),
        Q!("    mov             " "[" z!() "+ 48], " d6!()),
        Q!("    sbb             " d7!() ", 0"),
        Q!("    mov             " "[" z!() "+ 56], " d7!()),
        Q!("    sbb             " d8!() ", " m!()),
        Q!("    mov             " "[" z!() "+ 64], " d8!()),

        // Restore registers and return

        Q!("    pop             " "r12"),
        Q!("    pop             " "rbx"),

        inout("rdi") z.as_mut_ptr() => _,
        inout("rsi") x.as_ptr() => _,
        inout("rdx") y.as_ptr() => _,
        // clobbers
        out("r10") _,
        out("r11") _,
        out("r12") _,
        out("r8") _,
        out("r9") _,
        out("rax") _,
        out("rcx") _,
            )
    };
}
