// generated source. do not edit.
#![allow(non_upper_case_globals, unused_macros, unused_imports)]
use crate::low::macros::*;

// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

// ----------------------------------------------------------------------------
// Reduce modulo group order, z := x mod n_521
// Input x[9]; output z[9]
//
//    extern void bignum_mod_n521_9_alt(uint64_t z[static 9],
//                                      const uint64_t x[static 9]);
//
// Reduction is modulo the group order of the NIST curve P-521.
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

macro_rules! q {
    () => {
        "rcx"
    };
}
macro_rules! a {
    () => {
        "rax"
    };
}
macro_rules! d {
    () => {
        "rdx"
    };
}

macro_rules! c {
    () => {
        "rcx"
    };
}

macro_rules! n0 {
    () => {
        "r8"
    };
}
macro_rules! n1 {
    () => {
        "r9"
    };
}
macro_rules! n2 {
    () => {
        "r10"
    };
}
macro_rules! n3 {
    () => {
        "r11"
    };
}

macro_rules! ashort {
    () => {
        "eax"
    };
}
macro_rules! cshort {
    () => {
        "ecx"
    };
}
macro_rules! qshort {
    () => {
        "edx"
    };
}

/// Reduce modulo group order, z := x mod n_521
///
/// Input x[9]; output z[9]
///
/// Reduction is modulo the group order of the NIST curve P-521.
pub(crate) fn bignum_mod_n521_alt(z: &mut [u64; 9], x: &[u64; 9]) {
    // SAFETY: inline assembly. see [crate::low::inline_assembly_safety] for safety info.
    unsafe {
        core::arch::asm!(

        Q!("    endbr64         " ),

        // Load the top digit, putting a bit-stuffed version in output buffer.
        // The initial quotient estimate is q = h + 1 where x = 2^521 * h + t
        // The last add also clears the CF and OF flags ready for the carry chain.

        Q!("    mov             " q!() ", [" x!() "+ 64]"),
        Q!("    mov             " a!() ", ~ 0x1FF"),
        Q!("    or              " a!() ", " q!()),
        Q!("    mov             " "[" z!() "+ 64], " a!()),
        Q!("    shr             " q!() ", 9"),
        Q!("    add             " q!() ", 1"),

        // Now load other digits and form r = x - q * n_521 = (q * r_521 + t) - 2^521,
        // which is stored in the output buffer. Thanks to the bit-stuffing at the
        // start, we get r' = (q * r_521 + t) + (2^576 - 2^521) = r + 2^576 as the
        // computed result including the top carry. Hence CF <=> r >= 0, while
        // r' == r (mod 2^521) because things below bit 521 are uncorrupted. We
        // keep the top word in the register c since we at least have that one free.

        Q!("    mov             " "rax, 0x449048e16ec79bf7"),
        Q!("    mul             " q!()),
        Q!("    mov             " n0!() ", rax"),
        Q!("    mov             " n1!() ", rdx"),

        Q!("    mov             " "rax, 0xc44a36477663b851"),
        Q!("    mul             " q!()),
        Q!("    xor             " n2!() ", " n2!()),
        Q!("    add             " n1!() ", rax"),
        Q!("    adc             " n2!() ", rdx"),

        Q!("    mov             " "rax, 0x8033feb708f65a2f"),
        Q!("    mul             " q!()),
        Q!("    xor             " n3!() ", " n3!()),
        Q!("    add             " n2!() ", rax"),
        Q!("    adc             " n3!() ", rdx"),

        Q!("    mov             " "rax, 0xae79787c40d06994"),
        Q!("    mul             " q!()),
        Q!("    imul            " q!() ", 5"),
        Q!("    add             " n3!() ", rax"),
        Q!("    adc             " q!() ", rdx"),
        Q!("    sbb             " "rdx, rdx"),
        Q!("    neg             " "rdx"),

        // [rdx;q;n3;n2;n1;n0] = q * r_521

        Q!("    xor             " "eax, eax"),
        Q!("    add             " n0!() ", [" x!() "]"),
        Q!("    mov             " "[" z!() "], " n0!()),
        Q!("    adc             " n1!() ", [" x!() "+ 8]"),
        Q!("    mov             " "[" z!() "+ 8], " n1!()),
        Q!("    adc             " n2!() ", [" x!() "+ 16]"),
        Q!("    mov             " "[" z!() "+ 16], " n2!()),
        Q!("    adc             " n3!() ", [" x!() "+ 24]"),
        Q!("    mov             " "[" z!() "+ 24], " n3!()),
        Q!("    adc             " q!() ", [" x!() "+ 32]"),
        Q!("    mov             " "[" z!() "+ 32], " q!()),
        Q!("    adc             " "rdx, [" x!() "+ 40]"),
        Q!("    mov             " "[" z!() "+ 40], rdx"),
        Q!("    mov             " d!() ", [" x!() "+ 48]"),
        Q!("    adc             " d!() ", rax"),
        Q!("    mov             " "[" z!() "+ 48], " d!()),
        Q!("    mov             " d!() ", [" x!() "+ 56]"),
        Q!("    adc             " d!() ", rax"),
        Q!("    mov             " "[" z!() "+ 56], " d!()),
        Q!("    mov             " c!() ", [" z!() "+ 64]"),
        Q!("    adc             " c!() ", rax"),

        // We already know r < n_521, but if it actually went negative then
        // we need to add back n_521 again. Use d as a bitmask for r < n_521,
        // and just subtract r_521 and mask rather than literally adding 2^521.
        // This also gets rid of the bit-stuffing above.

        Q!("    cmc             " ),
        Q!("    sbb             " d!() ", " d!()),

        Q!("    mov             " n0!() ", 0x449048e16ec79bf7"),
        Q!("    and             " n0!() ", " d!()),
        Q!("    mov             " n1!() ", 0xc44a36477663b851"),
        Q!("    and             " n1!() ", " d!()),
        Q!("    mov             " n2!() ", 0x8033feb708f65a2f"),
        Q!("    and             " n2!() ", " d!()),
        Q!("    mov             " n3!() ", 0xae79787c40d06994"),
        Q!("    and             " n3!() ", " d!()),
        Q!("    and             " d!() ", 5"),

        Q!("    sub             " "[" z!() "], " n0!()),
        Q!("    sbb             " "[" z!() "+ 8], " n1!()),
        Q!("    sbb             " "[" z!() "+ 16], " n2!()),
        Q!("    sbb             " "[" z!() "+ 24], " n3!()),
        Q!("    sbb             " "[" z!() "+ 32], " d!()),
        Q!("    sbb             " "[" z!() "+ 40], rax"),
        Q!("    sbb             " "[" z!() "+ 48], rax"),
        Q!("    sbb             " "[" z!() "+ 56], rax"),
        Q!("    sbb             " cshort!() ", " ashort!()),
        Q!("    and             " cshort!() ", 0x1FF"),
        Q!("    mov             " "[" z!() "+ 64], " c!()),

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
