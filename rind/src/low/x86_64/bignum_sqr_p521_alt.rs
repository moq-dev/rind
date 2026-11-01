// generated source. do not edit.
#![allow(non_upper_case_globals, unused_macros, unused_imports)]
use crate::low::macros::*;

// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

// ----------------------------------------------------------------------------
// Square modulo p_521, z := (x^2) mod p_521, assuming x reduced
// Input x[9]; output z[9]
//
//    extern void bignum_sqr_p521_alt(uint64_t z[static 9],
//                                    const uint64_t x[static 9]);
//
// Standard x86-64 ABI: RDI = z, RSI = x
// Microsoft x64 ABI:   RCX = z, RDX = x
// ----------------------------------------------------------------------------

// Input arguments

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

// Macro for the key "multiply and add to (c,h,l)" step

macro_rules! combadd {
    ($c:expr, $h:expr, $l:expr, $numa:expr, $numb:expr) => { Q!(
        "mov rax, " $numa ";\n"
        "mul QWORD PTR " $numb ";\n"
        "add " $l ", rax;\n"
        "adc " $h ", rdx;\n"
        "adc " $c ", 0"
    )}
}

// Set up initial window (c,h,l) = numa * numb

macro_rules! combaddz {
    ($c:expr, $h:expr, $l:expr, $numa:expr, $numb:expr) => { Q!(
        "mov rax, " $numa ";\n"
        "mul QWORD PTR " $numb ";\n"
        "xor " $c ", " $c ";\n"
        "mov " $l ", rax;\n"
        "mov " $h ", rdx"
    )}
}

// Doubling step (c,h,l) = 2 * (c,hh,ll) + (0,h,l)

macro_rules! doubladd {
    ($c:expr, $h:expr, $l:expr, $hh:expr, $ll:expr) => { Q!(
        "add " $ll ", " $ll ";\n"
        "adc " $hh ", " $hh ";\n"
        "adc " $c ", " $c ";\n"
        "add " $l ", " $ll ";\n"
        "adc " $h ", " $hh ";\n"
        "adc " $c ", 0"
    )}
}

// Square term incorporation (c,h,l) += numba^2

macro_rules! combadd1 {
    ($c:expr, $h:expr, $l:expr, $numa:expr) => { Q!(
        "mov rax, " $numa ";\n"
        "mul rax;\n"
        "add " $l ", rax;\n"
        "adc " $h ", rdx;\n"
        "adc " $c ", 0"
    )}
}

// A short form where we don't expect a top carry

macro_rules! combads {
    ($h:expr, $l:expr, $numa:expr) => { Q!(
        "mov rax, " $numa ";\n"
        "mul rax;\n"
        "add " $l ", rax;\n"
        "adc " $h ", rdx"
    )}
}

// A version doubling directly before adding, for single non-square terms

macro_rules! combadd2 {
    ($c:expr, $h:expr, $l:expr, $numa:expr, $numb:expr) => { Q!(
        "mov rax, " $numa ";\n"
        "mul QWORD PTR " $numb ";\n"
        "add rax, rax;\n"
        "adc rdx, rdx;\n"
        "adc " $c ", 0;\n"
        "add " $l ", rax;\n"
        "adc " $h ", rdx;\n"
        "adc " $c ", 0"
    )}
}

/// Square modulo p_521, z := (x^2) mod p_521, assuming x reduced
///
/// Input x[9]; output z[9]
pub(crate) fn bignum_sqr_p521_alt(z: &mut [u64; 9], x: &[u64; 9]) {
    // SAFETY: inline assembly. see [crate::low::inline_assembly_safety] for safety info.
    unsafe {
        core::arch::asm!(

        Q!("    endbr64         " ),

        // Make more registers available and make temporary space on stack

        Q!("    push            " "rbx"),
        Q!("    push            " "r12"),
        Q!("    push            " "r13"),
        Q!("    push            " "r14"),
        Q!("    push            " "r15"),
        Q!("    sub             " "rsp, 72"),

        // Start doing a conventional columnwise squaring,
        // temporarily storing the lower 9 digits on the stack.
        // Start with result term 0

        Q!("    mov             " "rax, [" x!() "]"),
        Q!("    mul             " "rax"),

        Q!("    mov             " "[rsp], rax"),
        Q!("    mov             " "r9, rdx"),
        Q!("    xor             " "r10, r10"),

        // Result term 1

        Q!("    xor             " "r11, r11"),
        combadd2!("r11", "r10", "r9", Q!("[" x!() "]"), Q!("[" x!() "+" "8" "]")),
        Q!("    mov             " "[rsp + 8], r9"),

        // Result term 2

        Q!("    xor             " "r12, r12"),
        combadd1!("r12", "r11", "r10", Q!("[" x!() "+" "8" "]")),
        combadd2!("r12", "r11", "r10", Q!("[" x!() "]"), Q!("[" x!() "+" "16" "]")),
        Q!("    mov             " "[rsp + 16], r10"),

        // Result term 3

        combaddz!("r13", "rcx", "rbx", Q!("[" x!() "]"), Q!("[" x!() "+" "24" "]")),
        combadd!("r13", "rcx", "rbx", Q!("[" x!() "+" "8" "]"), Q!("[" x!() "+" "16" "]")),
        doubladd!("r13", "r12", "r11", "rcx", "rbx"),
        Q!("    mov             " "[rsp + 24], r11"),

        // Result term 4

        combaddz!("r14", "rcx", "rbx", Q!("[" x!() "]"), Q!("[" x!() "+" "32" "]")),
        combadd!("r14", "rcx", "rbx", Q!("[" x!() "+" "8" "]"), Q!("[" x!() "+" "24" "]")),
        doubladd!("r14", "r13", "r12", "rcx", "rbx"),
        combadd1!("r14", "r13", "r12", Q!("[" x!() "+" "16" "]")),
        Q!("    mov             " "[rsp + 32], r12"),

        // Result term 5

        combaddz!("r15", "rcx", "rbx", Q!("[" x!() "]"), Q!("[" x!() "+" "40" "]")),
        combadd!("r15", "rcx", "rbx", Q!("[" x!() "+" "8" "]"), Q!("[" x!() "+" "32" "]")),
        combadd!("r15", "rcx", "rbx", Q!("[" x!() "+" "16" "]"), Q!("[" x!() "+" "24" "]")),
        doubladd!("r15", "r14", "r13", "rcx", "rbx"),
        Q!("    mov             " "[rsp + 40], r13"),

        // Result term 6

        combaddz!("r8", "rcx", "rbx", Q!("[" x!() "]"), Q!("[" x!() "+" "48" "]")),
        combadd!("r8", "rcx", "rbx", Q!("[" x!() "+" "8" "]"), Q!("[" x!() "+" "40" "]")),
        combadd!("r8", "rcx", "rbx", Q!("[" x!() "+" "16" "]"), Q!("[" x!() "+" "32" "]")),
        doubladd!("r8", "r15", "r14", "rcx", "rbx"),
        combadd1!("r8", "r15", "r14", Q!("[" x!() "+" "24" "]")),
        Q!("    mov             " "[rsp + 48], r14"),

        // Result term 7

        combaddz!("r9", "rcx", "rbx", Q!("[" x!() "]"), Q!("[" x!() "+" "56" "]")),
        combadd!("r9", "rcx", "rbx", Q!("[" x!() "+" "8" "]"), Q!("[" x!() "+" "48" "]")),
        combadd!("r9", "rcx", "rbx", Q!("[" x!() "+" "16" "]"), Q!("[" x!() "+" "40" "]")),
        combadd!("r9", "rcx", "rbx", Q!("[" x!() "+" "24" "]"), Q!("[" x!() "+" "32" "]")),
        doubladd!("r9", "r8", "r15", "rcx", "rbx"),
        Q!("    mov             " "[rsp + 56], r15"),

        // Result term 8

        combaddz!("r10", "rcx", "rbx", Q!("[" x!() "]"), Q!("[" x!() "+" "64" "]")),
        combadd!("r10", "rcx", "rbx", Q!("[" x!() "+" "8" "]"), Q!("[" x!() "+" "56" "]")),
        combadd!("r10", "rcx", "rbx", Q!("[" x!() "+" "16" "]"), Q!("[" x!() "+" "48" "]")),
        combadd!("r10", "rcx", "rbx", Q!("[" x!() "+" "24" "]"), Q!("[" x!() "+" "40" "]")),
        doubladd!("r10", "r9", "r8", "rcx", "rbx"),
        combadd1!("r10", "r9", "r8", Q!("[" x!() "+" "32" "]")),
        Q!("    mov             " "[rsp + 64], r8"),

        // We now stop writing back and keep remaining results in a register window.
        // Continue with result term 9

        combaddz!("r11", "rcx", "rbx", Q!("[" x!() "+" "8" "]"), Q!("[" x!() "+" "64" "]")),
        combadd!("r11", "rcx", "rbx", Q!("[" x!() "+" "16" "]"), Q!("[" x!() "+" "56" "]")),
        combadd!("r11", "rcx", "rbx", Q!("[" x!() "+" "24" "]"), Q!("[" x!() "+" "48" "]")),
        combadd!("r11", "rcx", "rbx", Q!("[" x!() "+" "32" "]"), Q!("[" x!() "+" "40" "]")),
        doubladd!("r11", "r10", "r9", "rcx", "rbx"),

        // Result term 10

        combaddz!("r12", "rcx", "rbx", Q!("[" x!() "+" "16" "]"), Q!("[" x!() "+" "64" "]")),
        combadd!("r12", "rcx", "rbx", Q!("[" x!() "+" "24" "]"), Q!("[" x!() "+" "56" "]")),
        combadd!("r12", "rcx", "rbx", Q!("[" x!() "+" "32" "]"), Q!("[" x!() "+" "48" "]")),
        doubladd!("r12", "r11", "r10", "rcx", "rbx"),
        combadd1!("r12", "r11", "r10", Q!("[" x!() "+" "40" "]")),

        // Result term 11

        combaddz!("r13", "rcx", "rbx", Q!("[" x!() "+" "24" "]"), Q!("[" x!() "+" "64" "]")),
        combadd!("r13", "rcx", "rbx", Q!("[" x!() "+" "32" "]"), Q!("[" x!() "+" "56" "]")),
        combadd!("r13", "rcx", "rbx", Q!("[" x!() "+" "40" "]"), Q!("[" x!() "+" "48" "]")),
        doubladd!("r13", "r12", "r11", "rcx", "rbx"),

        // Result term 12

        combaddz!("r14", "rcx", "rbx", Q!("[" x!() "+" "32" "]"), Q!("[" x!() "+" "64" "]")),
        combadd!("r14", "rcx", "rbx", Q!("[" x!() "+" "40" "]"), Q!("[" x!() "+" "56" "]")),
        doubladd!("r14", "r13", "r12", "rcx", "rbx"),
        combadd1!("r14", "r13", "r12", Q!("[" x!() "+" "48" "]")),

        // Result term 13

        combaddz!("r15", "rcx", "rbx", Q!("[" x!() "+" "40" "]"), Q!("[" x!() "+" "64" "]")),
        combadd!("r15", "rcx", "rbx", Q!("[" x!() "+" "48" "]"), Q!("[" x!() "+" "56" "]")),
        doubladd!("r15", "r14", "r13", "rcx", "rbx"),

        // Result term 14

        Q!("    xor             " "r8, r8"),
        combadd1!("r8", "r15", "r14", Q!("[" x!() "+" "56" "]")),
        combadd2!("r8", "r15", "r14", Q!("[" x!() "+" "48" "]"), Q!("[" x!() "+" "64" "]")),

        // Result term 15

        Q!("    mov             " "rax, [" x!() "+ 56]"),
        Q!("    mul             " "QWORD PTR [" x!() "+ 64]"),
        Q!("    add             " "rax, rax"),
        Q!("    adc             " "rdx, rdx"),
        Q!("    add             " "r15, rax"),
        Q!("    adc             " "r8, rdx"),

        // Result term 16

        Q!("    mov             " "rax, [" x!() "+ 64]"),
        Q!("    imul            " "rax, rax"),
        Q!("    add             " "rax, r8"),

        // Now the upper portion is [rax;r15;r14;r13;r12;r11;r10;r9;[rsp+64]].
        // Rotate the upper portion right 9 bits since 2^512 == 2^-9 (mod p_521)
        // Let rotated result rdx,r15,r14,...,r8 be h (high) and rsp[0..7] be l (low)

        Q!("    mov             " "r8, [rsp + 64]"),
        Q!("    mov             " "rdx, r8"),
        Q!("    and             " "rdx, 0x1FF"),
        Q!("    shrd            " "r8, r9, 9"),
        Q!("    shrd            " "r9, r10, 9"),
        Q!("    shrd            " "r10, r11, 9"),
        Q!("    shrd            " "r11, r12, 9"),
        Q!("    shrd            " "r12, r13, 9"),
        Q!("    shrd            " "r13, r14, 9"),
        Q!("    shrd            " "r14, r15, 9"),
        Q!("    shrd            " "r15, rax, 9"),
        Q!("    shr             " "rax, 9"),
        Q!("    add             " "rdx, rax"),

        // Force carry-in then add to get s = h + l + 1
        // but actually add all 1s in the top 53 bits to get simple carry out

        Q!("    stc             " ),
        Q!("    adc             " "r8, [rsp]"),
        Q!("    adc             " "r9, [rsp + 8]"),
        Q!("    adc             " "r10, [rsp + 16]"),
        Q!("    adc             " "r11, [rsp + 24]"),
        Q!("    adc             " "r12, [rsp + 32]"),
        Q!("    adc             " "r13, [rsp + 40]"),
        Q!("    adc             " "r14, [rsp + 48]"),
        Q!("    adc             " "r15, [rsp + 56]"),
        Q!("    adc             " "rdx, ~ 0x1FF"),

        // Now CF is set <=> h + l + 1 >= 2^521 <=> h + l >= p_521,
        // in which case the lower 521 bits are already right. Otherwise if
        // CF is clear, we want to subtract 1. Hence subtract the complement
        // of the carry flag then mask the top word, which scrubs the
        // padding in either case. Write digits back as they are created.

        Q!("    cmc             " ),
        Q!("    sbb             " "r8, 0"),
        Q!("    mov             " "[" z!() "], r8"),
        Q!("    sbb             " "r9, 0"),
        Q!("    mov             " "[" z!() "+ 8], r9"),
        Q!("    sbb             " "r10, 0"),
        Q!("    mov             " "[" z!() "+ 16], r10"),
        Q!("    sbb             " "r11, 0"),
        Q!("    mov             " "[" z!() "+ 24], r11"),
        Q!("    sbb             " "r12, 0"),
        Q!("    mov             " "[" z!() "+ 32], r12"),
        Q!("    sbb             " "r13, 0"),
        Q!("    mov             " "[" z!() "+ 40], r13"),
        Q!("    sbb             " "r14, 0"),
        Q!("    mov             " "[" z!() "+ 48], r14"),
        Q!("    sbb             " "r15, 0"),
        Q!("    mov             " "[" z!() "+ 56], r15"),
        Q!("    sbb             " "rdx, 0"),
        Q!("    and             " "rdx, 0x1FF"),
        Q!("    mov             " "[" z!() "+ 64], rdx"),

        // Restore registers and return

        Q!("    add             " "rsp, 72"),
        Q!("    pop             " "r15"),
        Q!("    pop             " "r14"),
        Q!("    pop             " "r13"),
        Q!("    pop             " "r12"),
        Q!("    pop             " "rbx"),
        inout("rdi") z.as_mut_ptr() => _,
        inout("rsi") x.as_ptr() => _,
        // clobbers
        out("r10") _,
        out("r11") _,
        out("r12") _,
        out("r13") _,
        out("r14") _,
        out("r15") _,
        out("r8") _,
        out("r9") _,
        out("rax") _,
        out("rcx") _,
        out("rdx") _,
            )
    };
}
