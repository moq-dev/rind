// generated source. do not edit.
#![allow(non_upper_case_globals, unused_macros, unused_imports)]
use crate::low::macros::*;

// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

// ----------------------------------------------------------------------------
// Montgomery square, z := (x^2 / 2^256) mod p_256
// Input x[4]; output z[4]
//
//    extern void bignum_montsqr_p256_alt(uint64_t z[static 4],
//                                        const uint64_t x[static 4]);
//
// Does z := (x^2 / 2^256) mod p_256, assuming x^2 <= 2^256 * p_256, which is
// guaranteed in particular if x < p_256 initially (the "intended" case).
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

// Add rbx * m into a register-pair (high,low) maintaining consistent
// carry-catching with carry (negated, as bitmask) and using rax and rdx
// as temporaries

macro_rules! mulpadd {
    ($carry:expr, $high:expr, $low:expr, $m:expr) => { Q!(
        "mov rax, " $m ";\n"
        "mul rbx;\n"
        "sub rdx, " $carry ";\n"
        "add " $low ", rax;\n"
        "adc " $high ", rdx;\n"
        "sbb " $carry ", " $carry
    )}
}

// Initial version assuming no carry-in

macro_rules! mulpadi {
    ($carry:expr, $high:expr, $low:expr, $m:expr) => { Q!(
        "mov rax, " $m ";\n"
        "mul rbx;\n"
        "add " $low ", rax;\n"
        "adc " $high ", rdx;\n"
        "sbb " $carry ", " $carry
    )}
}

// End version not catching the top carry-out

macro_rules! mulpade {
    ($carry:expr, $high:expr, $low:expr, $m:expr) => { Q!(
        "mov rax, " $m ";\n"
        "mul rbx;\n"
        "sub rdx, " $carry ";\n"
        "add " $low ", rax;\n"
        "adc " $high ", rdx"
    )}
}

/// Montgomery square, z := (x^2 / 2^256) mod p_256
///
/// Input x[4]; output z[4]
///
/// Does z := (x^2 / 2^256) mod p_256, assuming x^2 <= 2^256 * p_256, which is
/// guaranteed in particular if x < p_256 initially (the "intended" case).
pub(crate) fn bignum_montsqr_p256_alt(z: &mut [u64; 4], x: &[u64; 4]) {
    // SAFETY: inline assembly. see [crate::low::inline_assembly_safety] for safety info.
    unsafe {
        core::arch::asm!(

        Q!("    endbr64         " ),

        // Save more registers to play with

        Q!("    push            " "rbx"),
        Q!("    push            " "r12"),
        Q!("    push            " "r13"),
        Q!("    push            " "r14"),
        Q!("    push            " "r15"),

        // Compute [r15;r8] = [00] which we use later, but mainly
        // set up an initial window [r14;...;r9] = [23;03;01]

        Q!("    mov             " "rax, [" x!() "]"),
        Q!("    mov             " "rbx, rax"),
        Q!("    mul             " "rax"),
        Q!("    mov             " "r8, rax"),
        Q!("    mov             " "r15, rdx"),
        Q!("    mov             " "rax, [" x!() "+ 8]"),
        Q!("    mul             " "rbx"),
        Q!("    mov             " "r9, rax"),
        Q!("    mov             " "r10, rdx"),
        Q!("    mov             " "rax, [" x!() "+ 24]"),
        Q!("    mov             " "r13, rax"),
        Q!("    mul             " "rbx"),
        Q!("    mov             " "r11, rax"),
        Q!("    mov             " "r12, rdx"),
        Q!("    mov             " "rax, [" x!() "+ 16]"),
        Q!("    mov             " "rbx, rax"),
        Q!("    mul             " "r13"),
        Q!("    mov             " "r13, rax"),
        Q!("    mov             " "r14, rdx"),

        // Chain in the addition of 02 + 12 + 13 to that window (no carry-out possible)
        // This gives all the "heterogeneous" terms of the squaring ready to double

        mulpadi!("rcx", "r11", "r10", Q!("[" x!() "]")),
        mulpadd!("rcx", "r12", "r11", Q!("[" x!() "+" "8" "]")),
        Q!("    mov             " "rbx, [" x!() "+ 24]"),
        mulpade!("rcx", "r13", "r12", Q!("[" x!() "+" "8" "]")),
        Q!("    adc             " "r14, 0"),

        // Double the window [r14;...;r9], catching top carry in rcx

        Q!("    xor             " "ecx, ecx"),
        Q!("    add             " "r9, r9"),
        Q!("    adc             " "r10, r10"),
        Q!("    adc             " "r11, r11"),
        Q!("    adc             " "r12, r12"),
        Q!("    adc             " "r13, r13"),
        Q!("    adc             " "r14, r14"),
        Q!("    adc             " "rcx, rcx"),

        // Add to the 00 + 11 + 22 + 33 terms

        Q!("    mov             " "rax, [" x!() "+ 8]"),
        Q!("    mul             " "rax"),
        Q!("    add             " "r9, r15"),
        Q!("    adc             " "r10, rax"),
        Q!("    adc             " "r11, rdx"),
        Q!("    sbb             " "r15, r15"),
        Q!("    mov             " "rax, [" x!() "+ 16]"),
        Q!("    mul             " "rax"),
        Q!("    neg             " "r15"),
        Q!("    adc             " "r12, rax"),
        Q!("    adc             " "r13, rdx"),
        Q!("    sbb             " "r15, r15"),
        Q!("    mov             " "rax, [" x!() "+ 24]"),
        Q!("    mul             " "rax"),
        Q!("    neg             " "r15"),
        Q!("    adc             " "r14, rax"),
        Q!("    adc             " "rdx, rcx"),
        Q!("    mov             " "r15, rdx"),

        // First two waves of Montgomery reduction, now re-using r8 for top carry

        Q!("    mov             " "rbx, 0x0000000100000000"),
        mulpadi!("rcx", "r10", "r9", "r8"),
        mulpadd!("rcx", "r11", "r10", "r9"),
        Q!("    not             " "rbx"),
        Q!("    lea             " "rbx, [rbx + 2]"),
        mulpadd!("rcx", "r12", "r11", "r8"),
        Q!("    xor             " "r8d, r8d"),
        mulpade!("rcx", "r13", "r12", "r9"),
        Q!("    adc             " "r14, r8"),
        Q!("    adc             " "r15, r8"),
        Q!("    adc             " "r8, r8"),

        // Now two more steps of Montgomery reduction, again with r8 = top carry

        Q!("    mov             " "rbx, 0x0000000100000000"),
        mulpadi!("rcx", "r12", "r11", "r10"),
        mulpadd!("rcx", "r13", "r12", "r11"),
        Q!("    not             " "rbx"),
        Q!("    lea             " "rbx, [rbx + 2]"),
        mulpadd!("rcx", "r14", "r13", "r10"),
        Q!("    xor             " "r9d, r9d"),
        mulpade!("rcx", "r15", "r14", "r11"),
        Q!("    adc             " "r8, r9"),

        // Load [rax;r11;r9;rbx;rcx] = 2^320 - p_256, re-using earlier numbers a bit
        // Do [rax;r11;r9;rbx;rcx] = [r8;r15;r14;r13;r12] + (2^320 - p_256)

        Q!("    mov             " "ecx, 1"),
        Q!("    add             " "rcx, r12"),
        Q!("    lea             " "rbx, [rbx -1]"),
        Q!("    adc             " "rbx, r13"),
        Q!("    lea             " "r9, [r9 -1]"),
        Q!("    mov             " "rax, r9"),
        Q!("    adc             " "r9, r14"),
        Q!("    mov             " "r11d, 0x00000000fffffffe"),
        Q!("    adc             " "r11, r15"),
        Q!("    adc             " "rax, r8"),

        // Now carry is set if r + (2^320 - p_256) >= 2^320, i.e. r >= p_256
        // where r is the pre-reduced form. So conditionally select the
        // output accordingly.

        Q!("    cmovc           " "r12, rcx"),
        Q!("    cmovc           " "r13, rbx"),
        Q!("    cmovc           " "r14, r9"),
        Q!("    cmovc           " "r15, r11"),

        // Write back reduced value

        Q!("    mov             " "[" z!() "], r12"),
        Q!("    mov             " "[" z!() "+ 8], r13"),
        Q!("    mov             " "[" z!() "+ 16], r14"),
        Q!("    mov             " "[" z!() "+ 24], r15"),

        // Restore saved registers and return

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
