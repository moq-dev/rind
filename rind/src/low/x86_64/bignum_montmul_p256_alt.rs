// generated source. do not edit.
#![allow(non_upper_case_globals, unused_macros, unused_imports)]
use crate::low::macros::*;

// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

// ----------------------------------------------------------------------------
// Montgomery multiply, z := (x * y / 2^256) mod p_256
// Inputs x[4], y[4]; output z[4]
//
//    extern void bignum_montmul_p256_alt(uint64_t z[static 4],
//                                        const uint64_t x[static 4],
//                                        const uint64_t y[static 4]);
//
// Does z := (2^{-256} * x * y) mod p_256, assuming that the inputs x and y
// satisfy x * y <= 2^256 * p_256 (in particular this is true if we are in
// the "usual" case x < p_256 and y < p_256).
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

// We move the y argument here so we can use rdx for multipliers

macro_rules! y {
    () => {
        "rcx"
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

/// Montgomery multiply, z := (x * y / 2^256) mod p_256
///
/// Inputs x[4], y[4]; output z[4]
///
/// Does z := (2^{-256} * x * y) mod p_256, assuming that the inputs x and y
/// satisfy x * y <= 2^256 * p_256 (in particular this is true if we are in
/// the "usual" case x < p_256 and y < p_256).
pub(crate) fn bignum_montmul_p256_alt(z: &mut [u64; 4], x: &[u64; 4], y: &[u64; 4]) {
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

        // Copy y into a safe register to start with

        Q!("    mov             " y!() ", rdx"),

        // Do row 0 computation, which is a bit different:
        // set up initial window [r12,r11,r10,r9,r8] = y[0] * x
        // Unlike later, we only need a single carry chain

        Q!("    mov             " "rbx, [" y!() "]"),
        Q!("    mov             " "rax, [" x!() "]"),
        Q!("    mul             " "rbx"),
        Q!("    mov             " "r8, rax"),
        Q!("    mov             " "r9, rdx"),

        Q!("    mov             " "rax, [" x!() "+ 8]"),
        Q!("    mul             " "rbx"),
        Q!("    xor             " "r10d, r10d"),
        Q!("    add             " "r9, rax"),
        Q!("    adc             " "r10, rdx"),

        Q!("    mov             " "rax, [" x!() "+ 16]"),
        Q!("    mul             " "rbx"),
        Q!("    xor             " "r11d, r11d"),
        Q!("    add             " "r10, rax"),
        Q!("    adc             " "r11, rdx"),

        Q!("    mov             " "rax, [" x!() "+ 24]"),
        Q!("    mul             " "rbx"),
        Q!("    xor             " "r12d, r12d"),
        Q!("    add             " "r11, rax"),
        Q!("    adc             " "r12, rdx"),

        // Add row 1

        Q!("    mov             " "rbx, [" y!() "+ 8]"),
        Q!("    xor             " "r13d, r13d"),
        mulpadi!("r14", "r10", "r9", Q!("[" x!() "]")),
        mulpadd!("r14", "r11", "r10", Q!("[" x!() "+" "8" "]")),
        mulpadd!("r14", "r12", "r11", Q!("[" x!() "+" "16" "]")),
        mulpade!("r14", "r13", "r12", Q!("[" x!() "+" "24" "]")),

        // Montgomery reduce windows 0 and 1 together

        Q!("    xor             " "r14d, r14d"),
        Q!("    mov             " "rbx, 0x0000000100000000"),
        mulpadi!("r15", "r10", "r9", "r8"),
        mulpadd!("r15", "r11", "r10", "r9"),
        Q!("    not             " "rbx"),
        Q!("    lea             " "rbx, [rbx + 2]"),
        mulpadd!("r15", "r12", "r11", "r8"),
        mulpade!("r15", "r13", "r12", "r9"),
        Q!("    adc             " "r14, r14"),

        // Add row 2

        Q!("    mov             " "rbx, [" y!() "+ 16]"),
        Q!("    xor             " "r15d, r15d"),
        mulpadi!("r8", "r11", "r10", Q!("[" x!() "]")),
        mulpadd!("r8", "r12", "r11", Q!("[" x!() "+" "8" "]")),
        mulpadd!("r8", "r13", "r12", Q!("[" x!() "+" "16" "]")),
        mulpade!("r8", "r14", "r13", Q!("[" x!() "+" "24" "]")),
        Q!("    adc             " "r15, r15"),

        // Add row 3

        Q!("    mov             " "rbx, [" y!() "+ 24]"),
        Q!("    xor             " "r8d, r8d"),
        mulpadi!("r9", "r12", "r11", Q!("[" x!() "]")),
        mulpadd!("r9", "r13", "r12", Q!("[" x!() "+" "8" "]")),
        mulpadd!("r9", "r14", "r13", Q!("[" x!() "+" "16" "]")),
        mulpade!("r9", "r15", "r14", Q!("[" x!() "+" "24" "]")),
        Q!("    adc             " "r8, r8"),

        // Montgomery reduce windows 2 and 3 together

        Q!("    xor             " "r9d, r9d"),
        Q!("    mov             " "rbx, 0x0000000100000000"),
        mulpadi!("rcx", "r12", "r11", "r10"),
        mulpadd!("rcx", "r13", "r12", "r11"),
        Q!("    not             " "rbx"),
        Q!("    lea             " "rbx, [rbx + 2]"),
        mulpadd!("rcx", "r14", "r13", "r10"),
        mulpade!("rcx", "r15", "r14", "r11"),
        Q!("    adc             " "r8, r9"),

        // We now have a pre-reduced 5-word form [r8; r15;r14;r13;r12]
        // Load [rax;r11;r9;rbx;rcx] = 2^320 - p_256, re-using earlier numbers a bit
        // Do [rax;r11;r9;rbx;rcx] = [r8;r15;r14;r13;r12] + (2^320 - p_256)

        Q!("    mov             " "ecx, 1"),
        Q!("    add             " "rcx, r12"),
        Q!("    dec             " "rbx"),
        Q!("    adc             " "rbx, r13"),
        Q!("    dec             " "r9"),
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

        // Restore registers and return

        Q!("    pop             " "r15"),
        Q!("    pop             " "r14"),
        Q!("    pop             " "r13"),
        Q!("    pop             " "r12"),
        Q!("    pop             " "rbx"),

        inout("rdi") z.as_mut_ptr() => _,
        inout("rsi") x.as_ptr() => _,
        inout("rdx") y.as_ptr() => _,
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
            )
    };
}
