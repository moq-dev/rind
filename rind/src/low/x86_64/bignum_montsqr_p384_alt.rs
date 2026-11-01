// generated source. do not edit.
#![allow(non_upper_case_globals, unused_macros, unused_imports)]
use crate::low::macros::*;

// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

// ----------------------------------------------------------------------------
// Montgomery square, z := (x^2 / 2^384) mod p_384
// Input x[6]; output z[6]
//
//    extern void bignum_montsqr_p384_alt(uint64_t z[static 6],
//                                        const uint64_t x[static 6]);
//
// Does z := (x^2 / 2^384) mod p_384, assuming x^2 <= 2^384 * p_384, which is
// guaranteed in particular if x < p_384 initially (the "intended" case).
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

// Some temp registers for the last correction stage

macro_rules! d {
    () => {
        "rax"
    };
}
macro_rules! u {
    () => {
        "rdx"
    };
}
macro_rules! v {
    () => {
        "r10"
    };
}
macro_rules! w {
    () => {
        "r11"
    };
}

// A zero register, very often

macro_rules! zero {
    () => {
        "rbp"
    };
}
macro_rules! zeroe {
    () => {
        "ebp"
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

// Core one-step "short" Montgomery reduction macro. Takes input in
// [d5;d4;d3;d2;d1;d0] and returns result in [d6;d5;d4;d3;d2;d1],
// adding to the existing [d5;d4;d3;d2;d1] and re-using d0 as a
// temporary internally, as well as rax, rbx and rdx.
// It is OK for d6 and d0 to be the same register (they often are)
//
// We want to add (2^384 - 2^128 - 2^96 + 2^32 - 1) * w
// where w = [d0 + (d0<<32)] mod 2^64
//
//       montreds(d6,d5,d4,d3,d2,d1,d0)

macro_rules! montreds {
    ($d6:expr, $d5:expr, $d4:expr, $d3:expr, $d2:expr, $d1:expr, $d0:expr) => { Q!(
        /* Our correction multiplier is w = [d0 + (d0<<32)] mod 2^64 */
        "mov rbx, " $d0 ";\n"
        "shl rbx, 32;\n"
        "add rbx, " $d0 ";\n"
        /* Construct [rax;rdx;d0;-] = (2^384 - p_384) * w            */
        /* We know the lowest word will cancel so we can re-use d0   */
        /* and rbx as temps.                                         */
        "mov rax, 0xffffffff00000001;\n"
        "mul rbx;\n"
        "mov " $d0 ", rdx;\n"
        "mov rax, 0x00000000ffffffff;\n"
        "mul rbx;\n"
        "add " $d0 ", rax;\n"
        "mov eax, 0;\n"
        "adc rdx, rbx;\n"
        "adc eax, eax;\n"
        /* Now subtract that and add 2^384 * w                       */
        "sub " $d1 ", " $d0 ";\n"
        "sbb " $d2 ", rdx;\n"
        "sbb " $d3 ", rax;\n"
        "sbb " $d4 ", 0;\n"
        "sbb " $d5 ", 0;\n"
        "mov " $d6 ", rbx;\n"
        "sbb " $d6 ", 0"
    )}
}

/// Montgomery square, z := (x^2 / 2^384) mod p_384
///
/// Input x[6]; output z[6]
///
/// Does z := (x^2 / 2^384) mod p_384, assuming x^2 <= 2^384 * p_384, which is
/// guaranteed in particular if x < p_384 initially (the "intended" case).
pub(crate) fn bignum_montsqr_p384_alt(z: &mut [u64; 6], x: &[u64; 6]) {
    // SAFETY: inline assembly. see [crate::low::inline_assembly_safety] for safety info.
    unsafe {
        core::arch::asm!(

        Q!("    endbr64         " ),

        // Save more registers to play with

        Q!("    push            " "rbx"),
        Q!("    push            " "rbp"),
        Q!("    push            " "r12"),
        Q!("    push            " "r13"),
        Q!("    push            " "r14"),
        Q!("    push            " "r15"),

        // Set up an initial window [rcx;r15;...r9] = [34;05;03;01]
        // Note that we are using rcx as the first step past the rotating window

        Q!("    mov             " "rbx, [" x!() "]"),
        Q!("    mov             " "rax, [" x!() "+ 8]"),
        Q!("    mul             " "rbx"),
        Q!("    mov             " "r9, rax"),
        Q!("    mov             " "r10, rdx"),

        Q!("    mov             " "rax, [" x!() "+ 24]"),
        Q!("    mul             " "rbx"),
        Q!("    mov             " "r11, rax"),
        Q!("    mov             " "r12, rdx"),

        Q!("    mov             " "rax, [" x!() "+ 40]"),
        Q!("    mul             " "rbx"),
        Q!("    mov             " "r13, rax"),
        Q!("    mov             " "r14, rdx"),

        Q!("    mov             " "rax, [" x!() "+ 24]"),
        Q!("    mul             " "QWORD PTR [" x!() "+ 32]"),
        Q!("    mov             " "r15, rax"),
        Q!("    mov             " "rcx, rdx"),

        // Chain in the addition of 02 + 12 + 13 + 14 + 15 to that window
        // (no carry-out possible)

        Q!("    mov             " "rbx, [" x!() "+ 16]"),
        mulpadi!("rbp", "r11", "r10", Q!("[" x!() "]")),
        mulpadd!("rbp", "r12", "r11", Q!("[" x!() "+" "8" "]")),
        Q!("    mov             " "rbx, [" x!() "+ 8]"),
        mulpadd!("rbp", "r13", "r12", Q!("[" x!() "+" "24" "]")),
        mulpadd!("rbp", "r14", "r13", Q!("[" x!() "+" "32" "]")),
        mulpade!("rbp", "r15", "r14", Q!("[" x!() "+" "40" "]")),
        Q!("    adc             " "rcx, 0"),

        // Now chain in the 04 + 23 + 24 + 25 + 35 + 45 terms
        // We are running out of registers in our rotating window, so we start
        // using rbx (and hence need care with using mulpadd after this). Thus
        // our result so far is in [rbp;rbx;rcx;r15;...r9]

        Q!("    mov             " "rbx, [" x!() "+ 32]"),
        mulpadi!("rbp", "r13", "r12", Q!("[" x!() "]")),
        Q!("    mov             " "rbx, [" x!() "+ 16]"),
        mulpadd!("rbp", "r14", "r13", Q!("[" x!() "+" "24" "]")),
        mulpadd!("rbp", "r15", "r14", Q!("[" x!() "+" "32" "]")),
        mulpadd!("rbp", "rcx", "r15", Q!("[" x!() "+" "40" "]")),

        Q!("    xor             " "ebx, ebx"),
        Q!("    mov             " "rax, [" x!() "+ 24]"),
        Q!("    mul             " "QWORD PTR [" x!() "+ 40]"),
        Q!("    sub             " "rdx, rbp"),
        Q!("    xor             " "ebp, ebp"),
        Q!("    add             " "rcx, rax"),
        Q!("    adc             " "rbx, rdx"),
        Q!("    adc             " "ebp, ebp"),
        Q!("    mov             " "rax, [" x!() "+ 32]"),
        Q!("    mul             " "QWORD PTR [" x!() "+ 40]"),
        Q!("    add             " "rbx, rax"),
        Q!("    adc             " "rbp, rdx"),

        // Double the window as [r8;rbp;rbx;rcx;r15;...r9]

        Q!("    xor             " "r8d, r8d"),
        Q!("    add             " "r9, r9"),
        Q!("    adc             " "r10, r10"),
        Q!("    adc             " "r11, r11"),
        Q!("    adc             " "r12, r12"),
        Q!("    adc             " "r13, r13"),
        Q!("    adc             " "r14, r14"),
        Q!("    adc             " "r15, r15"),
        Q!("    adc             " "rcx, rcx"),
        Q!("    adc             " "rbx, rbx"),
        Q!("    adc             " "rbp, rbp"),
        Q!("    adc             " "r8d, r8d"),

        // Add the doubled window to the 00 + 11 + 22 + 33 + 44 + 55 terms
        // For one glorious moment the entire squaring result is all in the
        // register file as [rsi;rbp;rbx;rcx;r15;...;r8]
        // (since we've now finished with x we can re-use rsi). But since
        // we are so close to running out of registers, we do a bit of
        // reshuffling and temporary storage in the output buffer.

        Q!("    mov             " "rax, [" x!() "]"),
        Q!("    mul             " "rax"),
        Q!("    mov             " "[" z!() "], r8"),
        Q!("    mov             " "r8, rax"),
        Q!("    mov             " "rax, [" x!() "+ 8]"),
        Q!("    mov             " "[" z!() "+ 8], rbp"),
        Q!("    add             " "r9, rdx"),
        Q!("    sbb             " "rbp, rbp"),

        Q!("    mul             " "rax"),
        Q!("    neg             " "rbp"),
        Q!("    adc             " "r10, rax"),
        Q!("    adc             " "r11, rdx"),
        Q!("    sbb             " "rbp, rbp"),

        Q!("    mov             " "rax, [" x!() "+ 16]"),
        Q!("    mul             " "rax"),
        Q!("    neg             " "rbp"),
        Q!("    adc             " "r12, rax"),
        Q!("    adc             " "r13, rdx"),
        Q!("    sbb             " "rbp, rbp"),

        Q!("    mov             " "rax, [" x!() "+ 24]"),
        Q!("    mul             " "rax"),
        Q!("    neg             " "rbp"),
        Q!("    adc             " "r14, rax"),
        Q!("    adc             " "r15, rdx"),
        Q!("    sbb             " "rbp, rbp"),

        Q!("    mov             " "rax, [" x!() "+ 32]"),
        Q!("    mul             " "rax"),
        Q!("    neg             " "rbp"),
        Q!("    adc             " "rcx, rax"),
        Q!("    adc             " "rbx, rdx"),
        Q!("    sbb             " "rbp, rbp"),

        Q!("    mov             " "rax, [" x!() "+ 40]"),
        Q!("    mul             " "rax"),
        Q!("    neg             " "rbp"),
        Q!("    adc             " "rax, [" z!() "+ 8]"),
        Q!("    adc             " "rdx, [" z!() "]"),
        Q!("    mov             " "rbp, rax"),
        Q!("    mov             " "rsi, rdx"),

        // We need just *one* more register as a temp for the Montgomery steps.
        // Since we are writing to the z buffer anyway, make use of that again
        // to stash rbx.

        Q!("    mov             " "[" z!() "], rbx"),

        // Montgomery reduce the r13,...,r8 window 6 times

        montreds!("r8", "r13", "r12", "r11", "r10", "r9", "r8"),
        montreds!("r9", "r8", "r13", "r12", "r11", "r10", "r9"),
        montreds!("r10", "r9", "r8", "r13", "r12", "r11", "r10"),
        montreds!("r11", "r10", "r9", "r8", "r13", "r12", "r11"),
        montreds!("r12", "r11", "r10", "r9", "r8", "r13", "r12"),
        montreds!("r13", "r12", "r11", "r10", "r9", "r8", "r13"),

        // Now we can safely restore rbx before accumulating

        Q!("    mov             " "rbx, [" z!() "]"),

        Q!("    add             " "r14, r8"),
        Q!("    adc             " "r15, r9"),
        Q!("    adc             " "rcx, r10"),
        Q!("    adc             " "rbx, r11"),
        Q!("    adc             " "rbp, r12"),
        Q!("    adc             " "rsi, r13"),
        Q!("    mov             " "r8d, 0"),
        Q!("    adc             " "r8, r8"),

        // We now have a pre-reduced 7-word form z = [r8; rsi;rbp;rbx;rcx;r15;r14]
        // Next, accumulate in different registers z - p_384, or more precisely
        //
        //   [r8; r13;r12;r11;r10;r9;rax] = z + (2^384 - p_384)

        Q!("    xor             " "r11, r11"),
        Q!("    xor             " "r12, r12"),
        Q!("    xor             " "r13, r13"),
        Q!("    mov             " "rax, 0xffffffff00000001"),
        Q!("    add             " "rax, r14"),
        Q!("    mov             " "r9d, 0x00000000ffffffff"),
        Q!("    adc             " "r9, r15"),
        Q!("    mov             " "r10d, 0x0000000000000001"),
        Q!("    adc             " "r10, rcx"),
        Q!("    adc             " "r11, rbx"),
        Q!("    adc             " "r12, rbp"),
        Q!("    adc             " "r13, rsi"),
        Q!("    adc             " "r8, 0"),

        // ~ZF <=> r12 >= 1 <=> z + (2^384 - p_384) >= 2^384 <=> z >= p_384, which
        // determines whether to use the further reduced argument or the original z.

        Q!("    cmovnz          " "r14, rax"),
        Q!("    cmovnz          " "r15, r9"),
        Q!("    cmovnz          " "rcx, r10"),
        Q!("    cmovnz          " "rbx, r11"),
        Q!("    cmovnz          " "rbp, r12"),
        Q!("    cmovnz          " "rsi, r13"),

        // Write back the result

        Q!("    mov             " "[" z!() "], r14"),
        Q!("    mov             " "[" z!() "+ 8], r15"),
        Q!("    mov             " "[" z!() "+ 16], rcx"),
        Q!("    mov             " "[" z!() "+ 24], rbx"),
        Q!("    mov             " "[" z!() "+ 32], rbp"),
        Q!("    mov             " "[" z!() "+ 40], rsi"),

        // Restore registers and return

        Q!("    pop             " "r15"),
        Q!("    pop             " "r14"),
        Q!("    pop             " "r13"),
        Q!("    pop             " "r12"),
        Q!("    pop             " "rbp"),
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
