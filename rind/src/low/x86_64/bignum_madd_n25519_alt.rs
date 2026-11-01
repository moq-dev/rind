// generated source. do not edit.
#![allow(non_upper_case_globals, unused_macros, unused_imports)]
use crate::low::macros::*;

// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

// ----------------------------------------------------------------------------
// Multiply-add modulo the order of the curve25519/edwards25519 basepoint
// Inputs x[4], y[4], c[4]; output z[4]
//
//    extern void bignum_madd_n25519_alt(uint64_t z[static 4],
//                                       const uint64_t x[static 4],
//                                       const uint64_t y[static 4],
//                                       const uint64_t c[static 4]);
//
// Performs z := (x * y + c) mod n_25519, where the modulus is
// n_25519 = 2^252 + 27742317777372353535851937790883648493, the
// order of the curve25519/edwards25519 basepoint. The result z
// and the inputs x, y and c are all 4 digits (256 bits).
//
// Standard x86-64 ABI: RDI = z, RSI = x, RDX = y, RCX = c
// Microsoft x64 ABI:   RCX = z, RDX = x, R8 = y, R9 = c
// ----------------------------------------------------------------------------

// Single round of modular reduction mod_n25519, mapping
// [m4;m3;m2;m1;m0] = m to [m3;m2;m1;m0] = m mod n_25519,
// *assuming* the input m < 2^64 * n_25519. This is very
// close to the loop body of the bignum_mod_n25519 function.

macro_rules! reduce {
    ($m4:expr, $m3:expr, $m2:expr, $m1:expr, $m0:expr) => { Q!(
        "mov rbx, " $m4 ";\n"
        "shld rbx, " $m3 ", 0x4;\n"
        "shr " $m4 ", 0x3c;\n"
        "sub rbx, " $m4 ";\n"
        "shl " $m3 ", 0x4;\n"
        "shrd " $m3 ", " $m4 ", 0x4;\n"
        "movabs rax, 0x5812631a5cf5d3ed;\n"
        "mul rbx;\n"
        "mov rbp, rax;\n"
        "mov rcx, rdx;\n"
        "movabs rax, 0x14def9dea2f79cd6;\n"
        "mul rbx;\n"
        "add rcx, rax;\n"
        "adc rdx, 0x0;\n"
        "sub " $m0 ", rbp;\n"
        "sbb " $m1 ", rcx;\n"
        "sbb " $m2 ", rdx;\n"
        "sbb " $m3 ", 0x0;\n"
        "sbb rbx, rbx;\n"
        "movabs rax, 0x5812631a5cf5d3ed;\n"
        "and rax, rbx;\n"
        "movabs rdx, 0x14def9dea2f79cd6;\n"
        "and rdx, rbx;\n"
        "movabs rbx, 0x1000000000000000;\n"
        "and rbx, rax;\n"
        "add " $m0 ", rax;\n"
        "adc " $m1 ", rdx;\n"
        "adc " $m2 ", 0x0;\n"
        "adc " $m3 ", rbx"
    )}
}

// Special case of "reduce" with m4 = 0. As well as not using m4,
// the quotient selection is slightly simpler, just floor(m/2^252)
// versus min (floor(m/2^252)) (2^63-1).

macro_rules! reduce0 {
    ($m3:expr, $m2:expr, $m1:expr, $m0:expr) => { Q!(
        "mov rbx, " $m3 ";\n"
        "shr rbx, 60;\n"
        "shl " $m3 ", 4;\n"
        "shr " $m3 ", 4;\n"
        "movabs rax, 0x5812631a5cf5d3ed;\n"
        "mul rbx;\n"
        "mov rbp, rax;\n"
        "mov rcx, rdx;\n"
        "movabs rax, 0x14def9dea2f79cd6;\n"
        "mul rbx;\n"
        "add rcx, rax;\n"
        "adc rdx, 0x0;\n"
        "sub " $m0 ", rbp;\n"
        "sbb " $m1 ", rcx;\n"
        "sbb " $m2 ", rdx;\n"
        "sbb " $m3 ", 0x0;\n"
        "sbb rbx, rbx;\n"
        "movabs rax, 0x5812631a5cf5d3ed;\n"
        "and rax, rbx;\n"
        "movabs rdx, 0x14def9dea2f79cd6;\n"
        "and rdx, rbx;\n"
        "movabs rbx, 0x1000000000000000;\n"
        "and rbx, rax;\n"
        "add " $m0 ", rax;\n"
        "adc " $m1 ", rdx;\n"
        "adc " $m2 ", 0x0;\n"
        "adc " $m3 ", rbx"
    )}
}

/// Multiply-add modulo the order of the curve25519/edwards25519 basepoint
///
/// Inputs x[4], y[4], c[4]; output z[4]
///
/// Performs z := (x * y + c) mod n_25519, where the modulus is
/// n_25519 = 2^252 + 27742317777372353535851937790883648493, the
/// order of the curve25519/edwards25519 basepoint. The result z
/// and the inputs x, y and c are all 4 digits (256 bits).
pub(crate) fn bignum_madd_n25519_alt(z: &mut [u64; 4], x: &[u64; 4], y: &[u64; 4], c: &[u64; 4]) {
    // SAFETY: inline assembly. see [crate::low::inline_assembly_safety] for safety info.
    unsafe {
        core::arch::asm!(

        Q!("    endbr64         " ),

        // Save some additional registers for use

        Q!("    push            " "rbx"),
        Q!("    push            " "rbp"),
        Q!("    push            " "r12"),
        Q!("    push            " "r13"),
        Q!("    push            " "r14"),
        Q!("    push            " "r15"),

        // First compute [r15;r14;r13;r12;r11;r10;r9;r8] = x * y + c. This inserts
        // some addition terms for c into a core Comba multiplier similar to
        // the start of bignum_mul_p256k1_alt.

        Q!("    mov             " "rbp, rdx"),
        Q!("    mov             " "rax, [rsi]"),
        Q!("    mul             " "QWORD PTR [rbp]"),
        Q!("    add             " "rax, [rcx]"),
        Q!("    adc             " "rdx, 0"),
        Q!("    mov             " "r8, rax"),
        Q!("    mov             " "r9, rdx"),
        Q!("    xor             " "r10, r10"),
        Q!("    xor             " "r11, r11"),
        Q!("    mov             " "rax, [rsi]"),
        Q!("    mul             " "QWORD PTR [rbp + 0x8]"),
        Q!("    add             " "rax, [rcx + 8]"),
        Q!("    adc             " "rdx, 0"),
        Q!("    add             " "r9, rax"),
        Q!("    adc             " "r10, rdx"),
        Q!("    mov             " "rax, [rsi + 0x8]"),
        Q!("    mul             " "QWORD PTR [rbp]"),
        Q!("    add             " "r9, rax"),
        Q!("    adc             " "r10, rdx"),
        Q!("    adc             " "r11, 0x0"),
        Q!("    xor             " "r12, r12"),
        Q!("    mov             " "rax, [rsi]"),
        Q!("    mul             " "QWORD PTR [rbp + 0x10]"),
        Q!("    add             " "rax, [rcx + 16]"),
        Q!("    adc             " "rdx, 0"),
        Q!("    add             " "r10, rax"),
        Q!("    adc             " "r11, rdx"),
        Q!("    adc             " "r12, r12"),
        Q!("    mov             " "rax, [rsi + 0x8]"),
        Q!("    mul             " "QWORD PTR [rbp + 0x8]"),
        Q!("    add             " "r10, rax"),
        Q!("    adc             " "r11, rdx"),
        Q!("    adc             " "r12, 0x0"),
        Q!("    mov             " "rax, [rsi + 0x10]"),
        Q!("    mul             " "QWORD PTR [rbp]"),
        Q!("    add             " "r10, rax"),
        Q!("    adc             " "r11, rdx"),
        Q!("    adc             " "r12, 0x0"),
        Q!("    xor             " "r13, r13"),
        Q!("    mov             " "rax, [rsi]"),
        Q!("    mul             " "QWORD PTR [rbp + 0x18]"),
        Q!("    add             " "rax, [rcx + 24]"),
        Q!("    adc             " "rdx, 0"),
        Q!("    add             " "r11, rax"),
        Q!("    adc             " "r12, rdx"),
        Q!("    adc             " "r13, r13"),
        Q!("    mov             " "rax, [rsi + 0x8]"),
        Q!("    mul             " "QWORD PTR [rbp + 0x10]"),
        Q!("    add             " "r11, rax"),
        Q!("    adc             " "r12, rdx"),
        Q!("    adc             " "r13, 0x0"),
        Q!("    mov             " "rax, [rsi + 0x10]"),
        Q!("    mul             " "QWORD PTR [rbp + 0x8]"),
        Q!("    add             " "r11, rax"),
        Q!("    adc             " "r12, rdx"),
        Q!("    adc             " "r13, 0x0"),
        Q!("    mov             " "rax, [rsi + 0x18]"),
        Q!("    mul             " "QWORD PTR [rbp]"),
        Q!("    add             " "r11, rax"),
        Q!("    adc             " "r12, rdx"),
        Q!("    adc             " "r13, 0x0"),
        Q!("    xor             " "r14, r14"),
        Q!("    mov             " "rax, [rsi + 0x8]"),
        Q!("    mul             " "QWORD PTR [rbp + 0x18]"),
        Q!("    add             " "r12, rax"),
        Q!("    adc             " "r13, rdx"),
        Q!("    adc             " "r14, r14"),
        Q!("    mov             " "rax, [rsi + 0x10]"),
        Q!("    mul             " "QWORD PTR [rbp + 0x10]"),
        Q!("    add             " "r12, rax"),
        Q!("    adc             " "r13, rdx"),
        Q!("    adc             " "r14, 0x0"),
        Q!("    mov             " "rax, [rsi + 0x18]"),
        Q!("    mul             " "QWORD PTR [rbp + 0x8]"),
        Q!("    add             " "r12, rax"),
        Q!("    adc             " "r13, rdx"),
        Q!("    adc             " "r14, 0x0"),
        Q!("    xor             " "r15, r15"),
        Q!("    mov             " "rax, [rsi + 0x10]"),
        Q!("    mul             " "QWORD PTR [rbp + 0x18]"),
        Q!("    add             " "r13, rax"),
        Q!("    adc             " "r14, rdx"),
        Q!("    adc             " "r15, r15"),
        Q!("    mov             " "rax, [rsi + 0x18]"),
        Q!("    mul             " "QWORD PTR [rbp + 0x10]"),
        Q!("    add             " "r13, rax"),
        Q!("    adc             " "r14, rdx"),
        Q!("    adc             " "r15, 0x0"),
        Q!("    mov             " "rax, [rsi + 0x18]"),
        Q!("    mul             " "QWORD PTR [rbp + 0x18]"),
        Q!("    add             " "r14, rax"),
        Q!("    adc             " "r15, rdx"),

        // Now do the modular reduction and write back

        reduce0!("r15", "r14", "r13", "r12"),
        reduce!("r15", "r14", "r13", "r12", "r11"),
        reduce!("r14", "r13", "r12", "r11", "r10"),
        reduce!("r13", "r12", "r11", "r10", "r9"),
        reduce!("r12", "r11", "r10", "r9", "r8"),

        Q!("    mov             " "[rdi], r8"),
        Q!("    mov             " "[rdi + 8], r9"),
        Q!("    mov             " "[rdi + 16], r10"),
        Q!("    mov             " "[rdi + 24], r11"),

        // Restore registers and return

        Q!("    pop             " "r15"),
        Q!("    pop             " "r14"),
        Q!("    pop             " "r13"),
        Q!("    pop             " "r12"),
        Q!("    pop             " "rbp"),
        Q!("    pop             " "rbx"),

        inout("rdi") z.as_mut_ptr() => _,
        inout("rsi") x.as_ptr() => _,
        inout("rdx") y.as_ptr() => _,
        inout("rcx") c.as_ptr() => _,
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
            )
    };
}
