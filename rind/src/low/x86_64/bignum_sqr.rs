// generated source. do not edit.
#![allow(non_upper_case_globals, unused_macros, unused_imports)]
use crate::low::macros::*;

// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

// ----------------------------------------------------------------------------
// Square z := x^2
// Input x[n]; output z[k]
//
//    extern void bignum_sqr(uint64_t k, uint64_t *z, uint64_t n, const uint64_t *x);
//
// Does the "z := x^2" operation where x is n digits and result z is k.
// Truncates the result in general unless k >= 2 * n
//
// Standard x86-64 ABI: RDI = k, RSI = z, RDX = n, RCX = x
// Microsoft x64 ABI:   RCX = k, RDX = z, R8 = n, R9 = x
// ----------------------------------------------------------------------------

// First three are where arguments come in, but n is moved.

macro_rules! p {
    () => {
        "rdi"
    };
}
macro_rules! z {
    () => {
        "rsi"
    };
}
macro_rules! x {
    () => {
        "rcx"
    };
}
macro_rules! n {
    () => {
        "r8"
    };
}

// These are always local scratch since multiplier result is in these

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

// Other variables

macro_rules! i {
    () => {
        "rbx"
    };
}
macro_rules! ll {
    () => {
        "rbp"
    };
}
macro_rules! hh {
    () => {
        "r9"
    };
}
macro_rules! k {
    () => {
        "r10"
    };
}
macro_rules! y {
    () => {
        "r11"
    };
}
macro_rules! htop {
    () => {
        "r12"
    };
}
macro_rules! l {
    () => {
        "r13"
    };
}
macro_rules! h {
    () => {
        "r14"
    };
}
macro_rules! c {
    () => {
        "r15"
    };
}

// Short versions

macro_rules! llshort {
    () => {
        "ebp"
    };
}

/// Square z := x^2
///
/// Input x[n]; output z[k]
///
/// Does the "z := x^2" operation where x is n digits and result z is k.
/// Truncates the result in general unless k >= 2 * n
pub(crate) fn bignum_sqr(z: &mut [u64], x: &[u64]) {
    debug_assert!(z.len() >= x.len() * 2);
    // SAFETY: inline assembly. see [crate::low::inline_assembly_safety] for safety info.
    unsafe {
        core::arch::asm!(

        Q!("    endbr64         " ),

        // We use too many registers, and also we need rax:rdx for multiplications

        Q!("    push            " "rbx"),
        Q!("    push            " "rbp"),
        Q!("    push            " "r12"),
        Q!("    push            " "r13"),
        Q!("    push            " "r14"),
        Q!("    push            " "r15"),
        Q!("    mov             " n!() ", rdx"),

        // If p = 0 the result is trivial and nothing needs doing

        Q!("    test            " p!() ", " p!()),
        Q!("    jz              " Label!("Lbignum_sqr_end", 2, After)),

        // initialize (hh,ll) = 0

        Q!("    xor             " llshort!() ", " llshort!()),
        Q!("    xor             " hh!() ", " hh!()),

        // Iterate outer loop from k = 0 ... k = p - 1 producing result digits

        Q!("    xor             " k!() ", " k!()),

        Q!(Label!("Lbignum_sqr_outerloop", 3) ":"),

        // First let bot = MAX 0 (k + 1 - n) and top = MIN (k + 1) n
        // We want to accumulate all x[i] * x[k - i] for bot <= i < top
        // For the optimization of squaring we avoid duplication and do
        // 2 * x[i] * x[k - i] for i < htop, where htop = MIN ((k+1)/2) n
        // Initialize i = bot; in fact just compute bot as i directly.

        Q!("    xor             " c!() ", " c!()),
        Q!("    lea             " i!() ", [" k!() "+ 1]"),
        Q!("    mov             " htop!() ", " i!()),
        Q!("    shr             " htop!() ", 1"),
        Q!("    sub             " i!() ", " n!()),
        Q!("    cmovc           " i!() ", " c!()),
        Q!("    cmp             " htop!() ", " n!()),
        Q!("    cmovnc          " htop!() ", " n!()),

        // Initialize the three-part local sum (c,h,l); c was already done above

        Q!("    xor             " l!() ", " l!()),
        Q!("    xor             " h!() ", " h!()),

        // If htop <= bot then main doubled part of the sum is empty

        Q!("    cmp             " i!() ", " htop!()),
        Q!("    jnc             " Label!("Lbignum_sqr_nosumming", 4, After)),

        // Use a moving pointer for [y] = x[k-i] for the cofactor

        Q!("    mov             " a!() ", " k!()),
        Q!("    sub             " a!() ", " i!()),
        Q!("    lea             " y!() ", [" x!() "+ 8 * " a!() "]"),

        // Do the main part of the sum x[i] * x[k - i] for 2 * i < k

        Q!(Label!("Lbignum_sqr_innerloop", 5) ":"),
        Q!("    mov             " a!() ", [" x!() "+ 8 * " i!() "]"),
        Q!("    mul             " "QWORD PTR [" y!() "]"),
        Q!("    add             " l!() ", " a!()),
        Q!("    adc             " h!() ", " d!()),
        Q!("    adc             " c!() ", 0"),
        Q!("    sub             " y!() ", 8"),
        Q!("    inc             " i!()),
        Q!("    cmp             " i!() ", " htop!()),
        Q!("    jc              " Label!("Lbignum_sqr_innerloop", 5, Before)),

        // Now double it

        Q!("    add             " l!() ", " l!()),
        Q!("    adc             " h!() ", " h!()),
        Q!("    adc             " c!() ", " c!()),

        // If k is even (which means 2 * i = k) and i < n add the extra x[i]^2 term

        Q!(Label!("Lbignum_sqr_nosumming", 4) ":"),
        Q!("    test            " k!() ", 1"),
        Q!("    jnz             " Label!("Lbignum_sqr_innerend", 6, After)),
        Q!("    cmp             " i!() ", " n!()),
        Q!("    jnc             " Label!("Lbignum_sqr_innerend", 6, After)),

        Q!("    mov             " a!() ", [" x!() "+ 8 * " i!() "]"),
        Q!("    mul             " a!()),
        Q!("    add             " l!() ", " a!()),
        Q!("    adc             " h!() ", " d!()),
        Q!("    adc             " c!() ", 0"),

        // Now add the local sum into the global sum, store and shift

        Q!(Label!("Lbignum_sqr_innerend", 6) ":"),
        Q!("    add             " l!() ", " ll!()),
        Q!("    mov             " "[" z!() "+ 8 * " k!() "], " l!()),
        Q!("    adc             " h!() ", " hh!()),
        Q!("    mov             " ll!() ", " h!()),
        Q!("    adc             " c!() ", 0"),
        Q!("    mov             " hh!() ", " c!()),

        Q!("    inc             " k!()),
        Q!("    cmp             " k!() ", " p!()),
        Q!("    jc              " Label!("Lbignum_sqr_outerloop", 3, Before)),

        // Restore registers and return

        Q!(Label!("Lbignum_sqr_end", 2) ":"),
        Q!("    pop             " "r15"),
        Q!("    pop             " "r14"),
        Q!("    pop             " "r13"),
        Q!("    pop             " "r12"),
        Q!("    pop             " "rbp"),
        Q!("    pop             " "rbx"),
        inout("rdi") z.len() => _,
        inout("rsi") z.as_mut_ptr() => _,
        inout("rdx") x.len() => _,
        inout("rcx") x.as_ptr() => _,
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
