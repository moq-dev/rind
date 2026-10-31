// generated source. do not edit.
#![allow(non_upper_case_globals, unused_macros, unused_imports)]
use crate::low::macros::*;

// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

// ----------------------------------------------------------------------------
// Reduce modulo group order, z := x mod n_521
// Input x[9]; output z[9]
//
//    extern void bignum_mod_n521_9(uint64_t z[static 9], const uint64_t x[static 9]);
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
        "rdx"
    };
}
macro_rules! a {
    () => {
        "rax"
    };
}

macro_rules! c {
    () => {
        "rcx"
    };
}
macro_rules! d {
    () => {
        "r8"
    };
}

macro_rules! n0 {
    () => {
        "r9"
    };
}
macro_rules! n1 {
    () => {
        "r10"
    };
}
macro_rules! n2 {
    () => {
        "r11"
    };
}
macro_rules! n3 {
    () => {
        Q!(d!())
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
pub(crate) fn bignum_mod_n521(z: &mut [u64; 9], x: &[u64; 9]) {
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

        Q!("    mov             " n0!() ", 0x449048e16ec79bf7"),
        Q!("    mulx            " c!() ", " a!() ", " n0!()),
        Q!("    adcx            " a!() ", [" x!() "]"),
        Q!("    mov             " "[" z!() "], " a!()),

        Q!("    mov             " n1!() ", 0xc44a36477663b851"),
        Q!("    mulx            " d!() ", " a!() ", " n1!()),
        Q!("    adcx            " a!() ", [" x!() "+ 8]"),
        Q!("    adox            " a!() ", " c!()),
        Q!("    mov             " "[" z!() "+ 8], " a!()),

        Q!("    mov             " n2!() ", 0x8033feb708f65a2f"),
        Q!("    mulx            " c!() ", " a!() ", " n2!()),
        Q!("    adcx            " a!() ", [" x!() "+ 16]"),
        Q!("    adox            " a!() ", " d!()),
        Q!("    mov             " "[" z!() "+ 16], " a!()),

        Q!("    mov             " a!() ", 0xae79787c40d06994"),
        Q!("    mulx            " d!() ", " a!() ", " a!()),
        Q!("    adcx            " a!() ", [" x!() "+ 24]"),
        Q!("    adox            " a!() ", " c!()),
        Q!("    mov             " "[" z!() "+ 24], " a!()),

        Q!("    mov             " ashort!() ", 5"),
        Q!("    mulx            " c!() ", " a!() ", " a!()),
        Q!("    adcx            " a!() ", [" x!() "+ 32]"),
        Q!("    adox            " a!() ", " d!()),
        Q!("    mov             " "[" z!() "+ 32], " a!()),

        Q!("    mov             " a!() ", " c!()),
        Q!("    adox            " c!() ", " c!()),
        Q!("    adc             " c!() ", [" x!() "+ 40]"),
        Q!("    mov             " "[" z!() "+ 40], " c!()),

        Q!("    mov             " c!() ", [" x!() "+ 48]"),
        Q!("    adc             " c!() ", " a!()),
        Q!("    mov             " "[" z!() "+ 48], " c!()),

        Q!("    mov             " c!() ", [" x!() "+ 56]"),
        Q!("    adc             " c!() ", " a!()),
        Q!("    mov             " "[" z!() "+ 56], " c!()),

        Q!("    mov             " c!() ", [" z!() "+ 64]"),
        Q!("    adc             " c!() ", " a!()),

        // We already know r < n_521, but if it actually went negative then
        // we need to add back n_521 again. Recycle q as a bitmask for r < n_521,
        // and just subtract r_521 and mask rather than literally adding 2^521.
        // This also gets rid of the bit-stuffing above.

        Q!("    cmc             " ),
        Q!("    sbb             " q!() ", " q!()),
        Q!("    and             " n0!() ", " q!()),
        Q!("    and             " n1!() ", " q!()),
        Q!("    and             " n2!() ", " q!()),
        Q!("    mov             " n3!() ", 0xae79787c40d06994"),
        Q!("    and             " n3!() ", " q!()),
        Q!("    and             " qshort!() ", 5"),
        Q!("    sub             " "[" z!() "], " n0!()),
        Q!("    sbb             " "[" z!() "+ 8], " n1!()),
        Q!("    sbb             " "[" z!() "+ 16], " n2!()),
        Q!("    sbb             " "[" z!() "+ 24], " n3!()),
        Q!("    sbb             " "[" z!() "+ 32], " q!()),
        Q!("    sbb             " "[" z!() "+ 40], " a!()),
        Q!("    sbb             " "[" z!() "+ 48], " a!()),
        Q!("    sbb             " "[" z!() "+ 56], " a!()),
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
