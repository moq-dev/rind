// generated source. do not edit.
#![allow(non_upper_case_globals, unused_macros, unused_imports)]
use crate::low::macros::*;

// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

// ----------------------------------------------------------------------------
// Square modulo p_521, z := (x^2) mod p_521, assuming x reduced
// Input x[9]; output z[9]
//
//    extern void bignum_sqr_p521(uint64_t z[static 9], const uint64_t x[static 9]);
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

// A zero register

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

// mulpadd(high,low,i) adds rdx * x[i] to a register-pair (high,low)
// maintaining consistent double-carrying with adcx and adox,
// using rax and rcx as temporaries.

macro_rules! mulpadd {
    ($high:expr, $low:expr, $I:expr) => { Q!(
        "mulx rcx, rax, [" x!() "+ " $I "];\n"
        "adcx " $low ", rax;\n"
        "adox " $high ", rcx"
    )}
}

// mulpade(high,low,i) adds rdx * x[i] to a register-pair (high,low)
// maintaining consistent double-carrying with adcx and adox,
// using rax as a temporary, assuming high created from scratch
// and that zero has value zero.

macro_rules! mulpade {
    ($high:expr, $low:expr, $I:expr) => { Q!(
        "mulx " $high ", rax, [" x!() "+ " $I "];\n"
        "adcx " $low ", rax;\n"
        "adox " $high ", " zero!()
    )}
}

/// Square modulo p_521, z := (x^2) mod p_521, assuming x reduced
///
/// Input x[9]; output z[9]
pub(crate) fn bignum_sqr_p521(z: &mut [u64; 9], x: &[u64; 9]) {
    // SAFETY: inline assembly. see [crate::low::inline_assembly_safety] for safety info.
    unsafe {
        core::arch::asm!(

        Q!("    endbr64         " ),

        // Save more registers to play with and make temporary space on stack

        Q!("    push            " "rbp"),
        Q!("    push            " "r12"),
        Q!("    push            " "r13"),
        Q!("    push            " "r14"),
        Q!("    push            " "r15"),
        Q!("    sub             " "rsp, 64"),

        // Do a basic 8x8 squaring stashing in rsp[0..7] but keeping the
        // top half in the usual rotating register window r15,...,r8. Except
        // for the lack of full writeback this is the same as bignum_sqr_8_16.

        Q!("    xor             " zeroe!() ", " zeroe!()),

        Q!("    mov             " "rdx, [" x!() "]"),
        Q!("    mulx            " "rax, r9, [" x!() "+ 8]"),
        Q!("    mov             " "[rsp + 8], r9"),
        Q!("    mulx            " "rcx, r10, [" x!() "+ 16]"),
        Q!("    adcx            " "r10, rax"),
        Q!("    mov             " "[rsp + 16], r10"),
        Q!("    mulx            " "rax, r11, [" x!() "+ 24]"),
        Q!("    adcx            " "r11, rcx"),
        Q!("    mulx            " "rcx, r12, [" x!() "+ 32]"),
        Q!("    adcx            " "r12, rax"),
        Q!("    mulx            " "rax, r13, [" x!() "+ 40]"),
        Q!("    adcx            " "r13, rcx"),
        Q!("    mulx            " "rcx, r14, [" x!() "+ 48]"),
        Q!("    adcx            " "r14, rax"),
        Q!("    mulx            " "r8, r15, [" x!() "+ 56]"),
        Q!("    adcx            " "r15, rcx"),
        Q!("    adcx            " "r8, " zero!()),

        Q!("    xor             " zeroe!() ", " zeroe!()),
        Q!("    mov             " "rdx, [" x!() "+ 8]"),
        mulpadd!("r12", "r11", "16"),
        Q!("    mov             " "[rsp + 24], r11"),
        mulpadd!("r13", "r12", "24"),
        Q!("    mov             " "[rsp + 32], r12"),
        mulpadd!("r14", "r13", "32"),
        mulpadd!("r15", "r14", "40"),
        mulpadd!("r8", "r15", "48"),
        mulpade!("r9", "r8", "56"),
        Q!("    mov             " "rdx, [" x!() "+ 32]"),
        mulpade!("r10", "r9", "40"),
        Q!("    adcx            " "r10, " zero!()),

        Q!("    xor             " zeroe!() ", " zeroe!()),
        Q!("    mov             " "rdx, [" x!() "+ 16]"),
        mulpadd!("r14", "r13", "24"),
        Q!("    mov             " "[rsp + 40], r13"),
        mulpadd!("r15", "r14", "32"),
        Q!("    mov             " "[rsp + 48], r14"),
        mulpadd!("r8", "r15", "40"),
        mulpadd!("r9", "r8", "48"),
        mulpadd!("r10", "r9", "56"),
        Q!("    mov             " "rdx, [" x!() "+ 48]"),
        mulpade!("r11", "r10", "32"),
        mulpade!("r12", "r11", "40"),
        Q!("    adcx            " "r12, " zero!()),

        Q!("    xor             " zeroe!() ", " zeroe!()),
        Q!("    mov             " "rdx, [" x!() "+ 24]"),
        mulpadd!("r8", "r15", "32"),
        Q!("    mov             " "[rsp + 56], r15"),
        mulpadd!("r9", "r8", "40"),
        mulpadd!("r10", "r9", "48"),
        mulpadd!("r11", "r10", "56"),
        Q!("    mov             " "rdx, [" x!() "+ 56]"),
        mulpadd!("r12", "r11", "32"),
        mulpade!("r13", "r12", "40"),
        mulpade!("r14", "r13", "48"),
        Q!("    adcx            " "r14, " zero!()),

        Q!("    xor             " zeroe!() ", " zeroe!()),
        Q!("    mov             " "rdx, [" x!() "]"),
        Q!("    mulx            " "rcx, rax, rdx"),
        Q!("    mov             " "[rsp], rax"),
        Q!("    mov             " "rax, [rsp + 8]"),
        Q!("    adcx            " "rax, rax"),
        Q!("    adox            " "rax, rcx"),
        Q!("    mov             " "[rsp + 8], rax"),

        Q!("    mov             " "rax, [rsp + 16]"),
        Q!("    mov             " "rdx, [" x!() "+ 8]"),
        Q!("    mulx            " "rcx, rdx, rdx"),
        Q!("    adcx            " "rax, rax"),
        Q!("    adox            " "rax, rdx"),
        Q!("    mov             " "[rsp + 16], rax"),
        Q!("    mov             " "rax, [rsp + 24]"),
        Q!("    adcx            " "rax, rax"),
        Q!("    adox            " "rax, rcx"),
        Q!("    mov             " "[rsp + 24], rax"),

        Q!("    mov             " "rax, [rsp + 32]"),
        Q!("    mov             " "rdx, [" x!() "+ 16]"),
        Q!("    mulx            " "rcx, rdx, rdx"),
        Q!("    adcx            " "rax, rax"),
        Q!("    adox            " "rax, rdx"),
        Q!("    mov             " "[rsp + 32], rax"),
        Q!("    mov             " "rax, [rsp + 40]"),
        Q!("    adcx            " "rax, rax"),
        Q!("    adox            " "rax, rcx"),
        Q!("    mov             " "[rsp + 40], rax"),

        Q!("    mov             " "rax, [rsp + 48]"),
        Q!("    mov             " "rdx, [" x!() "+ 24]"),
        Q!("    mulx            " "rcx, rdx, rdx"),
        Q!("    adcx            " "rax, rax"),
        Q!("    adox            " "rax, rdx"),
        Q!("    mov             " "[rsp + 48], rax"),
        Q!("    mov             " "rax, [rsp + 56]"),
        Q!("    adcx            " "rax, rax"),
        Q!("    adox            " "rax, rcx"),
        Q!("    mov             " "[rsp + 56], rax"),

        Q!("    mov             " "rdx, [" x!() "+ 32]"),
        Q!("    mulx            " "rcx, rdx, rdx"),
        Q!("    adcx            " "r8, r8"),
        Q!("    adox            " "r8, rdx"),
        Q!("    adcx            " "r9, r9"),
        Q!("    adox            " "r9, rcx"),

        Q!("    mov             " "rdx, [" x!() "+ 40]"),
        Q!("    mulx            " "rcx, rdx, rdx"),
        Q!("    adcx            " "r10, r10"),
        Q!("    adox            " "r10, rdx"),
        Q!("    adcx            " "r11, r11"),
        Q!("    adox            " "r11, rcx"),

        Q!("    mov             " "rdx, [" x!() "+ 48]"),
        Q!("    mulx            " "rcx, rdx, rdx"),
        Q!("    adcx            " "r12, r12"),
        Q!("    adox            " "r12, rdx"),
        Q!("    adcx            " "r13, r13"),
        Q!("    adox            " "r13, rcx"),

        Q!("    mov             " "rdx, [" x!() "+ 56]"),
        Q!("    mulx            " "r15, rdx, rdx"),
        Q!("    adcx            " "r14, r14"),
        Q!("    adox            " "r14, rdx"),
        Q!("    adcx            " "r15, " zero!()),
        Q!("    adox            " "r15, " zero!()),

        // Augment the high part with the contribution from the top little word C.
        // If we write the input as 2^512 * C + x then we are otherwise just doing
        // x^2, so we need to add to the high part 2^512 * C^2 + (2 * C) * x.
        // The initial doubling add of C also clears the CF and OF flags as desired.
        // We extend the window now to the 9-element rbp,r15,r14,...,r8.

        Q!("    mov             " "rdx, [" x!() "+ 64]"),
        Q!("    mov             " "rbp, rdx"),
        Q!("    imul            " "rbp, rbp"),
        Q!("    add             " "rdx, rdx"),
        mulpadd!("r9", "r8", "0"),
        mulpadd!("r10", "r9", "8"),
        mulpadd!("r11", "r10", "16"),
        mulpadd!("r12", "r11", "24"),
        mulpadd!("r13", "r12", "32"),
        mulpadd!("r14", "r13", "40"),
        mulpadd!("r15", "r14", "48"),
        Q!("    mulx            " "rcx, rax, [" x!() "+ 56]"),
        Q!("    adcx            " "r15, rax"),
        Q!("    adox            " "rbp, rcx"),
        Q!("    adc             " "rbp, 0"),

        // Rotate the upper portion right 9 bits since 2^512 == 2^-9 (mod p_521)
        // Let rotated result rbp,r15,r14,...,r8 be h (high) and rsp[0..7] be l (low)

        Q!("    mov             " "rax, r8"),
        Q!("    and             " "rax, 0x1FF"),
        Q!("    shrd            " "r8, r9, 9"),
        Q!("    shrd            " "r9, r10, 9"),
        Q!("    shrd            " "r10, r11, 9"),
        Q!("    shrd            " "r11, r12, 9"),
        Q!("    shrd            " "r12, r13, 9"),
        Q!("    shrd            " "r13, r14, 9"),
        Q!("    shrd            " "r14, r15, 9"),
        Q!("    shrd            " "r15, rbp, 9"),
        Q!("    shr             " "rbp, 9"),
        Q!("    add             " "rbp, rax"),

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
        Q!("    adc             " "rbp, ~ 0x1FF"),

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
        Q!("    sbb             " "rbp, 0"),
        Q!("    and             " "rbp, 0x1FF"),
        Q!("    mov             " "[" z!() "+ 64], rbp"),

        // Restore registers and return

        Q!("    add             " "rsp, 64"),
        Q!("    pop             " "r15"),
        Q!("    pop             " "r14"),
        Q!("    pop             " "r13"),
        Q!("    pop             " "r12"),
        Q!("    pop             " "rbp"),

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
