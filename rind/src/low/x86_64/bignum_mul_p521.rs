// generated source. do not edit.
#![allow(non_upper_case_globals, unused_macros, unused_imports)]
use crate::low::macros::*;

// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

// ----------------------------------------------------------------------------
// Multiply modulo p_521, z := (x * y) mod p_521, assuming x and y reduced
// Inputs x[9], y[9]; output z[9]
//
//    extern void bignum_mul_p521(uint64_t z[static 9], const uint64_t x[static 9],
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

// Copied in

macro_rules! y {
    () => {
        "rcx"
    };
}

// mulpadd (high,low,x) adds rdx * x to a register-pair (high,low)
// maintaining consistent double-carrying with adcx and adox,
// using rax and rbx as temporaries.

macro_rules! mulpadd {
    ($high:expr, $low:expr, $x:expr) => { Q!(
        "mulx rbx, rax, " $x ";\n"
        "adcx " $low ", rax;\n"
        "adox " $high ", rbx"
    )}
}

/// Multiply modulo p_521, z := (x * y) mod p_521, assuming x and y reduced
///
/// Inputs x[9], y[9]; output z[9]
pub(crate) fn bignum_mul_p521(z: &mut [u64; 9], x: &[u64; 9], y: &[u64; 9]) {
    // SAFETY: inline assembly. see [crate::low::inline_assembly_safety] for safety info.
    unsafe {
        core::arch::asm!(

        Q!("    endbr64         " ),

        // Save more registers to play with and make temporary space on stack

        Q!("    push            " "rbp"),
        Q!("    push            " "rbx"),
        Q!("    push            " "r12"),
        Q!("    push            " "r13"),
        Q!("    push            " "r14"),
        Q!("    push            " "r15"),
        Q!("    sub             " "rsp, 64"),

        // Copy y into a safe register to start with

        Q!("    mov             " y!() ", rdx"),

        // Clone of the main body of bignum_8_16, writing back the low 8 words to
        // the temporary buffer on the stack and keeping the top half in r15,...,r8

        Q!("    xor             " "ebp, ebp"),
        Q!("    mov             " "rdx, [" y!() "]"),
        Q!("    mulx            " "r9, r8, [" x!() "]"),
        Q!("    mov             " "[rsp], r8"),
        Q!("    mulx            " "r10, rbx, [" x!() "+ 0x8]"),
        Q!("    adc             " "r9, rbx"),
        Q!("    mulx            " "r11, rbx, [" x!() "+ 0x10]"),
        Q!("    adc             " "r10, rbx"),
        Q!("    mulx            " "r12, rbx, [" x!() "+ 0x18]"),
        Q!("    adc             " "r11, rbx"),
        Q!("    mulx            " "r13, rbx, [" x!() "+ 0x20]"),
        Q!("    adc             " "r12, rbx"),
        Q!("    mulx            " "r14, rbx, [" x!() "+ 0x28]"),
        Q!("    adc             " "r13, rbx"),
        Q!("    mulx            " "r15, rbx, [" x!() "+ 0x30]"),
        Q!("    adc             " "r14, rbx"),
        Q!("    mulx            " "r8, rbx, [" x!() "+ 0x38]"),
        Q!("    adc             " "r15, rbx"),
        Q!("    adc             " "r8, rbp"),
        Q!("    mov             " "rdx, [" y!() "+ 0x8]"),
        Q!("    xor             " "ebp, ebp"),
        Q!("    mulx            " "rbx, rax, [" x!() "]"),
        Q!("    adcx            " "r9, rax"),
        Q!("    adox            " "r10, rbx"),
        Q!("    mov             " "[rsp + 0x8], r9"),
        Q!("    mulx            " "rbx, rax, [" x!() "+ 0x8]"),
        Q!("    adcx            " "r10, rax"),
        Q!("    adox            " "r11, rbx"),
        Q!("    mulx            " "rbx, rax, [" x!() "+ 0x10]"),
        Q!("    adcx            " "r11, rax"),
        Q!("    adox            " "r12, rbx"),
        Q!("    mulx            " "rbx, rax, [" x!() "+ 0x18]"),
        Q!("    adcx            " "r12, rax"),
        Q!("    adox            " "r13, rbx"),
        Q!("    mulx            " "rbx, rax, [" x!() "+ 0x20]"),
        Q!("    adcx            " "r13, rax"),
        Q!("    adox            " "r14, rbx"),
        Q!("    mulx            " "rbx, rax, [" x!() "+ 0x28]"),
        Q!("    adcx            " "r14, rax"),
        Q!("    adox            " "r15, rbx"),
        Q!("    mulx            " "rbx, rax, [" x!() "+ 0x30]"),
        Q!("    adcx            " "r15, rax"),
        Q!("    adox            " "r8, rbx"),
        Q!("    mulx            " "r9, rax, [" x!() "+ 0x38]"),
        Q!("    adcx            " "r8, rax"),
        Q!("    adox            " "r9, rbp"),
        Q!("    adc             " "r9, rbp"),
        Q!("    mov             " "rdx, [" y!() "+ 0x10]"),
        Q!("    xor             " "ebp, ebp"),
        Q!("    mulx            " "rbx, rax, [" x!() "]"),
        Q!("    adcx            " "r10, rax"),
        Q!("    adox            " "r11, rbx"),
        Q!("    mov             " "[rsp + 0x10], r10"),
        Q!("    mulx            " "rbx, rax, [" x!() "+ 0x8]"),
        Q!("    adcx            " "r11, rax"),
        Q!("    adox            " "r12, rbx"),
        Q!("    mulx            " "rbx, rax, [" x!() "+ 0x10]"),
        Q!("    adcx            " "r12, rax"),
        Q!("    adox            " "r13, rbx"),
        Q!("    mulx            " "rbx, rax, [" x!() "+ 0x18]"),
        Q!("    adcx            " "r13, rax"),
        Q!("    adox            " "r14, rbx"),
        Q!("    mulx            " "rbx, rax, [" x!() "+ 0x20]"),
        Q!("    adcx            " "r14, rax"),
        Q!("    adox            " "r15, rbx"),
        Q!("    mulx            " "rbx, rax, [" x!() "+ 0x28]"),
        Q!("    adcx            " "r15, rax"),
        Q!("    adox            " "r8, rbx"),
        Q!("    mulx            " "rbx, rax, [" x!() "+ 0x30]"),
        Q!("    adcx            " "r8, rax"),
        Q!("    adox            " "r9, rbx"),
        Q!("    mulx            " "r10, rax, [" x!() "+ 0x38]"),
        Q!("    adcx            " "r9, rax"),
        Q!("    adox            " "r10, rbp"),
        Q!("    adc             " "r10, rbp"),
        Q!("    mov             " "rdx, [" y!() "+ 0x18]"),
        Q!("    xor             " "ebp, ebp"),
        Q!("    mulx            " "rbx, rax, [" x!() "]"),
        Q!("    adcx            " "r11, rax"),
        Q!("    adox            " "r12, rbx"),
        Q!("    mov             " "[rsp + 0x18], r11"),
        Q!("    mulx            " "rbx, rax, [" x!() "+ 0x8]"),
        Q!("    adcx            " "r12, rax"),
        Q!("    adox            " "r13, rbx"),
        Q!("    mulx            " "rbx, rax, [" x!() "+ 0x10]"),
        Q!("    adcx            " "r13, rax"),
        Q!("    adox            " "r14, rbx"),
        Q!("    mulx            " "rbx, rax, [" x!() "+ 0x18]"),
        Q!("    adcx            " "r14, rax"),
        Q!("    adox            " "r15, rbx"),
        Q!("    mulx            " "rbx, rax, [" x!() "+ 0x20]"),
        Q!("    adcx            " "r15, rax"),
        Q!("    adox            " "r8, rbx"),
        Q!("    mulx            " "rbx, rax, [" x!() "+ 0x28]"),
        Q!("    adcx            " "r8, rax"),
        Q!("    adox            " "r9, rbx"),
        Q!("    mulx            " "rbx, rax, [" x!() "+ 0x30]"),
        Q!("    adcx            " "r9, rax"),
        Q!("    adox            " "r10, rbx"),
        Q!("    mulx            " "r11, rax, [" x!() "+ 0x38]"),
        Q!("    adcx            " "r10, rax"),
        Q!("    adox            " "r11, rbp"),
        Q!("    adc             " "r11, rbp"),
        Q!("    mov             " "rdx, [" y!() "+ 0x20]"),
        Q!("    xor             " "ebp, ebp"),
        Q!("    mulx            " "rbx, rax, [" x!() "]"),
        Q!("    adcx            " "r12, rax"),
        Q!("    adox            " "r13, rbx"),
        Q!("    mov             " "[rsp + 0x20], r12"),
        Q!("    mulx            " "rbx, rax, [" x!() "+ 0x8]"),
        Q!("    adcx            " "r13, rax"),
        Q!("    adox            " "r14, rbx"),
        Q!("    mulx            " "rbx, rax, [" x!() "+ 0x10]"),
        Q!("    adcx            " "r14, rax"),
        Q!("    adox            " "r15, rbx"),
        Q!("    mulx            " "rbx, rax, [" x!() "+ 0x18]"),
        Q!("    adcx            " "r15, rax"),
        Q!("    adox            " "r8, rbx"),
        Q!("    mulx            " "rbx, rax, [" x!() "+ 0x20]"),
        Q!("    adcx            " "r8, rax"),
        Q!("    adox            " "r9, rbx"),
        Q!("    mulx            " "rbx, rax, [" x!() "+ 0x28]"),
        Q!("    adcx            " "r9, rax"),
        Q!("    adox            " "r10, rbx"),
        Q!("    mulx            " "rbx, rax, [" x!() "+ 0x30]"),
        Q!("    adcx            " "r10, rax"),
        Q!("    adox            " "r11, rbx"),
        Q!("    mulx            " "r12, rax, [" x!() "+ 0x38]"),
        Q!("    adcx            " "r11, rax"),
        Q!("    adox            " "r12, rbp"),
        Q!("    adc             " "r12, rbp"),
        Q!("    mov             " "rdx, [" y!() "+ 0x28]"),
        Q!("    xor             " "ebp, ebp"),
        Q!("    mulx            " "rbx, rax, [" x!() "]"),
        Q!("    adcx            " "r13, rax"),
        Q!("    adox            " "r14, rbx"),
        Q!("    mov             " "[rsp + 0x28], r13"),
        Q!("    mulx            " "rbx, rax, [" x!() "+ 0x8]"),
        Q!("    adcx            " "r14, rax"),
        Q!("    adox            " "r15, rbx"),
        Q!("    mulx            " "rbx, rax, [" x!() "+ 0x10]"),
        Q!("    adcx            " "r15, rax"),
        Q!("    adox            " "r8, rbx"),
        Q!("    mulx            " "rbx, rax, [" x!() "+ 0x18]"),
        Q!("    adcx            " "r8, rax"),
        Q!("    adox            " "r9, rbx"),
        Q!("    mulx            " "rbx, rax, [" x!() "+ 0x20]"),
        Q!("    adcx            " "r9, rax"),
        Q!("    adox            " "r10, rbx"),
        Q!("    mulx            " "rbx, rax, [" x!() "+ 0x28]"),
        Q!("    adcx            " "r10, rax"),
        Q!("    adox            " "r11, rbx"),
        Q!("    mulx            " "rbx, rax, [" x!() "+ 0x30]"),
        Q!("    adcx            " "r11, rax"),
        Q!("    adox            " "r12, rbx"),
        Q!("    mulx            " "r13, rax, [" x!() "+ 0x38]"),
        Q!("    adcx            " "r12, rax"),
        Q!("    adox            " "r13, rbp"),
        Q!("    adc             " "r13, rbp"),
        Q!("    mov             " "rdx, [" y!() "+ 0x30]"),
        Q!("    xor             " "ebp, ebp"),
        Q!("    mulx            " "rbx, rax, [" x!() "]"),
        Q!("    adcx            " "r14, rax"),
        Q!("    adox            " "r15, rbx"),
        Q!("    mov             " "[rsp + 0x30], r14"),
        Q!("    mulx            " "rbx, rax, [" x!() "+ 0x8]"),
        Q!("    adcx            " "r15, rax"),
        Q!("    adox            " "r8, rbx"),
        Q!("    mulx            " "rbx, rax, [" x!() "+ 0x10]"),
        Q!("    adcx            " "r8, rax"),
        Q!("    adox            " "r9, rbx"),
        Q!("    mulx            " "rbx, rax, [" x!() "+ 0x18]"),
        Q!("    adcx            " "r9, rax"),
        Q!("    adox            " "r10, rbx"),
        Q!("    mulx            " "rbx, rax, [" x!() "+ 0x20]"),
        Q!("    adcx            " "r10, rax"),
        Q!("    adox            " "r11, rbx"),
        Q!("    mulx            " "rbx, rax, [" x!() "+ 0x28]"),
        Q!("    adcx            " "r11, rax"),
        Q!("    adox            " "r12, rbx"),
        Q!("    mulx            " "rbx, rax, [" x!() "+ 0x30]"),
        Q!("    adcx            " "r12, rax"),
        Q!("    adox            " "r13, rbx"),
        Q!("    mulx            " "r14, rax, [" x!() "+ 0x38]"),
        Q!("    adcx            " "r13, rax"),
        Q!("    adox            " "r14, rbp"),
        Q!("    adc             " "r14, rbp"),
        Q!("    mov             " "rdx, [" y!() "+ 0x38]"),
        Q!("    xor             " "ebp, ebp"),
        Q!("    mulx            " "rbx, rax, [" x!() "]"),
        Q!("    adcx            " "r15, rax"),
        Q!("    adox            " "r8, rbx"),
        Q!("    mov             " "[rsp + 0x38], r15"),
        Q!("    mulx            " "rbx, rax, [" x!() "+ 0x8]"),
        Q!("    adcx            " "r8, rax"),
        Q!("    adox            " "r9, rbx"),
        Q!("    mulx            " "rbx, rax, [" x!() "+ 0x10]"),
        Q!("    adcx            " "r9, rax"),
        Q!("    adox            " "r10, rbx"),
        Q!("    mulx            " "rbx, rax, [" x!() "+ 0x18]"),
        Q!("    adcx            " "r10, rax"),
        Q!("    adox            " "r11, rbx"),
        Q!("    mulx            " "rbx, rax, [" x!() "+ 0x20]"),
        Q!("    adcx            " "r11, rax"),
        Q!("    adox            " "r12, rbx"),
        Q!("    mulx            " "rbx, rax, [" x!() "+ 0x28]"),
        Q!("    adcx            " "r12, rax"),
        Q!("    adox            " "r13, rbx"),
        Q!("    mulx            " "rbx, rax, [" x!() "+ 0x30]"),
        Q!("    adcx            " "r13, rax"),
        Q!("    adox            " "r14, rbx"),
        Q!("    mulx            " "r15, rax, [" x!() "+ 0x38]"),
        Q!("    adcx            " "r14, rax"),
        Q!("    adox            " "r15, rbp"),
        Q!("    adc             " "r15, rbp"),

        // Accumulate x[8] * y[0..7], extending the window to rbp,r15,...,r8

        Q!("    mov             " "rdx, [" x!() "+ 64]"),
        Q!("    xor             " "ebp, ebp"),
        mulpadd!("r9", "r8", Q!("[" y!() "]")),
        mulpadd!("r10", "r9", Q!("[" y!() "+" "8" "]")),
        mulpadd!("r11", "r10", Q!("[" y!() "+" "16" "]")),
        mulpadd!("r12", "r11", Q!("[" y!() "+" "24" "]")),
        mulpadd!("r13", "r12", Q!("[" y!() "+" "32" "]")),
        mulpadd!("r14", "r13", Q!("[" y!() "+" "40" "]")),
        mulpadd!("r15", "r14", Q!("[" y!() "+" "48" "]")),
        Q!("    mulx            " "rbx, rax, [" y!() "+ 56]"),
        Q!("    adcx            " "r15, rax"),
        Q!("    adox            " "rbx, rbp"),
        Q!("    adc             " "rbp, rbx"),

        // Accumulate y[8] * x[0..8] within this extended window rbp,r15,...,r8

        Q!("    mov             " "rdx, [" y!() "+ 64]"),
        Q!("    xor             " "eax, eax"),
        mulpadd!("r9", "r8", Q!("[" x!() "]")),
        mulpadd!("r10", "r9", Q!("[" x!() "+" "8" "]")),
        mulpadd!("r11", "r10", Q!("[" x!() "+" "16" "]")),
        mulpadd!("r12", "r11", Q!("[" x!() "+" "24" "]")),
        mulpadd!("r13", "r12", Q!("[" x!() "+" "32" "]")),
        mulpadd!("r14", "r13", Q!("[" x!() "+" "40" "]")),
        mulpadd!("r15", "r14", Q!("[" x!() "+" "48" "]")),
        Q!("    mulx            " "rbx, rax, [" x!() "+ 56]"),
        Q!("    adcx            " "r15, rax"),
        Q!("    adox            " "rbp, rbx"),
        Q!("    mulx            " "rbx, rax, [" x!() "+ 64]"),
        Q!("    adc             " "rbp, rax"),

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
        Q!("    pop             " "rbx"),
        Q!("    pop             " "rbp"),

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
