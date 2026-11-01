// generated source. do not edit.
#![allow(non_upper_case_globals, unused_macros, unused_imports)]
use crate::low::macros::*;

// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

// ----------------------------------------------------------------------------
// Convert from Montgomery form z := (x / 2^256) mod p_256, assuming x reduced
// Input x[4]; output z[4]
//
//    extern void bignum_demont_p256_alt(uint64_t z[static 4],
//                                       const uint64_t x[static 4]);
//
// This assumes the input is < p_256 for correctness. If this is not the case,
// use the variant "bignum_deamont_p256" instead.
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

// Add rdx * m into a register-pair (high,low)
// maintaining consistent double-carrying with adcx and adox,
// using rax and rcx as temporaries

macro_rules! mulpado {
    ($high:expr, $low:expr, $m:expr) => { Q!(
        "mulx rcx, rax, " $m ";\n"
        "adcx " $low ", rax;\n"
        "adox " $high ", rcx"
    )}
}

// Add rcx * m into a register-pair (high,low) maintaining consistent
// carry-catching with carry (negated, as bitmask) and using rax and rdx
// as temporaries

macro_rules! mulpadd {
    ($carry:expr, $high:expr, $low:expr, $m:expr) => { Q!(
        "mov rax, " $m ";\n"
        "mul rcx;\n"
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
        "mul rcx;\n"
        "add " $low ", rax;\n"
        "adc " $high ", rdx;\n"
        "sbb " $carry ", " $carry
    )}
}

// Version with no carry in or out

macro_rules! mulpadn {
    ($high:expr, $low:expr, $m:expr) => { Q!(
        "mov rax, " $m ";\n"
        "mul rcx;\n"
        "add " $low ", rax;\n"
        "adc " $high ", rdx"
    )}
}

/// Convert from Montgomery form z := (x / 2^256) mod p_256, assuming x reduced
///
/// Input x[4]; output z[4]
///
/// This assumes the input is < p_256 for correctness. If this is not the case,
/// use the variant "bignum_deamont_p256" instead.
pub(crate) fn bignum_demont_p256_alt(z: &mut [u64; 4], x: &[u64; 4]) {
    // SAFETY: inline assembly. see [crate::low::inline_assembly_safety] for safety info.
    unsafe {
        core::arch::asm!(

        Q!("    endbr64         " ),

        // Set up an initial 4-word window [r11,r10,r9,r8] = x

        Q!("    mov             " "r8, [" x!() "]"),
        Q!("    mov             " "r9, [" x!() "+ 8]"),
        Q!("    mov             " "r10, [" x!() "+ 16]"),
        Q!("    mov             " "r11, [" x!() "+ 24]"),

        // Load constant 2^32; rcx toggles between this and (1 - rcx) below

        Q!("    mov             " "rcx, 0x0000000100000000"),

        // Montgomery reduce windows 0 and 1 together as [r8;rsi;r11;r10]

        mulpadi!("rsi", "r10", "r9", "r8"),
        mulpadd!("rsi", "r11", "r10", "r9"),
        Q!("    neg             " "rcx"),
        Q!("    neg             " "rsi"),
        Q!("    inc             " "rcx"),
        mulpadi!("r8", "rsi", "r11", "r8"),
        Q!("    neg             " "r8"),
        mulpadn!("r8", "rsi", "r9"),

        // Montgomery reduce windows 2 and 3 together as [r10;r9;r8;rsi]

        Q!("    neg             " "rcx"),
        Q!("    inc             " "rcx"),
        mulpadi!("r9", "rsi", "r11", "r10"),
        mulpadd!("r9", "r8", "rsi", "r11"),
        Q!("    neg             " "rcx"),
        Q!("    neg             " "r9"),
        Q!("    inc             " "rcx"),
        mulpadi!("r10", "r9", "r8", "r10"),
        Q!("    neg             " "r10"),
        mulpadn!("r10", "r9", "r11"),

        // Since the input was assumed reduced modulo, i.e. < p, we actually know that
        // 2^256 * [carries; r10;r9;r8;rsi] is <= (p - 1) + (2^256 - 1) p
        // and hence [carries; r10;r9;r8;rsi] < p. This means in fact carries = 0
        // and [r10;r9;r8;rsi] is already our answer, without further correction.
        // Write that back.

        Q!("    mov             " "[" z!() "], rsi"),
        Q!("    mov             " "[" z!() "+ 8], r8"),
        Q!("    mov             " "[" z!() "+ 16], r9"),
        Q!("    mov             " "[" z!() "+ 24], r10"),

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
