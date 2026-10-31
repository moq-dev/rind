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
// Standard ARM ABI: X0 = z, X1 = x
// ----------------------------------------------------------------------------

macro_rules! z {
    () => {
        "x0"
    };
}
macro_rules! x {
    () => {
        "x1"
    };
}

macro_rules! a0 {
    () => {
        "x2"
    };
}
macro_rules! a1 {
    () => {
        "x3"
    };
}
macro_rules! a2 {
    () => {
        "x4"
    };
}
macro_rules! a3 {
    () => {
        "x5"
    };
}
macro_rules! a4 {
    () => {
        "x6"
    };
}
macro_rules! a5 {
    () => {
        "x7"
    };
}
macro_rules! a6 {
    () => {
        "x8"
    };
}
macro_rules! a7 {
    () => {
        "x9"
    };
}
macro_rules! a8 {
    () => {
        "x1"
    };
}

macro_rules! l {
    () => {
        "x10"
    };
}

macro_rules! u0 {
    () => {
        "x2"
    };
}
macro_rules! u1 {
    () => {
        "x11"
    };
}
macro_rules! u2 {
    () => {
        "x12"
    };
}
macro_rules! u3 {
    () => {
        "x13"
    };
}
macro_rules! u4 {
    () => {
        "x14"
    };
}
macro_rules! u5 {
    () => {
        "x15"
    };
}
macro_rules! u6 {
    () => {
        "x16"
    };
}
macro_rules! u7 {
    () => {
        "x17"
    };
}
macro_rules! u8 {
    () => {
        "x19"
    };
}
macro_rules! u9 {
    () => {
        "x20"
    };
}
macro_rules! u10 {
    () => {
        "x21"
    };
}
macro_rules! u11 {
    () => {
        "x22"
    };
}
macro_rules! u12 {
    () => {
        "x23"
    };
}
macro_rules! u13 {
    () => {
        "x24"
    };
}
macro_rules! u14 {
    () => {
        "x25"
    };
}
macro_rules! u15 {
    () => {
        "x26"
    };
}
macro_rules! u16 {
    () => {
        "x4"
    };
}

/// Square modulo p_521, z := (x^2) mod p_521, assuming x reduced
///
/// Input x[9]; output z[9]
pub(crate) fn bignum_sqr_p521(z: &mut [u64; 9], x: &[u64; 9]) {
    // SAFETY: inline assembly. see [crate::low::inline_assembly_safety] for safety info.
    unsafe {
        core::arch::asm!(

        // It's convenient to have more registers to play with

        Q!("    stp             " "x19, x20, [sp, #-16] !"),
        Q!("    stp             " "x21, x22, [sp, #-16] !"),
        Q!("    stp             " "x23, x24, [sp, #-16] !"),
        Q!("    stp             " "x25, x26, [sp, #-16] !"),

        // Load low 8 elements as [a7;a6;a5;a4;a3;a2;a1;a0], set up an initial
        // window [u8;u7;u6;u5;u4;u3;u2;u1] =  10 + 20 + 30 + 40 + 50 + 60 + 70

        Q!("    ldp             " a0!() ", " a1!() ", [" x!() "]"),

        Q!("    mul             " u1!() ", " a0!() ", " a1!()),
        Q!("    umulh           " u2!() ", " a0!() ", " a1!()),

        Q!("    ldp             " a2!() ", " a3!() ", [" x!() ", #16]"),

        Q!("    mul             " l!() ", " a0!() ", " a2!()),
        Q!("    umulh           " u3!() ", " a0!() ", " a2!()),
        Q!("    adds            " u2!() ", " u2!() ", " l!()),

        Q!("    ldp             " a4!() ", " a5!() ", [" x!() ", #32]"),

        Q!("    mul             " l!() ", " a0!() ", " a3!()),
        Q!("    umulh           " u4!() ", " a0!() ", " a3!()),
        Q!("    adcs            " u3!() ", " u3!() ", " l!()),

        Q!("    ldp             " a6!() ", " a7!() ", [" x!() ", #48]"),

        Q!("    mul             " l!() ", " a0!() ", " a4!()),
        Q!("    umulh           " u5!() ", " a0!() ", " a4!()),
        Q!("    adcs            " u4!() ", " u4!() ", " l!()),

        Q!("    mul             " l!() ", " a0!() ", " a5!()),
        Q!("    umulh           " u6!() ", " a0!() ", " a5!()),
        Q!("    adcs            " u5!() ", " u5!() ", " l!()),

        Q!("    mul             " l!() ", " a0!() ", " a6!()),
        Q!("    umulh           " u7!() ", " a0!() ", " a6!()),
        Q!("    adcs            " u6!() ", " u6!() ", " l!()),

        Q!("    mul             " l!() ", " a0!() ", " a7!()),
        Q!("    umulh           " u8!() ", " a0!() ", " a7!()),
        Q!("    adcs            " u7!() ", " u7!() ", " l!()),

        Q!("    adc             " u8!() ", " u8!() ", xzr"),

        // Add in the next diagonal = 21 + 31 + 41 + 51 + 61 + 71 + 54

        Q!("    mul             " l!() ", " a1!() ", " a2!()),
        Q!("    adds            " u3!() ", " u3!() ", " l!()),
        Q!("    mul             " l!() ", " a1!() ", " a3!()),
        Q!("    adcs            " u4!() ", " u4!() ", " l!()),
        Q!("    mul             " l!() ", " a1!() ", " a4!()),
        Q!("    adcs            " u5!() ", " u5!() ", " l!()),
        Q!("    mul             " l!() ", " a1!() ", " a5!()),
        Q!("    adcs            " u6!() ", " u6!() ", " l!()),
        Q!("    mul             " l!() ", " a1!() ", " a6!()),
        Q!("    adcs            " u7!() ", " u7!() ", " l!()),
        Q!("    mul             " l!() ", " a1!() ", " a7!()),
        Q!("    adcs            " u8!() ", " u8!() ", " l!()),
        Q!("    cset            " u9!() ", cs"),

        Q!("    umulh           " l!() ", " a1!() ", " a2!()),
        Q!("    adds            " u4!() ", " u4!() ", " l!()),
        Q!("    umulh           " l!() ", " a1!() ", " a3!()),
        Q!("    adcs            " u5!() ", " u5!() ", " l!()),
        Q!("    umulh           " l!() ", " a1!() ", " a4!()),
        Q!("    adcs            " u6!() ", " u6!() ", " l!()),
        Q!("    umulh           " l!() ", " a1!() ", " a5!()),
        Q!("    adcs            " u7!() ", " u7!() ", " l!()),
        Q!("    umulh           " l!() ", " a1!() ", " a6!()),
        Q!("    adcs            " u8!() ", " u8!() ", " l!()),
        Q!("    umulh           " l!() ", " a1!() ", " a7!()),
        Q!("    adc             " u9!() ", " u9!() ", " l!()),
        Q!("    mul             " l!() ", " a4!() ", " a5!()),
        Q!("    umulh           " u10!() ", " a4!() ", " a5!()),
        Q!("    adds            " u9!() ", " u9!() ", " l!()),
        Q!("    adc             " u10!() ", " u10!() ", xzr"),

        // And the next one = 32 + 42 + 52 + 62 + 72 + 64 + 65

        Q!("    mul             " l!() ", " a2!() ", " a3!()),
        Q!("    adds            " u5!() ", " u5!() ", " l!()),
        Q!("    mul             " l!() ", " a2!() ", " a4!()),
        Q!("    adcs            " u6!() ", " u6!() ", " l!()),
        Q!("    mul             " l!() ", " a2!() ", " a5!()),
        Q!("    adcs            " u7!() ", " u7!() ", " l!()),
        Q!("    mul             " l!() ", " a2!() ", " a6!()),
        Q!("    adcs            " u8!() ", " u8!() ", " l!()),
        Q!("    mul             " l!() ", " a2!() ", " a7!()),
        Q!("    adcs            " u9!() ", " u9!() ", " l!()),
        Q!("    mul             " l!() ", " a4!() ", " a6!()),
        Q!("    adcs            " u10!() ", " u10!() ", " l!()),
        Q!("    cset            " u11!() ", cs"),

        Q!("    umulh           " l!() ", " a2!() ", " a3!()),
        Q!("    adds            " u6!() ", " u6!() ", " l!()),
        Q!("    umulh           " l!() ", " a2!() ", " a4!()),
        Q!("    adcs            " u7!() ", " u7!() ", " l!()),
        Q!("    umulh           " l!() ", " a2!() ", " a5!()),
        Q!("    adcs            " u8!() ", " u8!() ", " l!()),
        Q!("    umulh           " l!() ", " a2!() ", " a6!()),
        Q!("    adcs            " u9!() ", " u9!() ", " l!()),
        Q!("    umulh           " l!() ", " a2!() ", " a7!()),
        Q!("    adcs            " u10!() ", " u10!() ", " l!()),
        Q!("    umulh           " l!() ", " a4!() ", " a6!()),
        Q!("    adc             " u11!() ", " u11!() ", " l!()),
        Q!("    mul             " l!() ", " a5!() ", " a6!()),
        Q!("    umulh           " u12!() ", " a5!() ", " a6!()),
        Q!("    adds            " u11!() ", " u11!() ", " l!()),
        Q!("    adc             " u12!() ", " u12!() ", xzr"),

        // And the final one = 43 + 53 + 63 + 73 + 74 + 75 + 76

        Q!("    mul             " l!() ", " a3!() ", " a4!()),
        Q!("    adds            " u7!() ", " u7!() ", " l!()),
        Q!("    mul             " l!() ", " a3!() ", " a5!()),
        Q!("    adcs            " u8!() ", " u8!() ", " l!()),
        Q!("    mul             " l!() ", " a3!() ", " a6!()),
        Q!("    adcs            " u9!() ", " u9!() ", " l!()),
        Q!("    mul             " l!() ", " a3!() ", " a7!()),
        Q!("    adcs            " u10!() ", " u10!() ", " l!()),
        Q!("    mul             " l!() ", " a4!() ", " a7!()),
        Q!("    adcs            " u11!() ", " u11!() ", " l!()),
        Q!("    mul             " l!() ", " a5!() ", " a7!()),
        Q!("    adcs            " u12!() ", " u12!() ", " l!()),
        Q!("    cset            " u13!() ", cs"),

        Q!("    umulh           " l!() ", " a3!() ", " a4!()),
        Q!("    adds            " u8!() ", " u8!() ", " l!()),
        Q!("    umulh           " l!() ", " a3!() ", " a5!()),
        Q!("    adcs            " u9!() ", " u9!() ", " l!()),
        Q!("    umulh           " l!() ", " a3!() ", " a6!()),
        Q!("    adcs            " u10!() ", " u10!() ", " l!()),
        Q!("    umulh           " l!() ", " a3!() ", " a7!()),
        Q!("    adcs            " u11!() ", " u11!() ", " l!()),
        Q!("    umulh           " l!() ", " a4!() ", " a7!()),
        Q!("    adcs            " u12!() ", " u12!() ", " l!()),
        Q!("    umulh           " l!() ", " a5!() ", " a7!()),
        Q!("    adc             " u13!() ", " u13!() ", " l!()),
        Q!("    mul             " l!() ", " a6!() ", " a7!()),
        Q!("    umulh           " u14!() ", " a6!() ", " a7!()),
        Q!("    adds            " u13!() ", " u13!() ", " l!()),
        Q!("    adc             " u14!() ", " u14!() ", xzr"),

        // Double that, with u15 holding the top carry

        Q!("    adds            " u1!() ", " u1!() ", " u1!()),
        Q!("    adcs            " u2!() ", " u2!() ", " u2!()),
        Q!("    adcs            " u3!() ", " u3!() ", " u3!()),
        Q!("    adcs            " u4!() ", " u4!() ", " u4!()),
        Q!("    adcs            " u5!() ", " u5!() ", " u5!()),
        Q!("    adcs            " u6!() ", " u6!() ", " u6!()),
        Q!("    adcs            " u7!() ", " u7!() ", " u7!()),
        Q!("    adcs            " u8!() ", " u8!() ", " u8!()),
        Q!("    adcs            " u9!() ", " u9!() ", " u9!()),
        Q!("    adcs            " u10!() ", " u10!() ", " u10!()),
        Q!("    adcs            " u11!() ", " u11!() ", " u11!()),
        Q!("    adcs            " u12!() ", " u12!() ", " u12!()),
        Q!("    adcs            " u13!() ", " u13!() ", " u13!()),
        Q!("    adcs            " u14!() ", " u14!() ", " u14!()),
        Q!("    cset            " u15!() ", cs"),

        // Add the homogeneous terms 00 + 11 + 22 + 33 + 44 + 55 + 66 + 77

        Q!("    umulh           " l!() ", " a0!() ", " a0!()),
        Q!("    adds            " u1!() ", " u1!() ", " l!()),

        Q!("    mul             " l!() ", " a1!() ", " a1!()),
        Q!("    adcs            " u2!() ", " u2!() ", " l!()),
        Q!("    umulh           " l!() ", " a1!() ", " a1!()),
        Q!("    adcs            " u3!() ", " u3!() ", " l!()),

        Q!("    mul             " l!() ", " a2!() ", " a2!()),
        Q!("    adcs            " u4!() ", " u4!() ", " l!()),
        Q!("    umulh           " l!() ", " a2!() ", " a2!()),
        Q!("    adcs            " u5!() ", " u5!() ", " l!()),

        Q!("    mul             " l!() ", " a3!() ", " a3!()),
        Q!("    adcs            " u6!() ", " u6!() ", " l!()),
        Q!("    umulh           " l!() ", " a3!() ", " a3!()),
        Q!("    adcs            " u7!() ", " u7!() ", " l!()),

        Q!("    mul             " l!() ", " a4!() ", " a4!()),
        Q!("    adcs            " u8!() ", " u8!() ", " l!()),
        Q!("    umulh           " l!() ", " a4!() ", " a4!()),
        Q!("    adcs            " u9!() ", " u9!() ", " l!()),

        Q!("    mul             " l!() ", " a5!() ", " a5!()),
        Q!("    adcs            " u10!() ", " u10!() ", " l!()),
        Q!("    umulh           " l!() ", " a5!() ", " a5!()),
        Q!("    adcs            " u11!() ", " u11!() ", " l!()),

        Q!("    mul             " l!() ", " a6!() ", " a6!()),
        Q!("    adcs            " u12!() ", " u12!() ", " l!()),
        Q!("    umulh           " l!() ", " a6!() ", " a6!()),
        Q!("    adcs            " u13!() ", " u13!() ", " l!()),

        Q!("    mul             " l!() ", " a7!() ", " a7!()),
        Q!("    adcs            " u14!() ", " u14!() ", " l!()),
        Q!("    umulh           " l!() ", " a7!() ", " a7!()),
        Q!("    adc             " u15!() ", " u15!() ", " l!()),

        // Now load in the top digit a8, and immediately double the register

        Q!("    ldr             " a8!() ", [" x!() ", #64]"),
        Q!("    add             " a8!() ", " a8!() ", " a8!()),

        // Add (2 * a8) * [a7;...;a0] into the top of the buffer
        // At the end of the first chain we form u16 = a8 ^ 2.
        // This needs us to shift right the modified a8 again but it saves a
        // register, and the overall performance impact seems slightly positive.

        Q!("    mul             " l!() ", " a8!() ", " a0!()),
        Q!("    adds            " u8!() ", " u8!() ", " l!()),
        Q!("    umulh           " l!() ", " a8!() ", " a0!()),
        Q!("    adcs            " u9!() ", " u9!() ", " l!()),
        Q!("    mul             " l!() ", " a8!() ", " a2!()),
        Q!("    adcs            " u10!() ", " u10!() ", " l!()),
        Q!("    umulh           " l!() ", " a8!() ", " a2!()),
        Q!("    adcs            " u11!() ", " u11!() ", " l!()),
        Q!("    mul             " l!() ", " a8!() ", " a4!()),
        Q!("    adcs            " u12!() ", " u12!() ", " l!()),
        Q!("    umulh           " l!() ", " a8!() ", " a4!()),
        Q!("    adcs            " u13!() ", " u13!() ", " l!()),
        Q!("    mul             " l!() ", " a8!() ", " a6!()),
        Q!("    adcs            " u14!() ", " u14!() ", " l!()),
        Q!("    umulh           " l!() ", " a8!() ", " a6!()),
        Q!("    adcs            " u15!() ", " u15!() ", " l!()),
        Q!("    lsr             " u16!() ", " a8!() ", #1"),
        Q!("    mul             " u16!() ", " u16!() ", " u16!()),
        Q!("    adc             " u16!() ", " u16!() ", xzr"),

        Q!("    mul             " l!() ", " a8!() ", " a1!()),
        Q!("    adds            " u9!() ", " u9!() ", " l!()),
        Q!("    umulh           " l!() ", " a8!() ", " a1!()),
        Q!("    adcs            " u10!() ", " u10!() ", " l!()),
        Q!("    mul             " l!() ", " a8!() ", " a3!()),
        Q!("    adcs            " u11!() ", " u11!() ", " l!()),
        Q!("    umulh           " l!() ", " a8!() ", " a3!()),
        Q!("    adcs            " u12!() ", " u12!() ", " l!()),
        Q!("    mul             " l!() ", " a8!() ", " a5!()),
        Q!("    adcs            " u13!() ", " u13!() ", " l!()),
        Q!("    umulh           " l!() ", " a8!() ", " a5!()),
        Q!("    adcs            " u14!() ", " u14!() ", " l!()),
        Q!("    mul             " l!() ", " a8!() ", " a7!()),
        Q!("    adcs            " u15!() ", " u15!() ", " l!()),
        Q!("    umulh           " l!() ", " a8!() ", " a7!()),
        Q!("    adc             " u16!() ", " u16!() ", " l!()),

        // Finally squeeze in the lowest mul. This didn't need to be involved
        // in the addition chains and moreover lets us re-use u0 == a0

        Q!("    mul             " u0!() ", " a0!() ", " a0!()),

        // Now we have the full product, which we consider as
        // 2^521 * h + l. Form h + l + 1

        Q!("    subs            " "xzr, xzr, xzr"),
        Q!("    extr            " l!() ", " u9!() ", " u8!() ", #9"),
        Q!("    adcs            " u0!() ", " u0!() ", " l!()),
        Q!("    extr            " l!() ", " u10!() ", " u9!() ", #9"),
        Q!("    adcs            " u1!() ", " u1!() ", " l!()),
        Q!("    extr            " l!() ", " u11!() ", " u10!() ", #9"),
        Q!("    adcs            " u2!() ", " u2!() ", " l!()),
        Q!("    extr            " l!() ", " u12!() ", " u11!() ", #9"),
        Q!("    adcs            " u3!() ", " u3!() ", " l!()),
        Q!("    extr            " l!() ", " u13!() ", " u12!() ", #9"),
        Q!("    adcs            " u4!() ", " u4!() ", " l!()),
        Q!("    extr            " l!() ", " u14!() ", " u13!() ", #9"),
        Q!("    adcs            " u5!() ", " u5!() ", " l!()),
        Q!("    extr            " l!() ", " u15!() ", " u14!() ", #9"),
        Q!("    adcs            " u6!() ", " u6!() ", " l!()),
        Q!("    extr            " l!() ", " u16!() ", " u15!() ", #9"),
        Q!("    adcs            " u7!() ", " u7!() ", " l!()),
        Q!("    orr             " u8!() ", " u8!() ", # ~ 0x1FF"),
        Q!("    lsr             " l!() ", " u16!() ", #9"),
        Q!("    adcs            " u8!() ", " u8!() ", " l!()),

        // Now CF is set if h + l + 1 >= 2^521, which means it's already
        // the answer, while if ~CF the answer is h + l so we should subtract
        // 1 (all considered in 521 bits). Hence subtract ~CF and mask.

        Q!("    sbcs            " u0!() ", " u0!() ", xzr"),
        Q!("    sbcs            " u1!() ", " u1!() ", xzr"),
        Q!("    sbcs            " u2!() ", " u2!() ", xzr"),
        Q!("    sbcs            " u3!() ", " u3!() ", xzr"),
        Q!("    sbcs            " u4!() ", " u4!() ", xzr"),
        Q!("    sbcs            " u5!() ", " u5!() ", xzr"),
        Q!("    sbcs            " u6!() ", " u6!() ", xzr"),
        Q!("    sbcs            " u7!() ", " u7!() ", xzr"),
        Q!("    sbc             " u8!() ", " u8!() ", xzr"),
        Q!("    and             " u8!() ", " u8!() ", #0x1FF"),

        // Store back digits of final result

        Q!("    stp             " u0!() ", " u1!() ", [" z!() "]"),
        Q!("    stp             " u2!() ", " u3!() ", [" z!() ", #16]"),
        Q!("    stp             " u4!() ", " u5!() ", [" z!() ", #32]"),
        Q!("    stp             " u6!() ", " u7!() ", [" z!() ", #48]"),
        Q!("    str             " u8!() ", [" z!() ", #64]"),

        // Restore registers and return

        Q!("    ldp             " "x25, x26, [sp], #16"),
        Q!("    ldp             " "x23, x24, [sp], #16"),
        Q!("    ldp             " "x21, x22, [sp], #16"),
        Q!("    ldp             " "x19, x20, [sp], #16"),

        inout("x0") z.as_mut_ptr() => _,
        inout("x1") x.as_ptr() => _,
        // clobbers
        out("x10") _,
        out("x11") _,
        out("x12") _,
        out("x13") _,
        out("x14") _,
        out("x15") _,
        out("x16") _,
        out("x17") _,
        out("x2") _,
        out("x20") _,
        out("x21") _,
        out("x22") _,
        out("x23") _,
        out("x24") _,
        out("x25") _,
        out("x26") _,
        out("x3") _,
        out("x4") _,
        out("x5") _,
        out("x6") _,
        out("x7") _,
        out("x8") _,
        out("x9") _,
            )
    };
}
