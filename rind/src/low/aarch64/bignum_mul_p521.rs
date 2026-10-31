// generated source. do not edit.
#![allow(non_upper_case_globals, unused_macros, unused_imports)]
use crate::low::macros::*;

// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

// ----------------------------------------------------------------------------
// Multiply modulo p_521, z := (x * y) mod p_521, assuming x and y reduced
// Inputs x[9], y[9]; output z[9]
//
//    extern void bignum_mul_p521_alt(uint64_t z[static 9],
//                                    const uint64_t x[static 9],
//                                    const uint64_t y[static 9]);
//
// Standard ARM ABI: X0 = z, X1 = x, X2 = y
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
macro_rules! y {
    () => {
        "x2"
    };
}

// These are repeated mod 2 as we load paris of inputs

macro_rules! a0 {
    () => {
        "x3"
    };
}
macro_rules! a1 {
    () => {
        "x4"
    };
}
macro_rules! a2 {
    () => {
        "x3"
    };
}
macro_rules! a3 {
    () => {
        "x4"
    };
}
macro_rules! a4 {
    () => {
        "x3"
    };
}
macro_rules! a5 {
    () => {
        "x4"
    };
}
macro_rules! a6 {
    () => {
        "x3"
    };
}
macro_rules! a7 {
    () => {
        "x4"
    };
}
macro_rules! a8 {
    () => {
        "x3"
    };
}

macro_rules! b0 {
    () => {
        "x5"
    };
}
macro_rules! b1 {
    () => {
        "x6"
    };
}
macro_rules! b2 {
    () => {
        "x7"
    };
}
macro_rules! b3 {
    () => {
        "x8"
    };
}
macro_rules! b4 {
    () => {
        "x9"
    };
}
macro_rules! b5 {
    () => {
        "x10"
    };
}
macro_rules! b6 {
    () => {
        "x11"
    };
}
macro_rules! b7 {
    () => {
        "x12"
    };
}
macro_rules! b8 {
    () => {
        "x13"
    };
}

macro_rules! t {
    () => {
        "x14"
    };
}

// These repeat mod 11 as we stash some intermediate results in the
// output buffer.

macro_rules! u0 {
    () => {
        "x15"
    };
}
macro_rules! u1 {
    () => {
        "x16"
    };
}
macro_rules! u2 {
    () => {
        "x17"
    };
}
macro_rules! u3 {
    () => {
        "x19"
    };
}
macro_rules! u4 {
    () => {
        "x20"
    };
}
macro_rules! u5 {
    () => {
        "x21"
    };
}
macro_rules! u6 {
    () => {
        "x22"
    };
}
macro_rules! u7 {
    () => {
        "x23"
    };
}
macro_rules! u8 {
    () => {
        "x24"
    };
}
macro_rules! u9 {
    () => {
        "x25"
    };
}
macro_rules! u10 {
    () => {
        "x26"
    };
}
macro_rules! u11 {
    () => {
        "x15"
    };
}
macro_rules! u12 {
    () => {
        "x16"
    };
}
macro_rules! u13 {
    () => {
        "x17"
    };
}
macro_rules! u14 {
    () => {
        "x19"
    };
}
macro_rules! u15 {
    () => {
        "x20"
    };
}
macro_rules! u16 {
    () => {
        "x21"
    };
}

/// Multiply modulo p_521, z := (x * y) mod p_521, assuming x and y reduced
///
/// Inputs x[9], y[9]; output z[9]
pub(crate) fn bignum_mul_p521(z: &mut [u64; 9], x: &[u64; 9], y: &[u64; 9]) {
    // SAFETY: inline assembly. see [crate::low::inline_assembly_safety] for safety info.
    unsafe {
        core::arch::asm!(

        // Save more registers and make temporary space on stack

        Q!("    stp             " "x19, x20, [sp, #-16] !"),
        Q!("    stp             " "x21, x22, [sp, #-16] !"),
        Q!("    stp             " "x23, x24, [sp, #-16] !"),
        Q!("    stp             " "x25, x26, [sp, #-16] !"),
        Q!("    sub             " "sp, sp, # (64 + 0)"),

        // Load operands and set up row 0 = [u9;...;u0] = a0 * [b8;...;b0]

        Q!("    ldp             " a0!() ", " a1!() ", [" x!() "]"),
        Q!("    ldp             " b0!() ", " b1!() ", [" y!() "]"),

        Q!("    mul             " u0!() ", " a0!() ", " b0!()),
        Q!("    umulh           " u1!() ", " a0!() ", " b0!()),
        Q!("    mul             " t!() ", " a0!() ", " b1!()),
        Q!("    umulh           " u2!() ", " a0!() ", " b1!()),
        Q!("    adds            " u1!() ", " u1!() ", " t!()),

        Q!("    ldp             " b2!() ", " b3!() ", [" y!() ", #16]"),

        Q!("    mul             " t!() ", " a0!() ", " b2!()),
        Q!("    umulh           " u3!() ", " a0!() ", " b2!()),
        Q!("    adcs            " u2!() ", " u2!() ", " t!()),

        Q!("    mul             " t!() ", " a0!() ", " b3!()),
        Q!("    umulh           " u4!() ", " a0!() ", " b3!()),
        Q!("    adcs            " u3!() ", " u3!() ", " t!()),

        Q!("    ldp             " b4!() ", " b5!() ", [" y!() ", #32]"),

        Q!("    mul             " t!() ", " a0!() ", " b4!()),
        Q!("    umulh           " u5!() ", " a0!() ", " b4!()),
        Q!("    adcs            " u4!() ", " u4!() ", " t!()),

        Q!("    mul             " t!() ", " a0!() ", " b5!()),
        Q!("    umulh           " u6!() ", " a0!() ", " b5!()),
        Q!("    adcs            " u5!() ", " u5!() ", " t!()),

        Q!("    ldp             " b6!() ", " b7!() ", [" y!() ", #48]"),

        Q!("    mul             " t!() ", " a0!() ", " b6!()),
        Q!("    umulh           " u7!() ", " a0!() ", " b6!()),
        Q!("    adcs            " u6!() ", " u6!() ", " t!()),

        Q!("    ldr             " b8!() ", [" y!() ", #64]"),

        Q!("    mul             " t!() ", " a0!() ", " b7!()),
        Q!("    umulh           " u8!() ", " a0!() ", " b7!()),
        Q!("    adcs            " u7!() ", " u7!() ", " t!()),

        Q!("    mul             " t!() ", " a0!() ", " b8!()),
        Q!("    umulh           " u9!() ", " a0!() ", " b8!()),
        Q!("    adcs            " u8!() ", " u8!() ", " t!()),

        Q!("    adc             " u9!() ", " u9!() ", xzr"),

        // Row 1 = [u10;...;u0] = [a1;a0] * [b8;...;b0]

        Q!("    mul             " t!() ", " a1!() ", " b0!()),
        Q!("    adds            " u1!() ", " u1!() ", " t!()),
        Q!("    mul             " t!() ", " a1!() ", " b1!()),
        Q!("    adcs            " u2!() ", " u2!() ", " t!()),
        Q!("    mul             " t!() ", " a1!() ", " b2!()),
        Q!("    adcs            " u3!() ", " u3!() ", " t!()),
        Q!("    mul             " t!() ", " a1!() ", " b3!()),
        Q!("    adcs            " u4!() ", " u4!() ", " t!()),
        Q!("    mul             " t!() ", " a1!() ", " b4!()),
        Q!("    adcs            " u5!() ", " u5!() ", " t!()),
        Q!("    mul             " t!() ", " a1!() ", " b5!()),
        Q!("    adcs            " u6!() ", " u6!() ", " t!()),
        Q!("    mul             " t!() ", " a1!() ", " b6!()),
        Q!("    adcs            " u7!() ", " u7!() ", " t!()),
        Q!("    mul             " t!() ", " a1!() ", " b7!()),
        Q!("    adcs            " u8!() ", " u8!() ", " t!()),
        Q!("    mul             " t!() ", " a1!() ", " b8!()),
        Q!("    adcs            " u9!() ", " u9!() ", " t!()),
        Q!("    cset            " u10!() ", cs"),

        Q!("    umulh           " t!() ", " a1!() ", " b0!()),
        Q!("    adds            " u2!() ", " u2!() ", " t!()),
        Q!("    umulh           " t!() ", " a1!() ", " b1!()),
        Q!("    adcs            " u3!() ", " u3!() ", " t!()),
        Q!("    umulh           " t!() ", " a1!() ", " b2!()),
        Q!("    adcs            " u4!() ", " u4!() ", " t!()),
        Q!("    umulh           " t!() ", " a1!() ", " b3!()),
        Q!("    adcs            " u5!() ", " u5!() ", " t!()),
        Q!("    umulh           " t!() ", " a1!() ", " b4!()),
        Q!("    adcs            " u6!() ", " u6!() ", " t!()),
        Q!("    umulh           " t!() ", " a1!() ", " b5!()),
        Q!("    adcs            " u7!() ", " u7!() ", " t!()),
        Q!("    umulh           " t!() ", " a1!() ", " b6!()),
        Q!("    adcs            " u8!() ", " u8!() ", " t!()),
        Q!("    umulh           " t!() ", " a1!() ", " b7!()),
        Q!("    adcs            " u9!() ", " u9!() ", " t!()),
        Q!("    umulh           " t!() ", " a1!() ", " b8!()),
        Q!("    adc             " u10!() ", " u10!() ", " t!()),

        Q!("    stp             " u0!() ", " u1!() ", [sp]"),

        // Row 2 = [u11;...;u0] = [a2;a1;a0] * [b8;...;b0]

        Q!("    ldp             " a2!() ", " a3!() ", [" x!() ", #16]"),

        Q!("    mul             " t!() ", " a2!() ", " b0!()),
        Q!("    adds            " u2!() ", " u2!() ", " t!()),
        Q!("    mul             " t!() ", " a2!() ", " b1!()),
        Q!("    adcs            " u3!() ", " u3!() ", " t!()),
        Q!("    mul             " t!() ", " a2!() ", " b2!()),
        Q!("    adcs            " u4!() ", " u4!() ", " t!()),
        Q!("    mul             " t!() ", " a2!() ", " b3!()),
        Q!("    adcs            " u5!() ", " u5!() ", " t!()),
        Q!("    mul             " t!() ", " a2!() ", " b4!()),
        Q!("    adcs            " u6!() ", " u6!() ", " t!()),
        Q!("    mul             " t!() ", " a2!() ", " b5!()),
        Q!("    adcs            " u7!() ", " u7!() ", " t!()),
        Q!("    mul             " t!() ", " a2!() ", " b6!()),
        Q!("    adcs            " u8!() ", " u8!() ", " t!()),
        Q!("    mul             " t!() ", " a2!() ", " b7!()),
        Q!("    adcs            " u9!() ", " u9!() ", " t!()),
        Q!("    mul             " t!() ", " a2!() ", " b8!()),
        Q!("    adcs            " u10!() ", " u10!() ", " t!()),
        Q!("    cset            " u11!() ", cs"),

        Q!("    umulh           " t!() ", " a2!() ", " b0!()),
        Q!("    adds            " u3!() ", " u3!() ", " t!()),
        Q!("    umulh           " t!() ", " a2!() ", " b1!()),
        Q!("    adcs            " u4!() ", " u4!() ", " t!()),
        Q!("    umulh           " t!() ", " a2!() ", " b2!()),
        Q!("    adcs            " u5!() ", " u5!() ", " t!()),
        Q!("    umulh           " t!() ", " a2!() ", " b3!()),
        Q!("    adcs            " u6!() ", " u6!() ", " t!()),
        Q!("    umulh           " t!() ", " a2!() ", " b4!()),
        Q!("    adcs            " u7!() ", " u7!() ", " t!()),
        Q!("    umulh           " t!() ", " a2!() ", " b5!()),
        Q!("    adcs            " u8!() ", " u8!() ", " t!()),
        Q!("    umulh           " t!() ", " a2!() ", " b6!()),
        Q!("    adcs            " u9!() ", " u9!() ", " t!()),
        Q!("    umulh           " t!() ", " a2!() ", " b7!()),
        Q!("    adcs            " u10!() ", " u10!() ", " t!()),
        Q!("    umulh           " t!() ", " a2!() ", " b8!()),
        Q!("    adc             " u11!() ", " u11!() ", " t!()),

        // Row 3 = [u12;...;u0] = [a3;a2;a1;a0] * [b8;...;b0]

        Q!("    mul             " t!() ", " a3!() ", " b0!()),
        Q!("    adds            " u3!() ", " u3!() ", " t!()),
        Q!("    mul             " t!() ", " a3!() ", " b1!()),
        Q!("    adcs            " u4!() ", " u4!() ", " t!()),
        Q!("    mul             " t!() ", " a3!() ", " b2!()),
        Q!("    adcs            " u5!() ", " u5!() ", " t!()),
        Q!("    mul             " t!() ", " a3!() ", " b3!()),
        Q!("    adcs            " u6!() ", " u6!() ", " t!()),
        Q!("    mul             " t!() ", " a3!() ", " b4!()),
        Q!("    adcs            " u7!() ", " u7!() ", " t!()),
        Q!("    mul             " t!() ", " a3!() ", " b5!()),
        Q!("    adcs            " u8!() ", " u8!() ", " t!()),
        Q!("    mul             " t!() ", " a3!() ", " b6!()),
        Q!("    adcs            " u9!() ", " u9!() ", " t!()),
        Q!("    mul             " t!() ", " a3!() ", " b7!()),
        Q!("    adcs            " u10!() ", " u10!() ", " t!()),
        Q!("    mul             " t!() ", " a3!() ", " b8!()),
        Q!("    adcs            " u11!() ", " u11!() ", " t!()),
        Q!("    cset            " u12!() ", cs"),

        Q!("    umulh           " t!() ", " a3!() ", " b0!()),
        Q!("    adds            " u4!() ", " u4!() ", " t!()),
        Q!("    umulh           " t!() ", " a3!() ", " b1!()),
        Q!("    adcs            " u5!() ", " u5!() ", " t!()),
        Q!("    umulh           " t!() ", " a3!() ", " b2!()),
        Q!("    adcs            " u6!() ", " u6!() ", " t!()),
        Q!("    umulh           " t!() ", " a3!() ", " b3!()),
        Q!("    adcs            " u7!() ", " u7!() ", " t!()),
        Q!("    umulh           " t!() ", " a3!() ", " b4!()),
        Q!("    adcs            " u8!() ", " u8!() ", " t!()),
        Q!("    umulh           " t!() ", " a3!() ", " b5!()),
        Q!("    adcs            " u9!() ", " u9!() ", " t!()),
        Q!("    umulh           " t!() ", " a3!() ", " b6!()),
        Q!("    adcs            " u10!() ", " u10!() ", " t!()),
        Q!("    umulh           " t!() ", " a3!() ", " b7!()),
        Q!("    adcs            " u11!() ", " u11!() ", " t!()),
        Q!("    umulh           " t!() ", " a3!() ", " b8!()),
        Q!("    adc             " u12!() ", " u12!() ", " t!()),

        Q!("    stp             " u2!() ", " u3!() ", [sp, #16]"),

        // Row 4 = [u13;...;u0] = [a4;a3;a2;a1;a0] * [b8;...;b0]

        Q!("    ldp             " a4!() ", " a5!() ", [" x!() ", #32]"),

        Q!("    mul             " t!() ", " a4!() ", " b0!()),
        Q!("    adds            " u4!() ", " u4!() ", " t!()),
        Q!("    mul             " t!() ", " a4!() ", " b1!()),
        Q!("    adcs            " u5!() ", " u5!() ", " t!()),
        Q!("    mul             " t!() ", " a4!() ", " b2!()),
        Q!("    adcs            " u6!() ", " u6!() ", " t!()),
        Q!("    mul             " t!() ", " a4!() ", " b3!()),
        Q!("    adcs            " u7!() ", " u7!() ", " t!()),
        Q!("    mul             " t!() ", " a4!() ", " b4!()),
        Q!("    adcs            " u8!() ", " u8!() ", " t!()),
        Q!("    mul             " t!() ", " a4!() ", " b5!()),
        Q!("    adcs            " u9!() ", " u9!() ", " t!()),
        Q!("    mul             " t!() ", " a4!() ", " b6!()),
        Q!("    adcs            " u10!() ", " u10!() ", " t!()),
        Q!("    mul             " t!() ", " a4!() ", " b7!()),
        Q!("    adcs            " u11!() ", " u11!() ", " t!()),
        Q!("    mul             " t!() ", " a4!() ", " b8!()),
        Q!("    adcs            " u12!() ", " u12!() ", " t!()),
        Q!("    cset            " u13!() ", cs"),

        Q!("    umulh           " t!() ", " a4!() ", " b0!()),
        Q!("    adds            " u5!() ", " u5!() ", " t!()),
        Q!("    umulh           " t!() ", " a4!() ", " b1!()),
        Q!("    adcs            " u6!() ", " u6!() ", " t!()),
        Q!("    umulh           " t!() ", " a4!() ", " b2!()),
        Q!("    adcs            " u7!() ", " u7!() ", " t!()),
        Q!("    umulh           " t!() ", " a4!() ", " b3!()),
        Q!("    adcs            " u8!() ", " u8!() ", " t!()),
        Q!("    umulh           " t!() ", " a4!() ", " b4!()),
        Q!("    adcs            " u9!() ", " u9!() ", " t!()),
        Q!("    umulh           " t!() ", " a4!() ", " b5!()),
        Q!("    adcs            " u10!() ", " u10!() ", " t!()),
        Q!("    umulh           " t!() ", " a4!() ", " b6!()),
        Q!("    adcs            " u11!() ", " u11!() ", " t!()),
        Q!("    umulh           " t!() ", " a4!() ", " b7!()),
        Q!("    adcs            " u12!() ", " u12!() ", " t!()),
        Q!("    umulh           " t!() ", " a4!() ", " b8!()),
        Q!("    adc             " u13!() ", " u13!() ", " t!()),

        // Row 5 = [u14;...;u0] = [a5;a4;a3;a2;a1;a0] * [b8;...;b0]

        Q!("    mul             " t!() ", " a5!() ", " b0!()),
        Q!("    adds            " u5!() ", " u5!() ", " t!()),
        Q!("    mul             " t!() ", " a5!() ", " b1!()),
        Q!("    adcs            " u6!() ", " u6!() ", " t!()),
        Q!("    mul             " t!() ", " a5!() ", " b2!()),
        Q!("    adcs            " u7!() ", " u7!() ", " t!()),
        Q!("    mul             " t!() ", " a5!() ", " b3!()),
        Q!("    adcs            " u8!() ", " u8!() ", " t!()),
        Q!("    mul             " t!() ", " a5!() ", " b4!()),
        Q!("    adcs            " u9!() ", " u9!() ", " t!()),
        Q!("    mul             " t!() ", " a5!() ", " b5!()),
        Q!("    adcs            " u10!() ", " u10!() ", " t!()),
        Q!("    mul             " t!() ", " a5!() ", " b6!()),
        Q!("    adcs            " u11!() ", " u11!() ", " t!()),
        Q!("    mul             " t!() ", " a5!() ", " b7!()),
        Q!("    adcs            " u12!() ", " u12!() ", " t!()),
        Q!("    mul             " t!() ", " a5!() ", " b8!()),
        Q!("    adcs            " u13!() ", " u13!() ", " t!()),
        Q!("    cset            " u14!() ", cs"),

        Q!("    umulh           " t!() ", " a5!() ", " b0!()),
        Q!("    adds            " u6!() ", " u6!() ", " t!()),
        Q!("    umulh           " t!() ", " a5!() ", " b1!()),
        Q!("    adcs            " u7!() ", " u7!() ", " t!()),
        Q!("    umulh           " t!() ", " a5!() ", " b2!()),
        Q!("    adcs            " u8!() ", " u8!() ", " t!()),
        Q!("    umulh           " t!() ", " a5!() ", " b3!()),
        Q!("    adcs            " u9!() ", " u9!() ", " t!()),
        Q!("    umulh           " t!() ", " a5!() ", " b4!()),
        Q!("    adcs            " u10!() ", " u10!() ", " t!()),
        Q!("    umulh           " t!() ", " a5!() ", " b5!()),
        Q!("    adcs            " u11!() ", " u11!() ", " t!()),
        Q!("    umulh           " t!() ", " a5!() ", " b6!()),
        Q!("    adcs            " u12!() ", " u12!() ", " t!()),
        Q!("    umulh           " t!() ", " a5!() ", " b7!()),
        Q!("    adcs            " u13!() ", " u13!() ", " t!()),
        Q!("    umulh           " t!() ", " a5!() ", " b8!()),
        Q!("    adc             " u14!() ", " u14!() ", " t!()),

        Q!("    stp             " u4!() ", " u5!() ", [sp, #32]"),

        // Row 6 = [u15;...;u0] = [a6;a5;a4;a3;a2;a1;a0] * [b8;...;b0]

        Q!("    ldp             " a6!() ", " a7!() ", [" x!() ", #48]"),

        Q!("    mul             " t!() ", " a6!() ", " b0!()),
        Q!("    adds            " u6!() ", " u6!() ", " t!()),
        Q!("    mul             " t!() ", " a6!() ", " b1!()),
        Q!("    adcs            " u7!() ", " u7!() ", " t!()),
        Q!("    mul             " t!() ", " a6!() ", " b2!()),
        Q!("    adcs            " u8!() ", " u8!() ", " t!()),
        Q!("    mul             " t!() ", " a6!() ", " b3!()),
        Q!("    adcs            " u9!() ", " u9!() ", " t!()),
        Q!("    mul             " t!() ", " a6!() ", " b4!()),
        Q!("    adcs            " u10!() ", " u10!() ", " t!()),
        Q!("    mul             " t!() ", " a6!() ", " b5!()),
        Q!("    adcs            " u11!() ", " u11!() ", " t!()),
        Q!("    mul             " t!() ", " a6!() ", " b6!()),
        Q!("    adcs            " u12!() ", " u12!() ", " t!()),
        Q!("    mul             " t!() ", " a6!() ", " b7!()),
        Q!("    adcs            " u13!() ", " u13!() ", " t!()),
        Q!("    mul             " t!() ", " a6!() ", " b8!()),
        Q!("    adcs            " u14!() ", " u14!() ", " t!()),
        Q!("    cset            " u15!() ", cs"),

        Q!("    umulh           " t!() ", " a6!() ", " b0!()),
        Q!("    adds            " u7!() ", " u7!() ", " t!()),
        Q!("    umulh           " t!() ", " a6!() ", " b1!()),
        Q!("    adcs            " u8!() ", " u8!() ", " t!()),
        Q!("    umulh           " t!() ", " a6!() ", " b2!()),
        Q!("    adcs            " u9!() ", " u9!() ", " t!()),
        Q!("    umulh           " t!() ", " a6!() ", " b3!()),
        Q!("    adcs            " u10!() ", " u10!() ", " t!()),
        Q!("    umulh           " t!() ", " a6!() ", " b4!()),
        Q!("    adcs            " u11!() ", " u11!() ", " t!()),
        Q!("    umulh           " t!() ", " a6!() ", " b5!()),
        Q!("    adcs            " u12!() ", " u12!() ", " t!()),
        Q!("    umulh           " t!() ", " a6!() ", " b6!()),
        Q!("    adcs            " u13!() ", " u13!() ", " t!()),
        Q!("    umulh           " t!() ", " a6!() ", " b7!()),
        Q!("    adcs            " u14!() ", " u14!() ", " t!()),
        Q!("    umulh           " t!() ", " a6!() ", " b8!()),
        Q!("    adc             " u15!() ", " u15!() ", " t!()),

        // Row 7 = [u16;...;u0] = [a7;a6;a5;a4;a3;a2;a1;a0] * [b8;...;b0]

        Q!("    mul             " t!() ", " a7!() ", " b0!()),
        Q!("    adds            " u7!() ", " u7!() ", " t!()),
        Q!("    mul             " t!() ", " a7!() ", " b1!()),
        Q!("    adcs            " u8!() ", " u8!() ", " t!()),
        Q!("    mul             " t!() ", " a7!() ", " b2!()),
        Q!("    adcs            " u9!() ", " u9!() ", " t!()),
        Q!("    mul             " t!() ", " a7!() ", " b3!()),
        Q!("    adcs            " u10!() ", " u10!() ", " t!()),
        Q!("    mul             " t!() ", " a7!() ", " b4!()),
        Q!("    adcs            " u11!() ", " u11!() ", " t!()),
        Q!("    mul             " t!() ", " a7!() ", " b5!()),
        Q!("    adcs            " u12!() ", " u12!() ", " t!()),
        Q!("    mul             " t!() ", " a7!() ", " b6!()),
        Q!("    adcs            " u13!() ", " u13!() ", " t!()),
        Q!("    mul             " t!() ", " a7!() ", " b7!()),
        Q!("    adcs            " u14!() ", " u14!() ", " t!()),
        Q!("    mul             " t!() ", " a7!() ", " b8!()),
        Q!("    adcs            " u15!() ", " u15!() ", " t!()),
        Q!("    cset            " u16!() ", cs"),

        Q!("    umulh           " t!() ", " a7!() ", " b0!()),
        Q!("    adds            " u8!() ", " u8!() ", " t!()),
        Q!("    umulh           " t!() ", " a7!() ", " b1!()),
        Q!("    adcs            " u9!() ", " u9!() ", " t!()),
        Q!("    umulh           " t!() ", " a7!() ", " b2!()),
        Q!("    adcs            " u10!() ", " u10!() ", " t!()),
        Q!("    umulh           " t!() ", " a7!() ", " b3!()),
        Q!("    adcs            " u11!() ", " u11!() ", " t!()),
        Q!("    umulh           " t!() ", " a7!() ", " b4!()),
        Q!("    adcs            " u12!() ", " u12!() ", " t!()),
        Q!("    umulh           " t!() ", " a7!() ", " b5!()),
        Q!("    adcs            " u13!() ", " u13!() ", " t!()),
        Q!("    umulh           " t!() ", " a7!() ", " b6!()),
        Q!("    adcs            " u14!() ", " u14!() ", " t!()),
        Q!("    umulh           " t!() ", " a7!() ", " b7!()),
        Q!("    adcs            " u15!() ", " u15!() ", " t!()),
        Q!("    umulh           " t!() ", " a7!() ", " b8!()),
        Q!("    adc             " u16!() ", " u16!() ", " t!()),

        Q!("    stp             " u6!() ", " u7!() ", [sp, #48]"),

        // Row 8 = [u16;...;u0] = [a8;a7;a6;a5;a4;a3;a2;a1;a0] * [b8;...;b0]

        Q!("    ldr             " a8!() ", [" x!() ", #64]"),

        Q!("    mul             " t!() ", " a8!() ", " b0!()),
        Q!("    adds            " u8!() ", " u8!() ", " t!()),
        Q!("    mul             " t!() ", " a8!() ", " b1!()),
        Q!("    adcs            " u9!() ", " u9!() ", " t!()),
        Q!("    mul             " t!() ", " a8!() ", " b2!()),
        Q!("    adcs            " u10!() ", " u10!() ", " t!()),
        Q!("    mul             " t!() ", " a8!() ", " b3!()),
        Q!("    adcs            " u11!() ", " u11!() ", " t!()),
        Q!("    mul             " t!() ", " a8!() ", " b4!()),
        Q!("    adcs            " u12!() ", " u12!() ", " t!()),
        Q!("    mul             " t!() ", " a8!() ", " b5!()),
        Q!("    adcs            " u13!() ", " u13!() ", " t!()),
        Q!("    mul             " t!() ", " a8!() ", " b6!()),
        Q!("    adcs            " u14!() ", " u14!() ", " t!()),
        Q!("    mul             " t!() ", " a8!() ", " b7!()),
        Q!("    adcs            " u15!() ", " u15!() ", " t!()),
        Q!("    mul             " t!() ", " a8!() ", " b8!()),
        Q!("    adc             " u16!() ", " u16!() ", " t!()),

        Q!("    umulh           " t!() ", " a8!() ", " b0!()),
        Q!("    adds            " u9!() ", " u9!() ", " t!()),
        Q!("    umulh           " t!() ", " a8!() ", " b1!()),
        Q!("    adcs            " u10!() ", " u10!() ", " t!()),
        Q!("    umulh           " t!() ", " a8!() ", " b2!()),
        Q!("    adcs            " u11!() ", " u11!() ", " t!()),
        Q!("    umulh           " t!() ", " a8!() ", " b3!()),
        Q!("    adcs            " u12!() ", " u12!() ", " t!()),
        Q!("    umulh           " t!() ", " a8!() ", " b4!()),
        Q!("    adcs            " u13!() ", " u13!() ", " t!()),
        Q!("    umulh           " t!() ", " a8!() ", " b5!()),
        Q!("    adcs            " u14!() ", " u14!() ", " t!()),
        Q!("    umulh           " t!() ", " a8!() ", " b6!()),
        Q!("    adcs            " u15!() ", " u15!() ", " t!()),
        Q!("    umulh           " t!() ", " a8!() ", " b7!()),
        Q!("    adc             " u16!() ", " u16!() ", " t!()),

        // Now we have the full product, which we consider as
        // 2^521 * h + l. Form h + l + 1

        Q!("    subs            " "xzr, xzr, xzr"),
        Q!("    ldp             " b0!() ", " b1!() ", [sp]"),
        Q!("    extr            " t!() ", " u9!() ", " u8!() ", #9"),
        Q!("    adcs            " b0!() ", " b0!() ", " t!()),
        Q!("    extr            " t!() ", " u10!() ", " u9!() ", #9"),
        Q!("    adcs            " b1!() ", " b1!() ", " t!()),
        Q!("    ldp             " b2!() ", " b3!() ", [sp, #16]"),
        Q!("    extr            " t!() ", " u11!() ", " u10!() ", #9"),
        Q!("    adcs            " b2!() ", " b2!() ", " t!()),
        Q!("    extr            " t!() ", " u12!() ", " u11!() ", #9"),
        Q!("    adcs            " b3!() ", " b3!() ", " t!()),
        Q!("    ldp             " b4!() ", " b5!() ", [sp, #32]"),
        Q!("    extr            " t!() ", " u13!() ", " u12!() ", #9"),
        Q!("    adcs            " b4!() ", " b4!() ", " t!()),
        Q!("    extr            " t!() ", " u14!() ", " u13!() ", #9"),
        Q!("    adcs            " b5!() ", " b5!() ", " t!()),
        Q!("    ldp             " b6!() ", " b7!() ", [sp, #48]"),
        Q!("    extr            " t!() ", " u15!() ", " u14!() ", #9"),
        Q!("    adcs            " b6!() ", " b6!() ", " t!()),
        Q!("    extr            " t!() ", " u16!() ", " u15!() ", #9"),
        Q!("    adcs            " b7!() ", " b7!() ", " t!()),
        Q!("    orr             " b8!() ", " u8!() ", # ~ 0x1FF"),
        Q!("    lsr             " t!() ", " u16!() ", #9"),
        Q!("    adcs            " b8!() ", " b8!() ", " t!()),

        // Now CF is set if h + l + 1 >= 2^521, which means it's already
        // the answer, while if ~CF the answer is h + l so we should subtract
        // 1 (all considered in 521 bits). Hence subtract ~CF and mask.

        Q!("    sbcs            " b0!() ", " b0!() ", xzr"),
        Q!("    sbcs            " b1!() ", " b1!() ", xzr"),
        Q!("    sbcs            " b2!() ", " b2!() ", xzr"),
        Q!("    sbcs            " b3!() ", " b3!() ", xzr"),
        Q!("    sbcs            " b4!() ", " b4!() ", xzr"),
        Q!("    sbcs            " b5!() ", " b5!() ", xzr"),
        Q!("    sbcs            " b6!() ", " b6!() ", xzr"),
        Q!("    sbcs            " b7!() ", " b7!() ", xzr"),
        Q!("    sbc             " b8!() ", " b8!() ", xzr"),
        Q!("    and             " b8!() ", " b8!() ", #0x1FF"),

        // Store back digits of final result

        Q!("    stp             " b0!() ", " b1!() ", [" z!() "]"),
        Q!("    stp             " b2!() ", " b3!() ", [" z!() ", #16]"),
        Q!("    stp             " b4!() ", " b5!() ", [" z!() ", #32]"),
        Q!("    stp             " b6!() ", " b7!() ", [" z!() ", #48]"),
        Q!("    str             " b8!() ", [" z!() ", #64]"),

        // Restore registers

        Q!("    add             " "sp, sp, # (64 + 0)"),
        Q!("    ldp             " "x25, x26, [sp], #16"),
        Q!("    ldp             " "x23, x24, [sp], #16"),
        Q!("    ldp             " "x21, x22, [sp], #16"),
        Q!("    ldp             " "x19, x20, [sp], #16"),

        inout("x0") z.as_mut_ptr() => _,
        inout("x1") x.as_ptr() => _,
        inout("x2") y.as_ptr() => _,
        // clobbers
        out("x10") _,
        out("x11") _,
        out("x12") _,
        out("x13") _,
        out("x14") _,
        out("x15") _,
        out("x16") _,
        out("x17") _,
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
