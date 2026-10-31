// generated source. do not edit.
#![allow(non_upper_case_globals, unused_macros, unused_imports)]
use crate::low::macros::*;

// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

// ----------------------------------------------------------------------------
// Add modulo p_521, z := (x + y) mod p_521, assuming x and y reduced
// Inputs x[9], y[9]; output z[9]
//
//    extern void bignum_add_p521(uint64_t z[static 9], const uint64_t x[static 9],
//                                const uint64_t y[static 9]);
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
macro_rules! h {
    () => {
        "x3"
    };
}
macro_rules! l {
    () => {
        "x4"
    };
}
macro_rules! d0 {
    () => {
        "x5"
    };
}
macro_rules! d1 {
    () => {
        "x6"
    };
}
macro_rules! d2 {
    () => {
        "x7"
    };
}
macro_rules! d3 {
    () => {
        "x8"
    };
}
macro_rules! d4 {
    () => {
        "x9"
    };
}
macro_rules! d5 {
    () => {
        "x10"
    };
}
macro_rules! d6 {
    () => {
        "x11"
    };
}
macro_rules! d7 {
    () => {
        "x12"
    };
}
macro_rules! d8 {
    () => {
        "x13"
    };
}

/// Add modulo p_521, z := (x + y) mod p_521, assuming x and y reduced
///
/// Inputs x[9], y[9]; output z[9]
pub(crate) fn bignum_add_p521(z: &mut [u64; 9], x: &[u64; 9], y: &[u64; 9]) {
    // SAFETY: inline assembly. see [crate::low::inline_assembly_safety] for safety info.
    unsafe {
        core::arch::asm!(

        // Force carry-in to get s = [d8;d7;d6;d5;d4;d3;d2;d1;d0] = x + y + 1.
        // We ignore the carry-out, assuming inputs are reduced so there is none.

        Q!("    subs            " "xzr, xzr, xzr"),
        Q!("    ldp             " d0!() ", " d1!() ", [" x!() "]"),
        Q!("    ldp             " l!() ", " h!() ", [" y!() "]"),
        Q!("    adcs            " d0!() ", " d0!() ", " l!()),
        Q!("    adcs            " d1!() ", " d1!() ", " h!()),
        Q!("    ldp             " d2!() ", " d3!() ", [" x!() ", #16]"),
        Q!("    ldp             " l!() ", " h!() ", [" y!() ", #16]"),
        Q!("    adcs            " d2!() ", " d2!() ", " l!()),
        Q!("    adcs            " d3!() ", " d3!() ", " h!()),
        Q!("    ldp             " d4!() ", " d5!() ", [" x!() ", #32]"),
        Q!("    ldp             " l!() ", " h!() ", [" y!() ", #32]"),
        Q!("    adcs            " d4!() ", " d4!() ", " l!()),
        Q!("    adcs            " d5!() ", " d5!() ", " h!()),
        Q!("    ldp             " d6!() ", " d7!() ", [" x!() ", #48]"),
        Q!("    ldp             " l!() ", " h!() ", [" y!() ", #48]"),
        Q!("    adcs            " d6!() ", " d6!() ", " l!()),
        Q!("    adcs            " d7!() ", " d7!() ", " h!()),
        Q!("    ldr             " d8!() ", [" x!() ", #64]"),
        Q!("    ldr             " l!() ", [" y!() ", #64]"),
        Q!("    adc             " d8!() ", " d8!() ", " l!()),

        // Now x + y >= p_521 <=> s = x + y + 1 >= 2^521
        // Set CF <=> s = x + y + 1 >= 2^521 and make it a mask in l as well

        Q!("    subs            " l!() ", " d8!() ", #512"),
        Q!("    csetm           " l!() ", cs"),

        // Now if CF is set (and l is all 1s), we want (x + y) - p_521 = s - 2^521
        // while otherwise we want x + y = s - 1 (from existing CF, which is nice)

        Q!("    sbcs            " d0!() ", " d0!() ", xzr"),
        Q!("    and             " l!() ", " l!() ", #512"),
        Q!("    sbcs            " d1!() ", " d1!() ", xzr"),
        Q!("    sbcs            " d2!() ", " d2!() ", xzr"),
        Q!("    sbcs            " d3!() ", " d3!() ", xzr"),
        Q!("    sbcs            " d4!() ", " d4!() ", xzr"),
        Q!("    sbcs            " d5!() ", " d5!() ", xzr"),
        Q!("    sbcs            " d6!() ", " d6!() ", xzr"),
        Q!("    sbcs            " d7!() ", " d7!() ", xzr"),
        Q!("    sbc             " d8!() ", " d8!() ", " l!()),

        // Store the result

        Q!("    stp             " d0!() ", " d1!() ", [" z!() "]"),
        Q!("    stp             " d2!() ", " d3!() ", [" z!() ", #16]"),
        Q!("    stp             " d4!() ", " d5!() ", [" z!() ", #32]"),
        Q!("    stp             " d6!() ", " d7!() ", [" z!() ", #48]"),
        Q!("    str             " d8!() ", [" z!() ", #64]"),

        inout("x0") z.as_mut_ptr() => _,
        inout("x1") x.as_ptr() => _,
        inout("x2") y.as_ptr() => _,
        // clobbers
        out("x10") _,
        out("x11") _,
        out("x12") _,
        out("x13") _,
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
