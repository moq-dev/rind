// generated source. do not edit.
#![allow(non_upper_case_globals, unused_macros, unused_imports)]
use crate::low::macros::*;

// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

// ----------------------------------------------------------------------------
// Negate modulo p_521, z := (-x) mod p_521, assuming x reduced
// Input x[9]; output z[9]
//
//    extern void bignum_neg_p521(uint64_t z[static 9], const uint64_t x[static 9]);
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

macro_rules! p {
    () => {
        "x2"
    };
}

macro_rules! d0 {
    () => {
        "x3"
    };
}
macro_rules! d1 {
    () => {
        "x4"
    };
}
macro_rules! d2 {
    () => {
        "x5"
    };
}
macro_rules! d3 {
    () => {
        "x6"
    };
}
macro_rules! d4 {
    () => {
        "x7"
    };
}
macro_rules! d5 {
    () => {
        "x8"
    };
}
macro_rules! d6 {
    () => {
        "x9"
    };
}
macro_rules! d7 {
    () => {
        "x10"
    };
}
macro_rules! d8 {
    () => {
        "x11"
    };
}

/// Negate modulo p_521, z := (-x) mod p_521, assuming x reduced
///
/// Input x[9]; output z[9]
pub(crate) fn bignum_neg_p521(z: &mut [u64; 9], x: &[u64; 9]) {
    // SAFETY: inline assembly. see [crate::low::inline_assembly_safety] for safety info.
    unsafe {
        core::arch::asm!(

        // Load the 9 digits of x and generate p = the OR of them all

        Q!("    ldp             " d0!() ", " d1!() ", [" x!() "]"),
        Q!("    orr             " d6!() ", " d0!() ", " d1!()),
        Q!("    ldp             " d2!() ", " d3!() ", [" x!() ", #16]"),
        Q!("    orr             " d7!() ", " d2!() ", " d3!()),
        Q!("    orr             " p!() ", " d6!() ", " d7!()),
        Q!("    ldp             " d4!() ", " d5!() ", [" x!() ", #32]"),
        Q!("    orr             " d8!() ", " d4!() ", " d5!()),
        Q!("    orr             " p!() ", " p!() ", " d8!()),
        Q!("    ldp             " d6!() ", " d7!() ", [" x!() ", #48]"),
        Q!("    orr             " d8!() ", " d6!() ", " d7!()),
        Q!("    orr             " p!() ", " p!() ", " d8!()),
        Q!("    ldr             " d8!() ", [" x!() ", #64]"),
        Q!("    orr             " p!() ", " p!() ", " d8!()),

        // Turn p into a bitmask for "input is nonzero", so that we avoid doing
        // -0 = p_521 and hence maintain strict modular reduction

        Q!("    cmp             " p!() ", #0"),
        Q!("    csetm           " p!() ", ne"),

        // Since p_521 is all 1s, the subtraction is just an exclusive-or with p
        // to give an optional inversion, with a slight fiddle for the top digit.

        Q!("    eor             " d0!() ", " d0!() ", " p!()),
        Q!("    eor             " d1!() ", " d1!() ", " p!()),
        Q!("    eor             " d2!() ", " d2!() ", " p!()),
        Q!("    eor             " d3!() ", " d3!() ", " p!()),
        Q!("    eor             " d4!() ", " d4!() ", " p!()),
        Q!("    eor             " d5!() ", " d5!() ", " p!()),
        Q!("    eor             " d6!() ", " d6!() ", " p!()),
        Q!("    eor             " d7!() ", " d7!() ", " p!()),
        Q!("    and             " p!() ", " p!() ", #0x1FF"),
        Q!("    eor             " d8!() ", " d8!() ", " p!()),

        // Write back the result and return

        Q!("    stp             " d0!() ", " d1!() ", [" z!() "]"),
        Q!("    stp             " d2!() ", " d3!() ", [" z!() ", #16]"),
        Q!("    stp             " d4!() ", " d5!() ", [" z!() ", #32]"),
        Q!("    stp             " d6!() ", " d7!() ", [" z!() ", #48]"),
        Q!("    str             " d8!() ", [" z!() ", #64]"),
        inout("x0") z.as_mut_ptr() => _,
        inout("x1") x.as_ptr() => _,
        // clobbers
        out("x10") _,
        out("x11") _,
        out("x2") _,
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
