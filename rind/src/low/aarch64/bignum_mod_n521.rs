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

macro_rules! n0 {
    () => {
        "x2"
    };
}
macro_rules! n1 {
    () => {
        "x3"
    };
}
macro_rules! n2 {
    () => {
        "x4"
    };
}
macro_rules! n3 {
    () => {
        "x5"
    };
}

macro_rules! d0 {
    () => {
        "x6"
    };
}
macro_rules! d1 {
    () => {
        "x7"
    };
}
macro_rules! d2 {
    () => {
        "x8"
    };
}
macro_rules! d3 {
    () => {
        "x9"
    };
}
macro_rules! d4 {
    () => {
        "x10"
    };
}
macro_rules! d5 {
    () => {
        "x11"
    };
}
macro_rules! d6 {
    () => {
        "x12"
    };
}
macro_rules! d7 {
    () => {
        "x13"
    };
}
macro_rules! d8 {
    () => {
        "x14"
    };
}

macro_rules! q {
    () => {
        "x15"
    };
}

// Re-use d6 and d7 as temporaries before they are needed

macro_rules! s {
    () => {
        Q!(d6!())
    };
}
macro_rules! t {
    () => {
        Q!(d7!())
    };
}

macro_rules! movbig {
    ($nn:expr, $n3:expr, $n2:expr, $n1:expr, $n0:expr) => { Q!(
        "movz " $nn ", " $n0 ";\n"
        "movk " $nn ", " $n1 ", lsl #16;\n"
        "movk " $nn ", " $n2 ", lsl #32;\n"
        "movk " $nn ", " $n3 ", lsl #48"
    )}
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

        Q!(Label!("bignum_mod_n521_9_alt", 2) ":"),

        // Load the top digit first into d8.
        // The initial quotient estimate is q = h + 1 where x = 2^521 * h + t

        Q!("    ldr             " d8!() ", [" x!() ", #64]"),
        Q!("    lsr             " q!() ", " d8!() ", #9"),
        Q!("    add             " q!() ", " q!() ", #1"),

        // Let [5; n3; n2; n1; n0] = r_521 = 2^521 - n_521
        // and form [d4;d3;d2;d1;d0] = q * r_521

        movbig!(n0!(), "#0x4490", "#0x48e1", "#0x6ec7", "#0x9bf7"),
        Q!("    mul             " d0!() ", " n0!() ", " q!()),
        movbig!(n1!(), "#0xc44a", "#0x3647", "#0x7663", "#0xb851"),
        Q!("    mul             " d1!() ", " n1!() ", " q!()),
        movbig!(n2!(), "#0x8033", "#0xfeb7", "#0x08f6", "#0x5a2f"),
        Q!("    mul             " d2!() ", " n2!() ", " q!()),
        movbig!(n3!(), "#0xae79", "#0x787c", "#0x40d0", "#0x6994"),
        Q!("    mul             " d3!() ", " n3!() ", " q!()),
        Q!("    lsl             " d4!() ", " q!() ", #2"),
        Q!("    add             " d4!() ", " d4!() ", " q!()),
        Q!("    umulh           " t!() ", " n0!() ", " q!()),
        Q!("    adds            " d1!() ", " d1!() ", " t!()),
        Q!("    umulh           " t!() ", " n1!() ", " q!()),
        Q!("    adcs            " d2!() ", " d2!() ", " t!()),
        Q!("    umulh           " t!() ", " n2!() ", " q!()),
        Q!("    adcs            " d3!() ", " d3!() ", " t!()),
        Q!("    umulh           " t!() ", " n3!() ", " q!()),
        Q!("    adc             " d4!() ", " d4!() ", " t!()),

        // Now load other digits and form r = x - q * n_521 = (q * r_521 + t) - 2^521.
        // But the computed result stuffs in 1s from bit 521 onwards and actually
        // gives r' = (q * r_521 + t) + (2^576 - 2^521) = r + 2^576, including the
        // top carry. Hence CF <=> r >= 0, while r' == r (mod 2^521).

        Q!("    ldp             " s!() ", " t!() ", [" x!() "]"),
        Q!("    adds            " d0!() ", " d0!() ", " s!()),
        Q!("    adcs            " d1!() ", " d1!() ", " t!()),
        Q!("    ldp             " s!() ", " t!() ", [" x!() ", #16]"),
        Q!("    adcs            " d2!() ", " d2!() ", " s!()),
        Q!("    adcs            " d3!() ", " d3!() ", " t!()),
        Q!("    ldp             " t!() ", " d5!() ", [" x!() ", #32]"),
        Q!("    adcs            " d4!() ", " d4!() ", " t!()),
        Q!("    adcs            " d5!() ", " d5!() ", xzr"),
        Q!("    ldp             " d6!() ", " d7!() ", [" x!() ", #48]"),
        Q!("    adcs            " d6!() ", " d6!() ", xzr"),
        Q!("    adcs            " d7!() ", " d7!() ", xzr"),
        Q!("    orr             " d8!() ", " d8!() ", # ~ 0x1FF"),
        Q!("    adcs            " d8!() ", " d8!() ", xzr"),

        // We already know r < n_521, but if it actually went negative then
        // we need to add back n_521 again. Recycle q as a bitmask for r < n_521,
        // and just subtract r_521 and mask rather than literally adding 2^521.
        // This also gets rid of the bit-stuffing above.

        Q!("    csetm           " q!() ", cc"),
        Q!("    and             " n0!() ", " n0!() ", " q!()),
        Q!("    subs            " d0!() ", " d0!() ", " n0!()),
        Q!("    and             " n1!() ", " n1!() ", " q!()),
        Q!("    sbcs            " d1!() ", " d1!() ", " n1!()),
        Q!("    and             " n2!() ", " n2!() ", " q!()),
        Q!("    sbcs            " d2!() ", " d2!() ", " n2!()),
        Q!("    and             " n3!() ", " n3!() ", " q!()),
        Q!("    sbcs            " d3!() ", " d3!() ", " n3!()),
        Q!("    mov             " n0!() ", #5"),
        Q!("    and             " n0!() ", " n0!() ", " q!()),
        Q!("    sbcs            " d4!() ", " d4!() ", " n0!()),
        Q!("    sbcs            " d5!() ", " d5!() ", xzr"),
        Q!("    sbcs            " d6!() ", " d6!() ", xzr"),
        Q!("    sbcs            " d7!() ", " d7!() ", xzr"),
        Q!("    sbc             " d8!() ", " d8!() ", xzr"),
        Q!("    and             " d8!() ", " d8!() ", #0x1FF"),

        // Store the end result

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
        out("x12") _,
        out("x13") _,
        out("x14") _,
        out("x15") _,
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
