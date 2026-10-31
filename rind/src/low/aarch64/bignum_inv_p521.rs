// generated source. do not edit.
#![allow(non_upper_case_globals, unused_macros, unused_imports)]
use crate::low::macros::*;

// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

// ----------------------------------------------------------------------------
// Modular inverse modulo p_521 =  2^521 - 1
// Input x[9]; output z[9]
//
// extern void bignum_inv_p521(uint64_t z[static 9],const uint64_t x[static 9]);
//
// Assuming the 9-digit input x is coprime to p_521, i.e. is not divisible
// by it, returns z < p_521 such that x * z == 1 (mod p_521). Note that
// x does not need to be reduced modulo p_521, but the output always is.
//
// Standard ARM ABI: X0 = z, X1 = x
// ----------------------------------------------------------------------------

// Size in bytes of a 64-bit word

macro_rules! N {
    () => {
        "8"
    };
}

// Used for the return pointer

macro_rules! res {
    () => {
        "x20"
    };
}

// Loop counter and d = 2 * delta value for divstep

macro_rules! i {
    () => {
        "x21"
    };
}
macro_rules! d {
    () => {
        "x22"
    };
}

// Registers used for matrix element magnitudes and signs

macro_rules! m00 {
    () => {
        "x10"
    };
}
macro_rules! m01 {
    () => {
        "x11"
    };
}
macro_rules! m10 {
    () => {
        "x12"
    };
}
macro_rules! m11 {
    () => {
        "x13"
    };
}
macro_rules! s00 {
    () => {
        "x14"
    };
}
macro_rules! s01 {
    () => {
        "x15"
    };
}
macro_rules! s10 {
    () => {
        "x16"
    };
}
macro_rules! s11 {
    () => {
        "x17"
    };
}

// Initial carries for combinations

macro_rules! car0 {
    () => {
        "x9"
    };
}
macro_rules! car1 {
    () => {
        "x19"
    };
}

// Input and output, plain registers treated according to pattern

macro_rules! reg0 {
    () => {
        "x0, #0"
    };
}
macro_rules! reg1 {
    () => {
        "x1, #0"
    };
}
macro_rules! reg2 {
    () => {
        "x2, #0"
    };
}
macro_rules! reg3 {
    () => {
        "x3, #0"
    };
}
macro_rules! reg4 {
    () => {
        "x4, #0"
    };
}

macro_rules! x {
    () => {
        "x1, #0"
    };
}
macro_rules! z {
    () => {
        "x0, #0"
    };
}

// Pointer-offset pairs for temporaries on stack

macro_rules! f {
    () => {
        "sp, #0"
    };
}
macro_rules! g { () => { Q!("sp, # (9 * " N!() ")") } }
macro_rules! u { () => { Q!("sp, # (18 * " N!() ")") } }
macro_rules! v { () => { Q!("sp, # (27 * " N!() ")") } }

// Total size to reserve on the stack

macro_rules! NSPACE { () => { Q!("36 * " N!()) } }

// Very similar to a subroutine call to the s2n-bignum word_divstep59.
// But different in register usage and returning the final matrix in
// registers as follows
//
// [ m00  m01]
// [ m10  m11]

macro_rules! divstep59 {
    () => { Q!(
        "and x4, x2, #0xfffff;\n"
        "orr x4, x4, #0xfffffe0000000000;\n"
        "and x5, x3, #0xfffff;\n"
        "orr x5, x5, #0xc000000000000000;\n"
        "tst x5, #0x1;\n"
        "csel x6, x4, xzr, ne;\n"
        "ccmp x1, xzr, #0x8, ne;\n"
        "cneg x1, x1, ge;\n"
        "cneg x6, x6, ge;\n"
        "csel x4, x5, x4, ge;\n"
        "add x5, x5, x6;\n"
        "add x1, x1, #0x2;\n"
        "tst x5, #0x2;\n"
        "asr x5, x5, #1;\n"
        "csel x6, x4, xzr, ne;\n"
        "ccmp x1, xzr, #0x8, ne;\n"
        "cneg x1, x1, ge;\n"
        "cneg x6, x6, ge;\n"
        "csel x4, x5, x4, ge;\n"
        "add x5, x5, x6;\n"
        "add x1, x1, #0x2;\n"
        "tst x5, #0x2;\n"
        "asr x5, x5, #1;\n"
        "csel x6, x4, xzr, ne;\n"
        "ccmp x1, xzr, #0x8, ne;\n"
        "cneg x1, x1, ge;\n"
        "cneg x6, x6, ge;\n"
        "csel x4, x5, x4, ge;\n"
        "add x5, x5, x6;\n"
        "add x1, x1, #0x2;\n"
        "tst x5, #0x2;\n"
        "asr x5, x5, #1;\n"
        "csel x6, x4, xzr, ne;\n"
        "ccmp x1, xzr, #0x8, ne;\n"
        "cneg x1, x1, ge;\n"
        "cneg x6, x6, ge;\n"
        "csel x4, x5, x4, ge;\n"
        "add x5, x5, x6;\n"
        "add x1, x1, #0x2;\n"
        "tst x5, #0x2;\n"
        "asr x5, x5, #1;\n"
        "csel x6, x4, xzr, ne;\n"
        "ccmp x1, xzr, #0x8, ne;\n"
        "cneg x1, x1, ge;\n"
        "cneg x6, x6, ge;\n"
        "csel x4, x5, x4, ge;\n"
        "add x5, x5, x6;\n"
        "add x1, x1, #0x2;\n"
        "tst x5, #0x2;\n"
        "asr x5, x5, #1;\n"
        "csel x6, x4, xzr, ne;\n"
        "ccmp x1, xzr, #0x8, ne;\n"
        "cneg x1, x1, ge;\n"
        "cneg x6, x6, ge;\n"
        "csel x4, x5, x4, ge;\n"
        "add x5, x5, x6;\n"
        "add x1, x1, #0x2;\n"
        "tst x5, #0x2;\n"
        "asr x5, x5, #1;\n"
        "csel x6, x4, xzr, ne;\n"
        "ccmp x1, xzr, #0x8, ne;\n"
        "cneg x1, x1, ge;\n"
        "cneg x6, x6, ge;\n"
        "csel x4, x5, x4, ge;\n"
        "add x5, x5, x6;\n"
        "add x1, x1, #0x2;\n"
        "tst x5, #0x2;\n"
        "asr x5, x5, #1;\n"
        "csel x6, x4, xzr, ne;\n"
        "ccmp x1, xzr, #0x8, ne;\n"
        "cneg x1, x1, ge;\n"
        "cneg x6, x6, ge;\n"
        "csel x4, x5, x4, ge;\n"
        "add x5, x5, x6;\n"
        "add x1, x1, #0x2;\n"
        "tst x5, #0x2;\n"
        "asr x5, x5, #1;\n"
        "csel x6, x4, xzr, ne;\n"
        "ccmp x1, xzr, #0x8, ne;\n"
        "cneg x1, x1, ge;\n"
        "cneg x6, x6, ge;\n"
        "csel x4, x5, x4, ge;\n"
        "add x5, x5, x6;\n"
        "add x1, x1, #0x2;\n"
        "tst x5, #0x2;\n"
        "asr x5, x5, #1;\n"
        "csel x6, x4, xzr, ne;\n"
        "ccmp x1, xzr, #0x8, ne;\n"
        "cneg x1, x1, ge;\n"
        "cneg x6, x6, ge;\n"
        "csel x4, x5, x4, ge;\n"
        "add x5, x5, x6;\n"
        "add x1, x1, #0x2;\n"
        "tst x5, #0x2;\n"
        "asr x5, x5, #1;\n"
        "csel x6, x4, xzr, ne;\n"
        "ccmp x1, xzr, #0x8, ne;\n"
        "cneg x1, x1, ge;\n"
        "cneg x6, x6, ge;\n"
        "csel x4, x5, x4, ge;\n"
        "add x5, x5, x6;\n"
        "add x1, x1, #0x2;\n"
        "tst x5, #0x2;\n"
        "asr x5, x5, #1;\n"
        "csel x6, x4, xzr, ne;\n"
        "ccmp x1, xzr, #0x8, ne;\n"
        "cneg x1, x1, ge;\n"
        "cneg x6, x6, ge;\n"
        "csel x4, x5, x4, ge;\n"
        "add x5, x5, x6;\n"
        "add x1, x1, #0x2;\n"
        "tst x5, #0x2;\n"
        "asr x5, x5, #1;\n"
        "csel x6, x4, xzr, ne;\n"
        "ccmp x1, xzr, #0x8, ne;\n"
        "cneg x1, x1, ge;\n"
        "cneg x6, x6, ge;\n"
        "csel x4, x5, x4, ge;\n"
        "add x5, x5, x6;\n"
        "add x1, x1, #0x2;\n"
        "tst x5, #0x2;\n"
        "asr x5, x5, #1;\n"
        "csel x6, x4, xzr, ne;\n"
        "ccmp x1, xzr, #0x8, ne;\n"
        "cneg x1, x1, ge;\n"
        "cneg x6, x6, ge;\n"
        "csel x4, x5, x4, ge;\n"
        "add x5, x5, x6;\n"
        "add x1, x1, #0x2;\n"
        "tst x5, #0x2;\n"
        "asr x5, x5, #1;\n"
        "csel x6, x4, xzr, ne;\n"
        "ccmp x1, xzr, #0x8, ne;\n"
        "cneg x1, x1, ge;\n"
        "cneg x6, x6, ge;\n"
        "csel x4, x5, x4, ge;\n"
        "add x5, x5, x6;\n"
        "add x1, x1, #0x2;\n"
        "tst x5, #0x2;\n"
        "asr x5, x5, #1;\n"
        "csel x6, x4, xzr, ne;\n"
        "ccmp x1, xzr, #0x8, ne;\n"
        "cneg x1, x1, ge;\n"
        "cneg x6, x6, ge;\n"
        "csel x4, x5, x4, ge;\n"
        "add x5, x5, x6;\n"
        "add x1, x1, #0x2;\n"
        "tst x5, #0x2;\n"
        "asr x5, x5, #1;\n"
        "csel x6, x4, xzr, ne;\n"
        "ccmp x1, xzr, #0x8, ne;\n"
        "cneg x1, x1, ge;\n"
        "cneg x6, x6, ge;\n"
        "csel x4, x5, x4, ge;\n"
        "add x5, x5, x6;\n"
        "add x1, x1, #0x2;\n"
        "tst x5, #0x2;\n"
        "asr x5, x5, #1;\n"
        "csel x6, x4, xzr, ne;\n"
        "ccmp x1, xzr, #0x8, ne;\n"
        "cneg x1, x1, ge;\n"
        "cneg x6, x6, ge;\n"
        "csel x4, x5, x4, ge;\n"
        "add x5, x5, x6;\n"
        "add x1, x1, #0x2;\n"
        "tst x5, #0x2;\n"
        "asr x5, x5, #1;\n"
        "csel x6, x4, xzr, ne;\n"
        "ccmp x1, xzr, #0x8, ne;\n"
        "cneg x1, x1, ge;\n"
        "cneg x6, x6, ge;\n"
        "csel x4, x5, x4, ge;\n"
        "add x5, x5, x6;\n"
        "add x1, x1, #0x2;\n"
        "tst x5, #0x2;\n"
        "asr x5, x5, #1;\n"
        "csel x6, x4, xzr, ne;\n"
        "ccmp x1, xzr, #0x8, ne;\n"
        "cneg x1, x1, ge;\n"
        "cneg x6, x6, ge;\n"
        "csel x4, x5, x4, ge;\n"
        "add x5, x5, x6;\n"
        "add x1, x1, #0x2;\n"
        "asr x5, x5, #1;\n"
        "add x8, x4, #0x100, lsl #12;\n"
        "sbfx x8, x8, #21, #21;\n"
        "mov x11, #0x100000;\n"
        "add x11, x11, x11, lsl #21;\n"
        "add x9, x4, x11;\n"
        "asr x9, x9, #42;\n"
        "add x10, x5, #0x100, lsl #12;\n"
        "sbfx x10, x10, #21, #21;\n"
        "add x11, x5, x11;\n"
        "asr x11, x11, #42;\n"
        "mul x6, x8, x2;\n"
        "mul x7, x9, x3;\n"
        "mul x2, x10, x2;\n"
        "mul x3, x11, x3;\n"
        "add x4, x6, x7;\n"
        "add x5, x2, x3;\n"
        "asr x2, x4, #20;\n"
        "asr x3, x5, #20;\n"
        "and x4, x2, #0xfffff;\n"
        "orr x4, x4, #0xfffffe0000000000;\n"
        "and x5, x3, #0xfffff;\n"
        "orr x5, x5, #0xc000000000000000;\n"
        "tst x5, #0x1;\n"
        "csel x6, x4, xzr, ne;\n"
        "ccmp x1, xzr, #0x8, ne;\n"
        "cneg x1, x1, ge;\n"
        "cneg x6, x6, ge;\n"
        "csel x4, x5, x4, ge;\n"
        "add x5, x5, x6;\n"
        "add x1, x1, #0x2;\n"
        "tst x5, #0x2;\n"
        "asr x5, x5, #1;\n"
        "csel x6, x4, xzr, ne;\n"
        "ccmp x1, xzr, #0x8, ne;\n"
        "cneg x1, x1, ge;\n"
        "cneg x6, x6, ge;\n"
        "csel x4, x5, x4, ge;\n"
        "add x5, x5, x6;\n"
        "add x1, x1, #0x2;\n"
        "tst x5, #0x2;\n"
        "asr x5, x5, #1;\n"
        "csel x6, x4, xzr, ne;\n"
        "ccmp x1, xzr, #0x8, ne;\n"
        "cneg x1, x1, ge;\n"
        "cneg x6, x6, ge;\n"
        "csel x4, x5, x4, ge;\n"
        "add x5, x5, x6;\n"
        "add x1, x1, #0x2;\n"
        "tst x5, #0x2;\n"
        "asr x5, x5, #1;\n"
        "csel x6, x4, xzr, ne;\n"
        "ccmp x1, xzr, #0x8, ne;\n"
        "cneg x1, x1, ge;\n"
        "cneg x6, x6, ge;\n"
        "csel x4, x5, x4, ge;\n"
        "add x5, x5, x6;\n"
        "add x1, x1, #0x2;\n"
        "tst x5, #0x2;\n"
        "asr x5, x5, #1;\n"
        "csel x6, x4, xzr, ne;\n"
        "ccmp x1, xzr, #0x8, ne;\n"
        "cneg x1, x1, ge;\n"
        "cneg x6, x6, ge;\n"
        "csel x4, x5, x4, ge;\n"
        "add x5, x5, x6;\n"
        "add x1, x1, #0x2;\n"
        "tst x5, #0x2;\n"
        "asr x5, x5, #1;\n"
        "csel x6, x4, xzr, ne;\n"
        "ccmp x1, xzr, #0x8, ne;\n"
        "cneg x1, x1, ge;\n"
        "cneg x6, x6, ge;\n"
        "csel x4, x5, x4, ge;\n"
        "add x5, x5, x6;\n"
        "add x1, x1, #0x2;\n"
        "tst x5, #0x2;\n"
        "asr x5, x5, #1;\n"
        "csel x6, x4, xzr, ne;\n"
        "ccmp x1, xzr, #0x8, ne;\n"
        "cneg x1, x1, ge;\n"
        "cneg x6, x6, ge;\n"
        "csel x4, x5, x4, ge;\n"
        "add x5, x5, x6;\n"
        "add x1, x1, #0x2;\n"
        "tst x5, #0x2;\n"
        "asr x5, x5, #1;\n"
        "csel x6, x4, xzr, ne;\n"
        "ccmp x1, xzr, #0x8, ne;\n"
        "cneg x1, x1, ge;\n"
        "cneg x6, x6, ge;\n"
        "csel x4, x5, x4, ge;\n"
        "add x5, x5, x6;\n"
        "add x1, x1, #0x2;\n"
        "tst x5, #0x2;\n"
        "asr x5, x5, #1;\n"
        "csel x6, x4, xzr, ne;\n"
        "ccmp x1, xzr, #0x8, ne;\n"
        "cneg x1, x1, ge;\n"
        "cneg x6, x6, ge;\n"
        "csel x4, x5, x4, ge;\n"
        "add x5, x5, x6;\n"
        "add x1, x1, #0x2;\n"
        "tst x5, #0x2;\n"
        "asr x5, x5, #1;\n"
        "csel x6, x4, xzr, ne;\n"
        "ccmp x1, xzr, #0x8, ne;\n"
        "cneg x1, x1, ge;\n"
        "cneg x6, x6, ge;\n"
        "csel x4, x5, x4, ge;\n"
        "add x5, x5, x6;\n"
        "add x1, x1, #0x2;\n"
        "tst x5, #0x2;\n"
        "asr x5, x5, #1;\n"
        "csel x6, x4, xzr, ne;\n"
        "ccmp x1, xzr, #0x8, ne;\n"
        "cneg x1, x1, ge;\n"
        "cneg x6, x6, ge;\n"
        "csel x4, x5, x4, ge;\n"
        "add x5, x5, x6;\n"
        "add x1, x1, #0x2;\n"
        "tst x5, #0x2;\n"
        "asr x5, x5, #1;\n"
        "csel x6, x4, xzr, ne;\n"
        "ccmp x1, xzr, #0x8, ne;\n"
        "cneg x1, x1, ge;\n"
        "cneg x6, x6, ge;\n"
        "csel x4, x5, x4, ge;\n"
        "add x5, x5, x6;\n"
        "add x1, x1, #0x2;\n"
        "tst x5, #0x2;\n"
        "asr x5, x5, #1;\n"
        "csel x6, x4, xzr, ne;\n"
        "ccmp x1, xzr, #0x8, ne;\n"
        "cneg x1, x1, ge;\n"
        "cneg x6, x6, ge;\n"
        "csel x4, x5, x4, ge;\n"
        "add x5, x5, x6;\n"
        "add x1, x1, #0x2;\n"
        "tst x5, #0x2;\n"
        "asr x5, x5, #1;\n"
        "csel x6, x4, xzr, ne;\n"
        "ccmp x1, xzr, #0x8, ne;\n"
        "cneg x1, x1, ge;\n"
        "cneg x6, x6, ge;\n"
        "csel x4, x5, x4, ge;\n"
        "add x5, x5, x6;\n"
        "add x1, x1, #0x2;\n"
        "tst x5, #0x2;\n"
        "asr x5, x5, #1;\n"
        "csel x6, x4, xzr, ne;\n"
        "ccmp x1, xzr, #0x8, ne;\n"
        "cneg x1, x1, ge;\n"
        "cneg x6, x6, ge;\n"
        "csel x4, x5, x4, ge;\n"
        "add x5, x5, x6;\n"
        "add x1, x1, #0x2;\n"
        "tst x5, #0x2;\n"
        "asr x5, x5, #1;\n"
        "csel x6, x4, xzr, ne;\n"
        "ccmp x1, xzr, #0x8, ne;\n"
        "cneg x1, x1, ge;\n"
        "cneg x6, x6, ge;\n"
        "csel x4, x5, x4, ge;\n"
        "add x5, x5, x6;\n"
        "add x1, x1, #0x2;\n"
        "tst x5, #0x2;\n"
        "asr x5, x5, #1;\n"
        "csel x6, x4, xzr, ne;\n"
        "ccmp x1, xzr, #0x8, ne;\n"
        "cneg x1, x1, ge;\n"
        "cneg x6, x6, ge;\n"
        "csel x4, x5, x4, ge;\n"
        "add x5, x5, x6;\n"
        "add x1, x1, #0x2;\n"
        "tst x5, #0x2;\n"
        "asr x5, x5, #1;\n"
        "csel x6, x4, xzr, ne;\n"
        "ccmp x1, xzr, #0x8, ne;\n"
        "cneg x1, x1, ge;\n"
        "cneg x6, x6, ge;\n"
        "csel x4, x5, x4, ge;\n"
        "add x5, x5, x6;\n"
        "add x1, x1, #0x2;\n"
        "tst x5, #0x2;\n"
        "asr x5, x5, #1;\n"
        "csel x6, x4, xzr, ne;\n"
        "ccmp x1, xzr, #0x8, ne;\n"
        "cneg x1, x1, ge;\n"
        "cneg x6, x6, ge;\n"
        "csel x4, x5, x4, ge;\n"
        "add x5, x5, x6;\n"
        "add x1, x1, #0x2;\n"
        "tst x5, #0x2;\n"
        "asr x5, x5, #1;\n"
        "csel x6, x4, xzr, ne;\n"
        "ccmp x1, xzr, #0x8, ne;\n"
        "cneg x1, x1, ge;\n"
        "cneg x6, x6, ge;\n"
        "csel x4, x5, x4, ge;\n"
        "add x5, x5, x6;\n"
        "add x1, x1, #0x2;\n"
        "asr x5, x5, #1;\n"
        "add x12, x4, #0x100, lsl #12;\n"
        "sbfx x12, x12, #21, #21;\n"
        "mov x15, #0x100000;\n"
        "add x15, x15, x15, lsl #21;\n"
        "add x13, x4, x15;\n"
        "asr x13, x13, #42;\n"
        "add x14, x5, #0x100, lsl #12;\n"
        "sbfx x14, x14, #21, #21;\n"
        "add x15, x5, x15;\n"
        "asr x15, x15, #42;\n"
        "mul x6, x12, x2;\n"
        "mul x7, x13, x3;\n"
        "mul x2, x14, x2;\n"
        "mul x3, x15, x3;\n"
        "add x4, x6, x7;\n"
        "add x5, x2, x3;\n"
        "asr x2, x4, #20;\n"
        "asr x3, x5, #20;\n"
        "and x4, x2, #0xfffff;\n"
        "orr x4, x4, #0xfffffe0000000000;\n"
        "and x5, x3, #0xfffff;\n"
        "orr x5, x5, #0xc000000000000000;\n"
        "tst x5, #0x1;\n"
        "csel x6, x4, xzr, ne;\n"
        "ccmp x1, xzr, #0x8, ne;\n"
        "cneg x1, x1, ge;\n"
        "cneg x6, x6, ge;\n"
        "csel x4, x5, x4, ge;\n"
        "add x5, x5, x6;\n"
        "add x1, x1, #0x2;\n"
        "tst x5, #0x2;\n"
        "asr x5, x5, #1;\n"
        "csel x6, x4, xzr, ne;\n"
        "ccmp x1, xzr, #0x8, ne;\n"
        "cneg x1, x1, ge;\n"
        "cneg x6, x6, ge;\n"
        "csel x4, x5, x4, ge;\n"
        "add x5, x5, x6;\n"
        "add x1, x1, #0x2;\n"
        "tst x5, #0x2;\n"
        "asr x5, x5, #1;\n"
        "csel x6, x4, xzr, ne;\n"
        "ccmp x1, xzr, #0x8, ne;\n"
        "cneg x1, x1, ge;\n"
        "cneg x6, x6, ge;\n"
        "csel x4, x5, x4, ge;\n"
        "add x5, x5, x6;\n"
        "add x1, x1, #0x2;\n"
        "tst x5, #0x2;\n"
        "asr x5, x5, #1;\n"
        "csel x6, x4, xzr, ne;\n"
        "ccmp x1, xzr, #0x8, ne;\n"
        "cneg x1, x1, ge;\n"
        "cneg x6, x6, ge;\n"
        "csel x4, x5, x4, ge;\n"
        "add x5, x5, x6;\n"
        "add x1, x1, #0x2;\n"
        "tst x5, #0x2;\n"
        "asr x5, x5, #1;\n"
        "csel x6, x4, xzr, ne;\n"
        "ccmp x1, xzr, #0x8, ne;\n"
        "cneg x1, x1, ge;\n"
        "cneg x6, x6, ge;\n"
        "csel x4, x5, x4, ge;\n"
        "add x5, x5, x6;\n"
        "add x1, x1, #0x2;\n"
        "tst x5, #0x2;\n"
        "asr x5, x5, #1;\n"
        "csel x6, x4, xzr, ne;\n"
        "ccmp x1, xzr, #0x8, ne;\n"
        "cneg x1, x1, ge;\n"
        "cneg x6, x6, ge;\n"
        "csel x4, x5, x4, ge;\n"
        "add x5, x5, x6;\n"
        "add x1, x1, #0x2;\n"
        "tst x5, #0x2;\n"
        "asr x5, x5, #1;\n"
        "csel x6, x4, xzr, ne;\n"
        "ccmp x1, xzr, #0x8, ne;\n"
        "cneg x1, x1, ge;\n"
        "cneg x6, x6, ge;\n"
        "csel x4, x5, x4, ge;\n"
        "add x5, x5, x6;\n"
        "add x1, x1, #0x2;\n"
        "tst x5, #0x2;\n"
        "asr x5, x5, #1;\n"
        "csel x6, x4, xzr, ne;\n"
        "ccmp x1, xzr, #0x8, ne;\n"
        "cneg x1, x1, ge;\n"
        "cneg x6, x6, ge;\n"
        "csel x4, x5, x4, ge;\n"
        "add x5, x5, x6;\n"
        "add x1, x1, #0x2;\n"
        "tst x5, #0x2;\n"
        "asr x5, x5, #1;\n"
        "csel x6, x4, xzr, ne;\n"
        "ccmp x1, xzr, #0x8, ne;\n"
        "cneg x1, x1, ge;\n"
        "cneg x6, x6, ge;\n"
        "csel x4, x5, x4, ge;\n"
        "add x5, x5, x6;\n"
        "add x1, x1, #0x2;\n"
        "tst x5, #0x2;\n"
        "asr x5, x5, #1;\n"
        "csel x6, x4, xzr, ne;\n"
        "ccmp x1, xzr, #0x8, ne;\n"
        "cneg x1, x1, ge;\n"
        "cneg x6, x6, ge;\n"
        "csel x4, x5, x4, ge;\n"
        "add x5, x5, x6;\n"
        "add x1, x1, #0x2;\n"
        "tst x5, #0x2;\n"
        "asr x5, x5, #1;\n"
        "mul x2, x12, x8;\n"
        "mul x3, x12, x9;\n"
        "mul x6, x14, x8;\n"
        "mul x7, x14, x9;\n"
        "madd x8, x13, x10, x2;\n"
        "madd x9, x13, x11, x3;\n"
        "madd x16, x15, x10, x6;\n"
        "madd x17, x15, x11, x7;\n"
        "csel x6, x4, xzr, ne;\n"
        "ccmp x1, xzr, #0x8, ne;\n"
        "cneg x1, x1, ge;\n"
        "cneg x6, x6, ge;\n"
        "csel x4, x5, x4, ge;\n"
        "add x5, x5, x6;\n"
        "add x1, x1, #0x2;\n"
        "tst x5, #0x2;\n"
        "asr x5, x5, #1;\n"
        "csel x6, x4, xzr, ne;\n"
        "ccmp x1, xzr, #0x8, ne;\n"
        "cneg x1, x1, ge;\n"
        "cneg x6, x6, ge;\n"
        "csel x4, x5, x4, ge;\n"
        "add x5, x5, x6;\n"
        "add x1, x1, #0x2;\n"
        "tst x5, #0x2;\n"
        "asr x5, x5, #1;\n"
        "csel x6, x4, xzr, ne;\n"
        "ccmp x1, xzr, #0x8, ne;\n"
        "cneg x1, x1, ge;\n"
        "cneg x6, x6, ge;\n"
        "csel x4, x5, x4, ge;\n"
        "add x5, x5, x6;\n"
        "add x1, x1, #0x2;\n"
        "tst x5, #0x2;\n"
        "asr x5, x5, #1;\n"
        "csel x6, x4, xzr, ne;\n"
        "ccmp x1, xzr, #0x8, ne;\n"
        "cneg x1, x1, ge;\n"
        "cneg x6, x6, ge;\n"
        "csel x4, x5, x4, ge;\n"
        "add x5, x5, x6;\n"
        "add x1, x1, #0x2;\n"
        "tst x5, #0x2;\n"
        "asr x5, x5, #1;\n"
        "csel x6, x4, xzr, ne;\n"
        "ccmp x1, xzr, #0x8, ne;\n"
        "cneg x1, x1, ge;\n"
        "cneg x6, x6, ge;\n"
        "csel x4, x5, x4, ge;\n"
        "add x5, x5, x6;\n"
        "add x1, x1, #0x2;\n"
        "tst x5, #0x2;\n"
        "asr x5, x5, #1;\n"
        "csel x6, x4, xzr, ne;\n"
        "ccmp x1, xzr, #0x8, ne;\n"
        "cneg x1, x1, ge;\n"
        "cneg x6, x6, ge;\n"
        "csel x4, x5, x4, ge;\n"
        "add x5, x5, x6;\n"
        "add x1, x1, #0x2;\n"
        "tst x5, #0x2;\n"
        "asr x5, x5, #1;\n"
        "csel x6, x4, xzr, ne;\n"
        "ccmp x1, xzr, #0x8, ne;\n"
        "cneg x1, x1, ge;\n"
        "cneg x6, x6, ge;\n"
        "csel x4, x5, x4, ge;\n"
        "add x5, x5, x6;\n"
        "add x1, x1, #0x2;\n"
        "tst x5, #0x2;\n"
        "asr x5, x5, #1;\n"
        "csel x6, x4, xzr, ne;\n"
        "ccmp x1, xzr, #0x8, ne;\n"
        "cneg x1, x1, ge;\n"
        "cneg x6, x6, ge;\n"
        "csel x4, x5, x4, ge;\n"
        "add x5, x5, x6;\n"
        "add x1, x1, #0x2;\n"
        "tst x5, #0x2;\n"
        "asr x5, x5, #1;\n"
        "csel x6, x4, xzr, ne;\n"
        "ccmp x1, xzr, #0x8, ne;\n"
        "cneg x1, x1, ge;\n"
        "cneg x6, x6, ge;\n"
        "csel x4, x5, x4, ge;\n"
        "add x5, x5, x6;\n"
        "add x1, x1, #0x2;\n"
        "asr x5, x5, #1;\n"
        "add x12, x4, #0x100, lsl #12;\n"
        "sbfx x12, x12, #22, #21;\n"
        "mov x15, #0x100000;\n"
        "add x15, x15, x15, lsl #21;\n"
        "add x13, x4, x15;\n"
        "asr x13, x13, #43;\n"
        "add x14, x5, #0x100, lsl #12;\n"
        "sbfx x14, x14, #22, #21;\n"
        "add x15, x5, x15;\n"
        "asr x15, x15, #43;\n"
        "mneg x2, x12, x8;\n"
        "mneg x3, x12, x9;\n"
        "mneg x4, x14, x8;\n"
        "mneg x5, x14, x9;\n"
        "msub " m00!() ", x13, x16, x2;\n"
        "msub " m01!() ", x13, x17, x3;\n"
        "msub " m10!() ", x15, x16, x4;\n"
        "msub " m11!() ", x15, x17, x5"
    )}
}

// Loading large constants

macro_rules! movbig {
    ($nn:expr, $n3:expr, $n2:expr, $n1:expr, $n0:expr) => { Q!(
        "movz " $nn ", " $n0 ";\n"
        "movk " $nn ", " $n1 ", lsl #16;\n"
        "movk " $nn ", " $n2 ", lsl #32;\n"
        "movk " $nn ", " $n3 ", lsl #48"
    )}
}

/// Modular inverse modulo p_521 =  2^521 - 1
///
/// Input x[9]; output z[9]
///
/// Assuming the 9-digit input x is coprime to p_521, i.e. is not divisible
/// by it, returns z < p_521 such that x * z == 1 (mod p_521). Note that
/// x does not need to be reduced modulo p_521, but the output always is.
pub(crate) fn bignum_inv_p521(z: &mut [u64; 9], x: &[u64; 9]) {
    // SAFETY: inline assembly. see [crate::low::inline_assembly_safety] for safety info.
    unsafe {
        core::arch::asm!(

        // Save registers and make room for temporaries

        Q!("    stp             " "x19, x20, [sp, #-16] !"),
        Q!("    stp             " "x21, x22, [sp, #-16] !"),
        Q!("    sub             " "sp, sp, # (" NSPACE!() "+ 0)"),

        // Save the return pointer for the end so we can overwrite x0 later

        Q!("    mov             " res!() ", x0"),

        // Copy the prime p_521 = 2^521 - 1 into the f variable

        Q!("    mov             " "x10, #0xFFFFFFFFFFFFFFFF"),
        Q!("    stp             " "x10, x10, [" f!() "]"),
        Q!("    stp             " "x10, x10, [" f!() "+ 16]"),
        Q!("    stp             " "x10, x10, [" f!() "+ 32]"),
        Q!("    stp             " "x10, x10, [" f!() "+ 48]"),
        Q!("    mov             " "x11, #0x1FF"),
        Q!("    str             " "x11, [" f!() "+ 64]"),

        // Copy the input into the g variable, but reduce it strictly mod p_521
        // so that g <= f as assumed in the bound proof. This code fragment is
        // very similar to bignum_mod_p521_9 complete with carry condensation.

        Q!("    ldr             " "x8, [x1, #64]"),
        Q!("    lsr             " "x9, x8, #9"),

        Q!("    subs            " "xzr, xzr, xzr"),
        Q!("    ldp             " "x10, x11, [x1]"),
        Q!("    adcs            " "xzr, x10, x9"),
        Q!("    adcs            " "xzr, x11, xzr"),
        Q!("    ldp             " "x12, x13, [x1, #16]"),
        Q!("    and             " "x7, x12, x13"),
        Q!("    adcs            " "xzr, x7, xzr"),
        Q!("    ldp             " "x14, x15, [x1, #32]"),
        Q!("    and             " "x7, x14, x15"),
        Q!("    adcs            " "xzr, x7, xzr"),
        Q!("    ldp             " "x16, x17, [x1, #48]"),
        Q!("    and             " "x7, x16, x17"),
        Q!("    adcs            " "xzr, x7, xzr"),
        Q!("    orr             " "x7, x8, # ~ 0x1FF"),
        Q!("    adcs            " "x7, x7, xzr"),

        Q!("    adcs            " "x10, x10, x9"),
        Q!("    adcs            " "x11, x11, xzr"),
        Q!("    adcs            " "x12, x12, xzr"),
        Q!("    adcs            " "x13, x13, xzr"),
        Q!("    adcs            " "x14, x14, xzr"),
        Q!("    adcs            " "x15, x15, xzr"),
        Q!("    adcs            " "x16, x16, xzr"),
        Q!("    adcs            " "x17, x17, xzr"),
        Q!("    adc             " "x8, x8, xzr"),
        Q!("    and             " "x8, x8, #0x1FF"),

        Q!("    stp             " "x10, x11, [" g!() "]"),
        Q!("    stp             " "x12, x13, [" g!() "+ 16]"),
        Q!("    stp             " "x14, x15, [" g!() "+ 32]"),
        Q!("    stp             " "x16, x17, [" g!() "+ 48]"),
        Q!("    str             " "x8, [" g!() "+ 64]"),

        // Also maintain weakly reduced < 2*p_521 vector [u,v] such that
        // [f,g] == x * 2^{1239-59*i} * [u,v] (mod p_521)
        // starting with [p_521,x] == x * 2^{1239-59*0} * [0,2^-1239] (mod p_521)
        // Note that because (2^{a+521} == 2^a) (mod p_521) we simply have
        // (2^-1239 == 2^324) (mod p_521) so the constant initializer is simple.
        //
        // Based on the standard divstep bound, for inputs <= 2^b we need at least
        // n >= (9437 * b + 1) / 4096. Since b is 521, that means 1201 iterations.
        // Since we package divstep in multiples of 59 bits, we do 21 blocks of 59
        // making *1239* total. (With a bit more effort we could avoid the full 59
        // divsteps and use a shorter tail computation, but we keep it simple.)
        // Hence, after the 21st iteration we have [f,g] == x * [u,v] and since
        // |f| = 1 we get the modular inverse from u by flipping its sign with f.

        Q!("    stp             " "xzr, xzr, [" u!() "]"),
        Q!("    stp             " "xzr, xzr, [" u!() "+ 16]"),
        Q!("    stp             " "xzr, xzr, [" u!() "+ 32]"),
        Q!("    stp             " "xzr, xzr, [" u!() "+ 48]"),
        Q!("    str             " "xzr, [" u!() "+ 64]"),

        Q!("    mov             " "x10, #16"),
        Q!("    stp             " "xzr, xzr, [" v!() "]"),
        Q!("    stp             " "xzr, xzr, [" v!() "+ 16]"),
        Q!("    stp             " "xzr, x10, [" v!() "+ 32]"),
        Q!("    stp             " "xzr, xzr, [" v!() "+ 48]"),
        Q!("    str             " "xzr, [" v!() "+ 64]"),

        // Start of main loop. We jump into the middle so that the divstep
        // portion is common to the special 21st iteration after a uniform
        // first 20.

        Q!("    mov             " i!() ", #21"),
        Q!("    mov             " d!() ", #1"),
        Q!("    b               " Label!("Lbignum_inv_p521_midloop", 2, After)),

        Q!(Label!("Lbignum_inv_p521_loop", 3) ":"),

        // Separate the matrix elements into sign-magnitude pairs

        Q!("    cmp             " m00!() ", xzr"),
        Q!("    csetm           " s00!() ", mi"),
        Q!("    cneg            " m00!() ", " m00!() ", mi"),

        Q!("    cmp             " m01!() ", xzr"),
        Q!("    csetm           " s01!() ", mi"),
        Q!("    cneg            " m01!() ", " m01!() ", mi"),

        Q!("    cmp             " m10!() ", xzr"),
        Q!("    csetm           " s10!() ", mi"),
        Q!("    cneg            " m10!() ", " m10!() ", mi"),

        Q!("    cmp             " m11!() ", xzr"),
        Q!("    csetm           " s11!() ", mi"),
        Q!("    cneg            " m11!() ", " m11!() ", mi"),

        // Adjust the initial values to allow for complement instead of negation
        // This initial offset is the same for [f,g] and [u,v] compositions.
        // Save it in stable registers for the [u,v] part and do [f,g] first.

        Q!("    and             " "x0, " m00!() ", " s00!()),
        Q!("    and             " "x1, " m01!() ", " s01!()),
        Q!("    add             " car0!() ", x0, x1"),

        Q!("    and             " "x0, " m10!() ", " s10!()),
        Q!("    and             " "x1, " m11!() ", " s11!()),
        Q!("    add             " car1!() ", x0, x1"),

        // Now the computation of the updated f and g values. This maintains a
        // 2-word carry between stages so we can conveniently insert the shift
        // right by 59 before storing back, and not overwrite digits we need
        // again of the old f and g values.
        //
        // Digit 0 of [f,g]

        Q!("    ldr             " "x7, [" f!() "]"),
        Q!("    eor             " "x1, x7, " s00!()),
        Q!("    mul             " "x0, x1, " m00!()),
        Q!("    umulh           " "x1, x1, " m00!()),
        Q!("    adds            " "x4, " car0!() ", x0"),
        Q!("    adc             " "x2, xzr, x1"),
        Q!("    ldr             " "x8, [" g!() "]"),
        Q!("    eor             " "x1, x8, " s01!()),
        Q!("    mul             " "x0, x1, " m01!()),
        Q!("    umulh           " "x1, x1, " m01!()),
        Q!("    adds            " "x4, x4, x0"),
        Q!("    adc             " "x2, x2, x1"),

        Q!("    eor             " "x1, x7, " s10!()),
        Q!("    mul             " "x0, x1, " m10!()),
        Q!("    umulh           " "x1, x1, " m10!()),
        Q!("    adds            " "x5, " car1!() ", x0"),
        Q!("    adc             " "x3, xzr, x1"),
        Q!("    eor             " "x1, x8, " s11!()),
        Q!("    mul             " "x0, x1, " m11!()),
        Q!("    umulh           " "x1, x1, " m11!()),
        Q!("    adds            " "x5, x5, x0"),
        Q!("    adc             " "x3, x3, x1"),

        // Digit 1 of [f,g]

        Q!("    ldr             " "x7, [" f!() "+ " N!() "]"),
        Q!("    eor             " "x1, x7, " s00!()),
        Q!("    mul             " "x0, x1, " m00!()),
        Q!("    umulh           " "x1, x1, " m00!()),
        Q!("    adds            " "x2, x2, x0"),
        Q!("    adc             " "x6, xzr, x1"),
        Q!("    ldr             " "x8, [" g!() "+ " N!() "]"),
        Q!("    eor             " "x1, x8, " s01!()),
        Q!("    mul             " "x0, x1, " m01!()),
        Q!("    umulh           " "x1, x1, " m01!()),
        Q!("    adds            " "x2, x2, x0"),
        Q!("    adc             " "x6, x6, x1"),
        Q!("    extr            " "x4, x2, x4, #59"),
        Q!("    str             " "x4, [" f!() "]"),

        Q!("    eor             " "x1, x7, " s10!()),
        Q!("    mul             " "x0, x1, " m10!()),
        Q!("    umulh           " "x1, x1, " m10!()),
        Q!("    adds            " "x3, x3, x0"),
        Q!("    adc             " "x4, xzr, x1"),
        Q!("    eor             " "x1, x8, " s11!()),
        Q!("    mul             " "x0, x1, " m11!()),
        Q!("    umulh           " "x1, x1, " m11!()),
        Q!("    adds            " "x3, x3, x0"),
        Q!("    adc             " "x4, x4, x1"),
        Q!("    extr            " "x5, x3, x5, #59"),
        Q!("    str             " "x5, [" g!() "]"),

        // Digit 2 of [f,g]

        Q!("    ldr             " "x7, [" f!() "+ 2 * " N!() "]"),
        Q!("    eor             " "x1, x7, " s00!()),
        Q!("    mul             " "x0, x1, " m00!()),
        Q!("    umulh           " "x1, x1, " m00!()),
        Q!("    adds            " "x6, x6, x0"),
        Q!("    adc             " "x5, xzr, x1"),
        Q!("    ldr             " "x8, [" g!() "+ 2 * " N!() "]"),
        Q!("    eor             " "x1, x8, " s01!()),
        Q!("    mul             " "x0, x1, " m01!()),
        Q!("    umulh           " "x1, x1, " m01!()),
        Q!("    adds            " "x6, x6, x0"),
        Q!("    adc             " "x5, x5, x1"),
        Q!("    extr            " "x2, x6, x2, #59"),
        Q!("    str             " "x2, [" f!() "+ " N!() "]"),

        Q!("    eor             " "x1, x7, " s10!()),
        Q!("    mul             " "x0, x1, " m10!()),
        Q!("    umulh           " "x1, x1, " m10!()),
        Q!("    adds            " "x4, x4, x0"),
        Q!("    adc             " "x2, xzr, x1"),
        Q!("    eor             " "x1, x8, " s11!()),
        Q!("    mul             " "x0, x1, " m11!()),
        Q!("    umulh           " "x1, x1, " m11!()),
        Q!("    adds            " "x4, x4, x0"),
        Q!("    adc             " "x2, x2, x1"),
        Q!("    extr            " "x3, x4, x3, #59"),
        Q!("    str             " "x3, [" g!() "+ " N!() "]"),

        // Digit 3 of [f,g]

        Q!("    ldr             " "x7, [" f!() "+ 3 * " N!() "]"),
        Q!("    eor             " "x1, x7, " s00!()),
        Q!("    mul             " "x0, x1, " m00!()),
        Q!("    umulh           " "x1, x1, " m00!()),
        Q!("    adds            " "x5, x5, x0"),
        Q!("    adc             " "x3, xzr, x1"),
        Q!("    ldr             " "x8, [" g!() "+ 3 * " N!() "]"),
        Q!("    eor             " "x1, x8, " s01!()),
        Q!("    mul             " "x0, x1, " m01!()),
        Q!("    umulh           " "x1, x1, " m01!()),
        Q!("    adds            " "x5, x5, x0"),
        Q!("    adc             " "x3, x3, x1"),
        Q!("    extr            " "x6, x5, x6, #59"),
        Q!("    str             " "x6, [" f!() "+ 2 * " N!() "]"),

        Q!("    eor             " "x1, x7, " s10!()),
        Q!("    mul             " "x0, x1, " m10!()),
        Q!("    umulh           " "x1, x1, " m10!()),
        Q!("    adds            " "x2, x2, x0"),
        Q!("    adc             " "x6, xzr, x1"),
        Q!("    eor             " "x1, x8, " s11!()),
        Q!("    mul             " "x0, x1, " m11!()),
        Q!("    umulh           " "x1, x1, " m11!()),
        Q!("    adds            " "x2, x2, x0"),
        Q!("    adc             " "x6, x6, x1"),
        Q!("    extr            " "x4, x2, x4, #59"),
        Q!("    str             " "x4, [" g!() "+ 2 * " N!() "]"),

        // Digit 4 of [f,g]

        Q!("    ldr             " "x7, [" f!() "+ 4 * " N!() "]"),
        Q!("    eor             " "x1, x7, " s00!()),
        Q!("    mul             " "x0, x1, " m00!()),
        Q!("    umulh           " "x1, x1, " m00!()),
        Q!("    adds            " "x3, x3, x0"),
        Q!("    adc             " "x4, xzr, x1"),
        Q!("    ldr             " "x8, [" g!() "+ 4 * " N!() "]"),
        Q!("    eor             " "x1, x8, " s01!()),
        Q!("    mul             " "x0, x1, " m01!()),
        Q!("    umulh           " "x1, x1, " m01!()),
        Q!("    adds            " "x3, x3, x0"),
        Q!("    adc             " "x4, x4, x1"),
        Q!("    extr            " "x5, x3, x5, #59"),
        Q!("    str             " "x5, [" f!() "+ 3 * " N!() "]"),

        Q!("    eor             " "x1, x7, " s10!()),
        Q!("    mul             " "x0, x1, " m10!()),
        Q!("    umulh           " "x1, x1, " m10!()),
        Q!("    adds            " "x6, x6, x0"),
        Q!("    adc             " "x5, xzr, x1"),
        Q!("    eor             " "x1, x8, " s11!()),
        Q!("    mul             " "x0, x1, " m11!()),
        Q!("    umulh           " "x1, x1, " m11!()),
        Q!("    adds            " "x6, x6, x0"),
        Q!("    adc             " "x5, x5, x1"),
        Q!("    extr            " "x2, x6, x2, #59"),
        Q!("    str             " "x2, [" g!() "+ 3 * " N!() "]"),

        // Digit 5 of [f,g]

        Q!("    ldr             " "x7, [" f!() "+ 5 * " N!() "]"),
        Q!("    eor             " "x1, x7, " s00!()),
        Q!("    mul             " "x0, x1, " m00!()),
        Q!("    umulh           " "x1, x1, " m00!()),
        Q!("    adds            " "x4, x4, x0"),
        Q!("    adc             " "x2, xzr, x1"),
        Q!("    ldr             " "x8, [" g!() "+ 5 * " N!() "]"),
        Q!("    eor             " "x1, x8, " s01!()),
        Q!("    mul             " "x0, x1, " m01!()),
        Q!("    umulh           " "x1, x1, " m01!()),
        Q!("    adds            " "x4, x4, x0"),
        Q!("    adc             " "x2, x2, x1"),
        Q!("    extr            " "x3, x4, x3, #59"),
        Q!("    str             " "x3, [" f!() "+ 4 * " N!() "]"),

        Q!("    eor             " "x1, x7, " s10!()),
        Q!("    mul             " "x0, x1, " m10!()),
        Q!("    umulh           " "x1, x1, " m10!()),
        Q!("    adds            " "x5, x5, x0"),
        Q!("    adc             " "x3, xzr, x1"),
        Q!("    eor             " "x1, x8, " s11!()),
        Q!("    mul             " "x0, x1, " m11!()),
        Q!("    umulh           " "x1, x1, " m11!()),
        Q!("    adds            " "x5, x5, x0"),
        Q!("    adc             " "x3, x3, x1"),
        Q!("    extr            " "x6, x5, x6, #59"),
        Q!("    str             " "x6, [" g!() "+ 4 * " N!() "]"),

        // Digit 6 of [f,g]

        Q!("    ldr             " "x7, [" f!() "+ 6 * " N!() "]"),
        Q!("    eor             " "x1, x7, " s00!()),
        Q!("    mul             " "x0, x1, " m00!()),
        Q!("    umulh           " "x1, x1, " m00!()),
        Q!("    adds            " "x2, x2, x0"),
        Q!("    adc             " "x6, xzr, x1"),
        Q!("    ldr             " "x8, [" g!() "+ 6 * " N!() "]"),
        Q!("    eor             " "x1, x8, " s01!()),
        Q!("    mul             " "x0, x1, " m01!()),
        Q!("    umulh           " "x1, x1, " m01!()),
        Q!("    adds            " "x2, x2, x0"),
        Q!("    adc             " "x6, x6, x1"),
        Q!("    extr            " "x4, x2, x4, #59"),
        Q!("    str             " "x4, [" f!() "+ 5 * " N!() "]"),

        Q!("    eor             " "x1, x7, " s10!()),
        Q!("    mul             " "x0, x1, " m10!()),
        Q!("    umulh           " "x1, x1, " m10!()),
        Q!("    adds            " "x3, x3, x0"),
        Q!("    adc             " "x4, xzr, x1"),
        Q!("    eor             " "x1, x8, " s11!()),
        Q!("    mul             " "x0, x1, " m11!()),
        Q!("    umulh           " "x1, x1, " m11!()),
        Q!("    adds            " "x3, x3, x0"),
        Q!("    adc             " "x4, x4, x1"),
        Q!("    extr            " "x5, x3, x5, #59"),
        Q!("    str             " "x5, [" g!() "+ 5 * " N!() "]"),

        // Digit 7 of [f,g]

        Q!("    ldr             " "x7, [" f!() "+ 7 * " N!() "]"),
        Q!("    eor             " "x1, x7, " s00!()),
        Q!("    mul             " "x0, x1, " m00!()),
        Q!("    umulh           " "x1, x1, " m00!()),
        Q!("    adds            " "x6, x6, x0"),
        Q!("    adc             " "x5, xzr, x1"),
        Q!("    ldr             " "x8, [" g!() "+ 7 * " N!() "]"),
        Q!("    eor             " "x1, x8, " s01!()),
        Q!("    mul             " "x0, x1, " m01!()),
        Q!("    umulh           " "x1, x1, " m01!()),
        Q!("    adds            " "x6, x6, x0"),
        Q!("    adc             " "x5, x5, x1"),
        Q!("    extr            " "x2, x6, x2, #59"),
        Q!("    str             " "x2, [" f!() "+ 6 * " N!() "]"),

        Q!("    eor             " "x1, x7, " s10!()),
        Q!("    mul             " "x0, x1, " m10!()),
        Q!("    umulh           " "x1, x1, " m10!()),
        Q!("    adds            " "x4, x4, x0"),
        Q!("    adc             " "x2, xzr, x1"),
        Q!("    eor             " "x1, x8, " s11!()),
        Q!("    mul             " "x0, x1, " m11!()),
        Q!("    umulh           " "x1, x1, " m11!()),
        Q!("    adds            " "x4, x4, x0"),
        Q!("    adc             " "x2, x2, x1"),
        Q!("    extr            " "x3, x4, x3, #59"),
        Q!("    str             " "x3, [" g!() "+ 6 * " N!() "]"),

        // Digits 8 and 9 of [f,g]

        Q!("    ldr             " "x7, [" f!() "+ 8 * " N!() "]"),
        Q!("    eor             " "x1, x7, " s00!()),
        Q!("    asr             " "x3, x1, #63"),
        Q!("    and             " "x3, x3, " m00!()),
        Q!("    neg             " "x3, x3"),
        Q!("    mul             " "x0, x1, " m00!()),
        Q!("    umulh           " "x1, x1, " m00!()),
        Q!("    adds            " "x5, x5, x0"),
        Q!("    adc             " "x3, x3, x1"),
        Q!("    ldr             " "x8, [" g!() "+ 8 * " N!() "]"),
        Q!("    eor             " "x1, x8, " s01!()),
        Q!("    asr             " "x0, x1, #63"),
        Q!("    and             " "x0, x0, " m01!()),
        Q!("    sub             " "x3, x3, x0"),
        Q!("    mul             " "x0, x1, " m01!()),
        Q!("    umulh           " "x1, x1, " m01!()),
        Q!("    adds            " "x5, x5, x0"),
        Q!("    adc             " "x3, x3, x1"),
        Q!("    extr            " "x6, x5, x6, #59"),
        Q!("    str             " "x6, [" f!() "+ 7 * " N!() "]"),
        Q!("    extr            " "x5, x3, x5, #59"),
        Q!("    str             " "x5, [" f!() "+ 8 * " N!() "]"),

        Q!("    eor             " "x1, x7, " s10!()),
        Q!("    asr             " "x5, x1, #63"),
        Q!("    and             " "x5, x5, " m10!()),
        Q!("    neg             " "x5, x5"),
        Q!("    mul             " "x0, x1, " m10!()),
        Q!("    umulh           " "x1, x1, " m10!()),
        Q!("    adds            " "x2, x2, x0"),
        Q!("    adc             " "x5, x5, x1"),
        Q!("    eor             " "x1, x8, " s11!()),
        Q!("    asr             " "x0, x1, #63"),
        Q!("    and             " "x0, x0, " m11!()),
        Q!("    sub             " "x5, x5, x0"),
        Q!("    mul             " "x0, x1, " m11!()),
        Q!("    umulh           " "x1, x1, " m11!()),
        Q!("    adds            " "x2, x2, x0"),
        Q!("    adc             " "x5, x5, x1"),
        Q!("    extr            " "x4, x2, x4, #59"),
        Q!("    str             " "x4, [" g!() "+ 7 * " N!() "]"),
        Q!("    extr            " "x2, x5, x2, #59"),
        Q!("    str             " "x2, [" g!() "+ 8 * " N!() "]"),

        // Now the computation of the updated u and v values and their
        // modular reductions. A very similar accumulation except that
        // the top words of u and v are unsigned and we don't shift.
        //
        // Digit 0 of [u,v]

        Q!("    ldr             " "x7, [" u!() "]"),
        Q!("    eor             " "x1, x7, " s00!()),
        Q!("    mul             " "x0, x1, " m00!()),
        Q!("    umulh           " "x1, x1, " m00!()),
        Q!("    adds            " "x4, " car0!() ", x0"),
        Q!("    adc             " "x2, xzr, x1"),
        Q!("    ldr             " "x8, [" v!() "]"),
        Q!("    eor             " "x1, x8, " s01!()),
        Q!("    mul             " "x0, x1, " m01!()),
        Q!("    umulh           " "x1, x1, " m01!()),
        Q!("    adds            " "x4, x4, x0"),
        Q!("    str             " "x4, [" u!() "]"),
        Q!("    adc             " "x2, x2, x1"),

        Q!("    eor             " "x1, x7, " s10!()),
        Q!("    mul             " "x0, x1, " m10!()),
        Q!("    umulh           " "x1, x1, " m10!()),
        Q!("    adds            " "x5, " car1!() ", x0"),
        Q!("    adc             " "x3, xzr, x1"),
        Q!("    eor             " "x1, x8, " s11!()),
        Q!("    mul             " "x0, x1, " m11!()),
        Q!("    umulh           " "x1, x1, " m11!()),
        Q!("    adds            " "x5, x5, x0"),
        Q!("    str             " "x5, [" v!() "]"),
        Q!("    adc             " "x3, x3, x1"),

        // Digit 1 of [u,v]

        Q!("    ldr             " "x7, [" u!() "+ " N!() "]"),
        Q!("    eor             " "x1, x7, " s00!()),
        Q!("    mul             " "x0, x1, " m00!()),
        Q!("    umulh           " "x1, x1, " m00!()),
        Q!("    adds            " "x2, x2, x0"),
        Q!("    adc             " "x6, xzr, x1"),
        Q!("    ldr             " "x8, [" v!() "+ " N!() "]"),
        Q!("    eor             " "x1, x8, " s01!()),
        Q!("    mul             " "x0, x1, " m01!()),
        Q!("    umulh           " "x1, x1, " m01!()),
        Q!("    adds            " "x2, x2, x0"),
        Q!("    str             " "x2, [" u!() "+ " N!() "]"),
        Q!("    adc             " "x6, x6, x1"),

        Q!("    eor             " "x1, x7, " s10!()),
        Q!("    mul             " "x0, x1, " m10!()),
        Q!("    umulh           " "x1, x1, " m10!()),
        Q!("    adds            " "x3, x3, x0"),
        Q!("    adc             " "x4, xzr, x1"),
        Q!("    eor             " "x1, x8, " s11!()),
        Q!("    mul             " "x0, x1, " m11!()),
        Q!("    umulh           " "x1, x1, " m11!()),
        Q!("    adds            " "x3, x3, x0"),
        Q!("    str             " "x3, [" v!() "+ " N!() "]"),
        Q!("    adc             " "x4, x4, x1"),

        // Digit 2 of [u,v]

        Q!("    ldr             " "x7, [" u!() "+ 2 * " N!() "]"),
        Q!("    eor             " "x1, x7, " s00!()),
        Q!("    mul             " "x0, x1, " m00!()),
        Q!("    umulh           " "x1, x1, " m00!()),
        Q!("    adds            " "x6, x6, x0"),
        Q!("    adc             " "x5, xzr, x1"),
        Q!("    ldr             " "x8, [" v!() "+ 2 * " N!() "]"),
        Q!("    eor             " "x1, x8, " s01!()),
        Q!("    mul             " "x0, x1, " m01!()),
        Q!("    umulh           " "x1, x1, " m01!()),
        Q!("    adds            " "x6, x6, x0"),
        Q!("    str             " "x6, [" u!() "+ 2 * " N!() "]"),
        Q!("    adc             " "x5, x5, x1"),

        Q!("    eor             " "x1, x7, " s10!()),
        Q!("    mul             " "x0, x1, " m10!()),
        Q!("    umulh           " "x1, x1, " m10!()),
        Q!("    adds            " "x4, x4, x0"),
        Q!("    adc             " "x2, xzr, x1"),
        Q!("    eor             " "x1, x8, " s11!()),
        Q!("    mul             " "x0, x1, " m11!()),
        Q!("    umulh           " "x1, x1, " m11!()),
        Q!("    adds            " "x4, x4, x0"),
        Q!("    str             " "x4, [" v!() "+ 2 * " N!() "]"),
        Q!("    adc             " "x2, x2, x1"),

        // Digit 3 of [u,v]

        Q!("    ldr             " "x7, [" u!() "+ 3 * " N!() "]"),
        Q!("    eor             " "x1, x7, " s00!()),
        Q!("    mul             " "x0, x1, " m00!()),
        Q!("    umulh           " "x1, x1, " m00!()),
        Q!("    adds            " "x5, x5, x0"),
        Q!("    adc             " "x3, xzr, x1"),
        Q!("    ldr             " "x8, [" v!() "+ 3 * " N!() "]"),
        Q!("    eor             " "x1, x8, " s01!()),
        Q!("    mul             " "x0, x1, " m01!()),
        Q!("    umulh           " "x1, x1, " m01!()),
        Q!("    adds            " "x5, x5, x0"),
        Q!("    str             " "x5, [" u!() "+ 3 * " N!() "]"),
        Q!("    adc             " "x3, x3, x1"),

        Q!("    eor             " "x1, x7, " s10!()),
        Q!("    mul             " "x0, x1, " m10!()),
        Q!("    umulh           " "x1, x1, " m10!()),
        Q!("    adds            " "x2, x2, x0"),
        Q!("    adc             " "x6, xzr, x1"),
        Q!("    eor             " "x1, x8, " s11!()),
        Q!("    mul             " "x0, x1, " m11!()),
        Q!("    umulh           " "x1, x1, " m11!()),
        Q!("    adds            " "x2, x2, x0"),
        Q!("    str             " "x2, [" v!() "+ 3 * " N!() "]"),
        Q!("    adc             " "x6, x6, x1"),

        // Digit 4 of [u,v]

        Q!("    ldr             " "x7, [" u!() "+ 4 * " N!() "]"),
        Q!("    eor             " "x1, x7, " s00!()),
        Q!("    mul             " "x0, x1, " m00!()),
        Q!("    umulh           " "x1, x1, " m00!()),
        Q!("    adds            " "x3, x3, x0"),
        Q!("    adc             " "x4, xzr, x1"),
        Q!("    ldr             " "x8, [" v!() "+ 4 * " N!() "]"),
        Q!("    eor             " "x1, x8, " s01!()),
        Q!("    mul             " "x0, x1, " m01!()),
        Q!("    umulh           " "x1, x1, " m01!()),
        Q!("    adds            " "x3, x3, x0"),
        Q!("    str             " "x3, [" u!() "+ 4 * " N!() "]"),
        Q!("    adc             " "x4, x4, x1"),

        Q!("    eor             " "x1, x7, " s10!()),
        Q!("    mul             " "x0, x1, " m10!()),
        Q!("    umulh           " "x1, x1, " m10!()),
        Q!("    adds            " "x6, x6, x0"),
        Q!("    adc             " "x5, xzr, x1"),
        Q!("    eor             " "x1, x8, " s11!()),
        Q!("    mul             " "x0, x1, " m11!()),
        Q!("    umulh           " "x1, x1, " m11!()),
        Q!("    adds            " "x6, x6, x0"),
        Q!("    str             " "x6, [" v!() "+ 4 * " N!() "]"),
        Q!("    adc             " "x5, x5, x1"),

        // Digit 5 of [u,v]

        Q!("    ldr             " "x7, [" u!() "+ 5 * " N!() "]"),
        Q!("    eor             " "x1, x7, " s00!()),
        Q!("    mul             " "x0, x1, " m00!()),
        Q!("    umulh           " "x1, x1, " m00!()),
        Q!("    adds            " "x4, x4, x0"),
        Q!("    adc             " "x2, xzr, x1"),
        Q!("    ldr             " "x8, [" v!() "+ 5 * " N!() "]"),
        Q!("    eor             " "x1, x8, " s01!()),
        Q!("    mul             " "x0, x1, " m01!()),
        Q!("    umulh           " "x1, x1, " m01!()),
        Q!("    adds            " "x4, x4, x0"),
        Q!("    str             " "x4, [" u!() "+ 5 * " N!() "]"),
        Q!("    adc             " "x2, x2, x1"),

        Q!("    eor             " "x1, x7, " s10!()),
        Q!("    mul             " "x0, x1, " m10!()),
        Q!("    umulh           " "x1, x1, " m10!()),
        Q!("    adds            " "x5, x5, x0"),
        Q!("    adc             " "x3, xzr, x1"),
        Q!("    eor             " "x1, x8, " s11!()),
        Q!("    mul             " "x0, x1, " m11!()),
        Q!("    umulh           " "x1, x1, " m11!()),
        Q!("    adds            " "x5, x5, x0"),
        Q!("    str             " "x5, [" v!() "+ 5 * " N!() "]"),
        Q!("    adc             " "x3, x3, x1"),

        // Digit 6 of [u,v]

        Q!("    ldr             " "x7, [" u!() "+ 6 * " N!() "]"),
        Q!("    eor             " "x1, x7, " s00!()),
        Q!("    mul             " "x0, x1, " m00!()),
        Q!("    umulh           " "x1, x1, " m00!()),
        Q!("    adds            " "x2, x2, x0"),
        Q!("    adc             " "x6, xzr, x1"),
        Q!("    ldr             " "x8, [" v!() "+ 6 * " N!() "]"),
        Q!("    eor             " "x1, x8, " s01!()),
        Q!("    mul             " "x0, x1, " m01!()),
        Q!("    umulh           " "x1, x1, " m01!()),
        Q!("    adds            " "x2, x2, x0"),
        Q!("    str             " "x2, [" u!() "+ 6 * " N!() "]"),
        Q!("    adc             " "x6, x6, x1"),

        Q!("    eor             " "x1, x7, " s10!()),
        Q!("    mul             " "x0, x1, " m10!()),
        Q!("    umulh           " "x1, x1, " m10!()),
        Q!("    adds            " "x3, x3, x0"),
        Q!("    adc             " "x4, xzr, x1"),
        Q!("    eor             " "x1, x8, " s11!()),
        Q!("    mul             " "x0, x1, " m11!()),
        Q!("    umulh           " "x1, x1, " m11!()),
        Q!("    adds            " "x3, x3, x0"),
        Q!("    str             " "x3, [" v!() "+ 6 * " N!() "]"),
        Q!("    adc             " "x4, x4, x1"),

        // Digit 7 of [u,v]

        Q!("    ldr             " "x7, [" u!() "+ 7 * " N!() "]"),
        Q!("    eor             " "x1, x7, " s00!()),
        Q!("    mul             " "x0, x1, " m00!()),
        Q!("    umulh           " "x1, x1, " m00!()),
        Q!("    adds            " "x6, x6, x0"),
        Q!("    adc             " "x5, xzr, x1"),
        Q!("    ldr             " "x8, [" v!() "+ 7 * " N!() "]"),
        Q!("    eor             " "x1, x8, " s01!()),
        Q!("    mul             " "x0, x1, " m01!()),
        Q!("    umulh           " "x1, x1, " m01!()),
        Q!("    adds            " "x6, x6, x0"),
        Q!("    str             " "x6, [" u!() "+ 7 * " N!() "]"),
        Q!("    adc             " "x5, x5, x1"),

        Q!("    eor             " "x1, x7, " s10!()),
        Q!("    mul             " "x0, x1, " m10!()),
        Q!("    umulh           " "x1, x1, " m10!()),
        Q!("    adds            " "x4, x4, x0"),
        Q!("    adc             " "x2, xzr, x1"),
        Q!("    eor             " "x1, x8, " s11!()),
        Q!("    mul             " "x0, x1, " m11!()),
        Q!("    umulh           " "x1, x1, " m11!()),
        Q!("    adds            " "x4, x4, x0"),
        Q!("    str             " "x4, [" v!() "+ 7 * " N!() "]"),
        Q!("    adc             " "x2, x2, x1"),

        // Digits 8 and 9 of u (top is unsigned)

        Q!("    ldr             " "x7, [" u!() "+ 8 * " N!() "]"),
        Q!("    eor             " "x1, x7, " s00!()),
        Q!("    and             " "x3, " s00!() ", " m00!()),
        Q!("    neg             " "x3, x3"),
        Q!("    mul             " "x0, x1, " m00!()),
        Q!("    umulh           " "x1, x1, " m00!()),
        Q!("    adds            " "x5, x5, x0"),
        Q!("    adc             " "x3, x3, x1"),
        Q!("    ldr             " "x8, [" v!() "+ 8 * " N!() "]"),
        Q!("    eor             " "x1, x8, " s01!()),
        Q!("    and             " "x0, " s01!() ", " m01!()),
        Q!("    sub             " "x3, x3, x0"),
        Q!("    mul             " "x0, x1, " m01!()),
        Q!("    umulh           " "x1, x1, " m01!()),
        Q!("    adds            " "x5, x5, x0"),
        Q!("    adc             " "x3, x3, x1"),

        // Modular reduction of u, reloading as needed from u[0],...,u[7],x5,x3

        Q!("    extr            " "x6, x3, x5, #9"),
        Q!("    ldp             " "x0, x1, [" u!() "]"),
        Q!("    add             " "x6, x6, x3, asr #63"),
        Q!("    sub             " "x5, x5, x6, lsl #9"),
        Q!("    adds            " "x0, x0, x6"),
        Q!("    asr             " "x6, x6, #63"),
        Q!("    adcs            " "x1, x1, x6"),
        Q!("    stp             " "x0, x1, [" u!() "]"),
        Q!("    ldp             " "x0, x1, [" u!() "+ 16]"),
        Q!("    adcs            " "x0, x0, x6"),
        Q!("    adcs            " "x1, x1, x6"),
        Q!("    stp             " "x0, x1, [" u!() "+ 16]"),
        Q!("    ldp             " "x0, x1, [" u!() "+ 32]"),
        Q!("    adcs            " "x0, x0, x6"),
        Q!("    adcs            " "x1, x1, x6"),
        Q!("    stp             " "x0, x1, [" u!() "+ 32]"),
        Q!("    ldp             " "x0, x1, [" u!() "+ 48]"),
        Q!("    adcs            " "x0, x0, x6"),
        Q!("    adcs            " "x1, x1, x6"),
        Q!("    stp             " "x0, x1, [" u!() "+ 48]"),
        Q!("    adc             " "x5, x5, x6"),
        Q!("    str             " "x5, [" u!() "+ 64]"),

        // Digits 8 and 9 of v (top is unsigned)

        Q!("    eor             " "x1, x7, " s10!()),
        Q!("    and             " "x5, " s10!() ", " m10!()),
        Q!("    neg             " "x5, x5"),
        Q!("    mul             " "x0, x1, " m10!()),
        Q!("    umulh           " "x1, x1, " m10!()),
        Q!("    adds            " "x2, x2, x0"),
        Q!("    adc             " "x5, x5, x1"),
        Q!("    eor             " "x1, x8, " s11!()),
        Q!("    and             " "x0, " s11!() ", " m11!()),
        Q!("    sub             " "x5, x5, x0"),
        Q!("    mul             " "x0, x1, " m11!()),
        Q!("    umulh           " "x1, x1, " m11!()),
        Q!("    adds            " "x2, x2, x0"),
        Q!("    adc             " "x5, x5, x1"),

        // Modular reduction of v, reloading as needed from v[0],...,v[7],x2,x5

        Q!("    extr            " "x6, x5, x2, #9"),
        Q!("    ldp             " "x0, x1, [" v!() "]"),
        Q!("    add             " "x6, x6, x5, asr #63"),
        Q!("    sub             " "x2, x2, x6, lsl #9"),
        Q!("    adds            " "x0, x0, x6"),
        Q!("    asr             " "x6, x6, #63"),
        Q!("    adcs            " "x1, x1, x6"),
        Q!("    stp             " "x0, x1, [" v!() "]"),
        Q!("    ldp             " "x0, x1, [" v!() "+ 16]"),
        Q!("    adcs            " "x0, x0, x6"),
        Q!("    adcs            " "x1, x1, x6"),
        Q!("    stp             " "x0, x1, [" v!() "+ 16]"),
        Q!("    ldp             " "x0, x1, [" v!() "+ 32]"),
        Q!("    adcs            " "x0, x0, x6"),
        Q!("    adcs            " "x1, x1, x6"),
        Q!("    stp             " "x0, x1, [" v!() "+ 32]"),
        Q!("    ldp             " "x0, x1, [" v!() "+ 48]"),
        Q!("    adcs            " "x0, x0, x6"),
        Q!("    adcs            " "x1, x1, x6"),
        Q!("    stp             " "x0, x1, [" v!() "+ 48]"),
        Q!("    adc             " "x2, x2, x6"),
        Q!("    str             " "x2, [" v!() "+ 64]"),

        Q!(Label!("Lbignum_inv_p521_midloop", 2) ":"),

        Q!("    mov             " "x1, " d!()),
        Q!("    ldr             " "x2, [" f!() "]"),
        Q!("    ldr             " "x3, [" g!() "]"),
        divstep59!(),
        Q!("    mov             " d!() ", x1"),

        // Next iteration

        Q!("    subs            " i!() ", " i!() ", #1"),
        Q!("    bne             " Label!("Lbignum_inv_p521_loop", 3, Before)),

        // The 21st and last iteration does not need anything except the
        // u value and the sign of f; the latter can be obtained from the
        // lowest word of f. So it's done differently from the main loop.
        // Find the sign of the new f. For this we just need one digit
        // since we know (for in-scope cases) that f is either +1 or -1.
        // We don't explicitly shift right by 59 either, but looking at
        // bit 63 (or any bit >= 60) of the unshifted result is enough
        // to distinguish -1 from +1; this is then made into a mask.

        Q!("    ldr             " "x0, [" f!() "]"),
        Q!("    ldr             " "x1, [" g!() "]"),
        Q!("    mul             " "x0, x0, " m00!()),
        Q!("    madd            " "x1, x1, " m01!() ", x0"),
        Q!("    asr             " "x0, x1, #63"),

        // Now separate out the matrix into sign-magnitude pairs
        // and adjust each one based on the sign of f.
        //
        // Note that at this point we expect |f|=1 and we got its
        // sign above, so then since [f,0] == x * [u,v] (mod p_521)
        // we want to flip the sign of u according to that of f.

        Q!("    cmp             " m00!() ", xzr"),
        Q!("    csetm           " s00!() ", mi"),
        Q!("    cneg            " m00!() ", " m00!() ", mi"),
        Q!("    eor             " s00!() ", " s00!() ", x0"),

        Q!("    cmp             " m01!() ", xzr"),
        Q!("    csetm           " s01!() ", mi"),
        Q!("    cneg            " m01!() ", " m01!() ", mi"),
        Q!("    eor             " s01!() ", " s01!() ", x0"),

        Q!("    cmp             " m10!() ", xzr"),
        Q!("    csetm           " s10!() ", mi"),
        Q!("    cneg            " m10!() ", " m10!() ", mi"),
        Q!("    eor             " s10!() ", " s10!() ", x0"),

        Q!("    cmp             " m11!() ", xzr"),
        Q!("    csetm           " s11!() ", mi"),
        Q!("    cneg            " m11!() ", " m11!() ", mi"),
        Q!("    eor             " s11!() ", " s11!() ", x0"),

        // Adjust the initial value to allow for complement instead of negation

        Q!("    and             " "x0, " m00!() ", " s00!()),
        Q!("    and             " "x1, " m01!() ", " s01!()),
        Q!("    add             " car0!() ", x0, x1"),

        // Digit 0 of [u]

        Q!("    ldr             " "x7, [" u!() "]"),
        Q!("    eor             " "x1, x7, " s00!()),
        Q!("    mul             " "x0, x1, " m00!()),
        Q!("    umulh           " "x1, x1, " m00!()),
        Q!("    adds            " "x4, " car0!() ", x0"),
        Q!("    adc             " "x2, xzr, x1"),
        Q!("    ldr             " "x8, [" v!() "]"),
        Q!("    eor             " "x1, x8, " s01!()),
        Q!("    mul             " "x0, x1, " m01!()),
        Q!("    umulh           " "x1, x1, " m01!()),
        Q!("    adds            " "x4, x4, x0"),
        Q!("    str             " "x4, [" u!() "]"),
        Q!("    adc             " "x2, x2, x1"),

        // Digit 1 of [u]

        Q!("    ldr             " "x7, [" u!() "+ " N!() "]"),
        Q!("    eor             " "x1, x7, " s00!()),
        Q!("    mul             " "x0, x1, " m00!()),
        Q!("    umulh           " "x1, x1, " m00!()),
        Q!("    adds            " "x2, x2, x0"),
        Q!("    adc             " "x6, xzr, x1"),
        Q!("    ldr             " "x8, [" v!() "+ " N!() "]"),
        Q!("    eor             " "x1, x8, " s01!()),
        Q!("    mul             " "x0, x1, " m01!()),
        Q!("    umulh           " "x1, x1, " m01!()),
        Q!("    adds            " "x2, x2, x0"),
        Q!("    str             " "x2, [" u!() "+ " N!() "]"),
        Q!("    adc             " "x6, x6, x1"),

        // Digit 2 of [u]

        Q!("    ldr             " "x7, [" u!() "+ 2 * " N!() "]"),
        Q!("    eor             " "x1, x7, " s00!()),
        Q!("    mul             " "x0, x1, " m00!()),
        Q!("    umulh           " "x1, x1, " m00!()),
        Q!("    adds            " "x6, x6, x0"),
        Q!("    adc             " "x5, xzr, x1"),
        Q!("    ldr             " "x8, [" v!() "+ 2 * " N!() "]"),
        Q!("    eor             " "x1, x8, " s01!()),
        Q!("    mul             " "x0, x1, " m01!()),
        Q!("    umulh           " "x1, x1, " m01!()),
        Q!("    adds            " "x6, x6, x0"),
        Q!("    str             " "x6, [" u!() "+ 2 * " N!() "]"),
        Q!("    adc             " "x5, x5, x1"),

        // Digit 3 of [u]

        Q!("    ldr             " "x7, [" u!() "+ 3 * " N!() "]"),
        Q!("    eor             " "x1, x7, " s00!()),
        Q!("    mul             " "x0, x1, " m00!()),
        Q!("    umulh           " "x1, x1, " m00!()),
        Q!("    adds            " "x5, x5, x0"),
        Q!("    adc             " "x3, xzr, x1"),
        Q!("    ldr             " "x8, [" v!() "+ 3 * " N!() "]"),
        Q!("    eor             " "x1, x8, " s01!()),
        Q!("    mul             " "x0, x1, " m01!()),
        Q!("    umulh           " "x1, x1, " m01!()),
        Q!("    adds            " "x5, x5, x0"),
        Q!("    str             " "x5, [" u!() "+ 3 * " N!() "]"),
        Q!("    adc             " "x3, x3, x1"),

        // Digit 4 of [u]

        Q!("    ldr             " "x7, [" u!() "+ 4 * " N!() "]"),
        Q!("    eor             " "x1, x7, " s00!()),
        Q!("    mul             " "x0, x1, " m00!()),
        Q!("    umulh           " "x1, x1, " m00!()),
        Q!("    adds            " "x3, x3, x0"),
        Q!("    adc             " "x4, xzr, x1"),
        Q!("    ldr             " "x8, [" v!() "+ 4 * " N!() "]"),
        Q!("    eor             " "x1, x8, " s01!()),
        Q!("    mul             " "x0, x1, " m01!()),
        Q!("    umulh           " "x1, x1, " m01!()),
        Q!("    adds            " "x3, x3, x0"),
        Q!("    str             " "x3, [" u!() "+ 4 * " N!() "]"),
        Q!("    adc             " "x4, x4, x1"),

        // Digit 5 of [u]

        Q!("    ldr             " "x7, [" u!() "+ 5 * " N!() "]"),
        Q!("    eor             " "x1, x7, " s00!()),
        Q!("    mul             " "x0, x1, " m00!()),
        Q!("    umulh           " "x1, x1, " m00!()),
        Q!("    adds            " "x4, x4, x0"),
        Q!("    adc             " "x2, xzr, x1"),
        Q!("    ldr             " "x8, [" v!() "+ 5 * " N!() "]"),
        Q!("    eor             " "x1, x8, " s01!()),
        Q!("    mul             " "x0, x1, " m01!()),
        Q!("    umulh           " "x1, x1, " m01!()),
        Q!("    adds            " "x4, x4, x0"),
        Q!("    str             " "x4, [" u!() "+ 5 * " N!() "]"),
        Q!("    adc             " "x2, x2, x1"),

        // Digit 6 of [u]

        Q!("    ldr             " "x7, [" u!() "+ 6 * " N!() "]"),
        Q!("    eor             " "x1, x7, " s00!()),
        Q!("    mul             " "x0, x1, " m00!()),
        Q!("    umulh           " "x1, x1, " m00!()),
        Q!("    adds            " "x2, x2, x0"),
        Q!("    adc             " "x6, xzr, x1"),
        Q!("    ldr             " "x8, [" v!() "+ 6 * " N!() "]"),
        Q!("    eor             " "x1, x8, " s01!()),
        Q!("    mul             " "x0, x1, " m01!()),
        Q!("    umulh           " "x1, x1, " m01!()),
        Q!("    adds            " "x2, x2, x0"),
        Q!("    str             " "x2, [" u!() "+ 6 * " N!() "]"),
        Q!("    adc             " "x6, x6, x1"),

        // Digit 7 of [u]

        Q!("    ldr             " "x7, [" u!() "+ 7 * " N!() "]"),
        Q!("    eor             " "x1, x7, " s00!()),
        Q!("    mul             " "x0, x1, " m00!()),
        Q!("    umulh           " "x1, x1, " m00!()),
        Q!("    adds            " "x6, x6, x0"),
        Q!("    adc             " "x5, xzr, x1"),
        Q!("    ldr             " "x8, [" v!() "+ 7 * " N!() "]"),
        Q!("    eor             " "x1, x8, " s01!()),
        Q!("    mul             " "x0, x1, " m01!()),
        Q!("    umulh           " "x1, x1, " m01!()),
        Q!("    adds            " "x6, x6, x0"),
        Q!("    str             " "x6, [" u!() "+ 7 * " N!() "]"),
        Q!("    adc             " "x5, x5, x1"),

        // Digits 8 and 9 of u (top is unsigned)

        Q!("    ldr             " "x7, [" u!() "+ 8 * " N!() "]"),
        Q!("    eor             " "x1, x7, " s00!()),
        Q!("    and             " "x3, " s00!() ", " m00!()),
        Q!("    neg             " "x3, x3"),
        Q!("    mul             " "x0, x1, " m00!()),
        Q!("    umulh           " "x1, x1, " m00!()),
        Q!("    adds            " "x5, x5, x0"),
        Q!("    adc             " "x3, x3, x1"),
        Q!("    ldr             " "x8, [" v!() "+ 8 * " N!() "]"),
        Q!("    eor             " "x1, x8, " s01!()),
        Q!("    and             " "x0, " s01!() ", " m01!()),
        Q!("    sub             " "x3, x3, x0"),
        Q!("    mul             " "x0, x1, " m01!()),
        Q!("    umulh           " "x1, x1, " m01!()),
        Q!("    adds            " "x5, x5, x0"),
        Q!("    adc             " "x3, x3, x1"),

        // Modular reduction of u, reloading as needed from u[0],...,u[7],x5,x3

        Q!("    extr            " "x6, x3, x5, #9"),
        Q!("    ldp             " "x10, x11, [" u!() "]"),
        Q!("    add             " "x6, x6, x3, asr #63"),
        Q!("    sub             " "x5, x5, x6, lsl #9"),
        Q!("    adds            " "x10, x10, x6"),
        Q!("    asr             " "x6, x6, #63"),
        Q!("    adcs            " "x11, x11, x6"),
        Q!("    ldp             " "x12, x13, [" u!() "+ 16]"),
        Q!("    adcs            " "x12, x12, x6"),
        Q!("    adcs            " "x13, x13, x6"),
        Q!("    ldp             " "x14, x15, [" u!() "+ 32]"),
        Q!("    adcs            " "x14, x14, x6"),
        Q!("    adcs            " "x15, x15, x6"),
        Q!("    ldp             " "x16, x17, [" u!() "+ 48]"),
        Q!("    adcs            " "x16, x16, x6"),
        Q!("    adcs            " "x17, x17, x6"),
        Q!("    adc             " "x19, x5, x6"),

        // Further strict reduction ready for the output, which just means
        // a conditional subtraction of p_521

        Q!("    subs            " "x0, x10, #-1"),
        Q!("    adcs            " "x1, x11, xzr"),
        Q!("    adcs            " "x2, x12, xzr"),
        Q!("    adcs            " "x3, x13, xzr"),
        Q!("    adcs            " "x4, x14, xzr"),
        Q!("    adcs            " "x5, x15, xzr"),
        Q!("    adcs            " "x6, x16, xzr"),
        Q!("    adcs            " "x7, x17, xzr"),
        Q!("    mov             " "x8, #0x1FF"),
        Q!("    sbcs            " "x8, x19, x8"),

        Q!("    csel            " "x0, x0, x10, cs"),
        Q!("    csel            " "x1, x1, x11, cs"),
        Q!("    csel            " "x2, x2, x12, cs"),
        Q!("    csel            " "x3, x3, x13, cs"),
        Q!("    csel            " "x4, x4, x14, cs"),
        Q!("    csel            " "x5, x5, x15, cs"),
        Q!("    csel            " "x6, x6, x16, cs"),
        Q!("    csel            " "x7, x7, x17, cs"),
        Q!("    csel            " "x8, x8, x19, cs"),

        // Store it back to the final output

        Q!("    stp             " "x0, x1, [" res!() "]"),
        Q!("    stp             " "x2, x3, [" res!() ", #16]"),
        Q!("    stp             " "x4, x5, [" res!() ", #32]"),
        Q!("    stp             " "x6, x7, [" res!() ", #48]"),
        Q!("    str             " "x8, [" res!() ", #64]"),

        // Restore stack and registers

        Q!("    add             " "sp, sp, # (" NSPACE!() "+ 0)"),
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
