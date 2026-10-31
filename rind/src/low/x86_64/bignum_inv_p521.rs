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
// Standard x86-64 ABI: RDI = z, RSI = x
// Microsoft x64 ABI:   RCX = z, RDX = x
// ----------------------------------------------------------------------------

// Size in bytes of a 64-bit word

macro_rules! N {
    () => {
        "8"
    };
}

// Pointer-offset pairs for temporaries on stack

macro_rules! f {
    () => {
        "rsp + 0"
    };
}
macro_rules! g { () => { Q!("rsp + (9 * " N!() ")") } }
macro_rules! u { () => { Q!("rsp + (18 * " N!() ")") } }
macro_rules! v { () => { Q!("rsp + (27 * " N!() ")") } }
macro_rules! tmp { () => { Q!("QWORD PTR [rsp + (36 * " N!() ")]") } }
macro_rules! tmp2 { () => { Q!("QWORD PTR [rsp + (37 * " N!() ")]") } }
macro_rules! i { () => { Q!("QWORD PTR [rsp + (38 * " N!() ")]") } }
macro_rules! d { () => { Q!("QWORD PTR [rsp + (39 * " N!() ")]") } }

macro_rules! mat { () => { Q!("rsp + (40 * " N!() ")") } }

// Backup for the input pointer

macro_rules! res { () => { Q!("QWORD PTR [rsp + (44 * " N!() ")]") } }

// Total size to reserve on the stack

macro_rules! NSPACE { () => { Q!("45 * " N!()) } }

// Syntactic variants to make x86_att version simpler to generate

macro_rules! F {
    () => {
        "0"
    };
}
macro_rules! G { () => { Q!("(9 * " N!() ")") } }
macro_rules! U { () => { Q!("(18 * " N!() ")") } }
macro_rules! V { () => { Q!("(27 * " N!() ")") } }
macro_rules! MAT { () => { Q!("(40 * " N!() ")") } }

macro_rules! ff {
    () => {
        "QWORD PTR [rsp]"
    };
}
macro_rules! gg { () => { Q!("QWORD PTR [rsp + (9 * " N!() ")]") } }

// Very similar to a subroutine call to the s2n-bignum word_divstep59.
// But different in register usage and returning the final matrix as
//
// [ r8   r10]
// [ r12  r14]
//
// and also returning the matrix still negated (which doesn't matter)

macro_rules! divstep59 {
    ($din:expr, $fin:expr, $gin:expr) => { Q!(
        "mov rsi, " $din ";\n"
        "mov rdx, " $fin ";\n"
        "mov rcx, " $gin ";\n"
        "mov rbx, rdx;\n"
        "and rbx, 0xfffff;\n"
        "movabs rax, 0xfffffe0000000000;\n"
        "or rbx, rax;\n"
        "and rcx, 0xfffff;\n"
        "movabs rax, 0xc000000000000000;\n"
        "or rcx, rax;\n"
        "mov rax, 0xfffffffffffffffe;\n"
        "xor ebp, ebp;\n"
        "mov edx, 0x2;\n"
        "mov rdi, rbx;\n"
        "mov r8, rax;\n"
        "test rsi, rsi;\n"
        "cmovs r8, rbp;\n"
        "test rcx, 0x1;\n"
        "cmove r8, rbp;\n"
        "cmove rdi, rbp;\n"
        "xor rdi, r8;\n"
        "xor rsi, r8;\n"
        "bt r8, 0x3f;\n"
        "cmovb rbx, rcx;\n"
        "mov r8, rax;\n"
        "sub rsi, rax;\n"
        "lea rcx, [rcx + rdi];\n"
        "cmovs r8, rbp;\n"
        "mov rdi, rbx;\n"
        "test rcx, rdx;\n"
        "cmove r8, rbp;\n"
        "cmove rdi, rbp;\n"
        "sar rcx, 1;\n"
        "xor rdi, r8;\n"
        "xor rsi, r8;\n"
        "bt r8, 0x3f;\n"
        "cmovb rbx, rcx;\n"
        "mov r8, rax;\n"
        "sub rsi, rax;\n"
        "lea rcx, [rcx + rdi];\n"
        "cmovs r8, rbp;\n"
        "mov rdi, rbx;\n"
        "test rcx, rdx;\n"
        "cmove r8, rbp;\n"
        "cmove rdi, rbp;\n"
        "sar rcx, 1;\n"
        "xor rdi, r8;\n"
        "xor rsi, r8;\n"
        "bt r8, 0x3f;\n"
        "cmovb rbx, rcx;\n"
        "mov r8, rax;\n"
        "sub rsi, rax;\n"
        "lea rcx, [rcx + rdi];\n"
        "cmovs r8, rbp;\n"
        "mov rdi, rbx;\n"
        "test rcx, rdx;\n"
        "cmove r8, rbp;\n"
        "cmove rdi, rbp;\n"
        "sar rcx, 1;\n"
        "xor rdi, r8;\n"
        "xor rsi, r8;\n"
        "bt r8, 0x3f;\n"
        "cmovb rbx, rcx;\n"
        "mov r8, rax;\n"
        "sub rsi, rax;\n"
        "lea rcx, [rcx + rdi];\n"
        "cmovs r8, rbp;\n"
        "mov rdi, rbx;\n"
        "test rcx, rdx;\n"
        "cmove r8, rbp;\n"
        "cmove rdi, rbp;\n"
        "sar rcx, 1;\n"
        "xor rdi, r8;\n"
        "xor rsi, r8;\n"
        "bt r8, 0x3f;\n"
        "cmovb rbx, rcx;\n"
        "mov r8, rax;\n"
        "sub rsi, rax;\n"
        "lea rcx, [rcx + rdi];\n"
        "cmovs r8, rbp;\n"
        "mov rdi, rbx;\n"
        "test rcx, rdx;\n"
        "cmove r8, rbp;\n"
        "cmove rdi, rbp;\n"
        "sar rcx, 1;\n"
        "xor rdi, r8;\n"
        "xor rsi, r8;\n"
        "bt r8, 0x3f;\n"
        "cmovb rbx, rcx;\n"
        "mov r8, rax;\n"
        "sub rsi, rax;\n"
        "lea rcx, [rcx + rdi];\n"
        "cmovs r8, rbp;\n"
        "mov rdi, rbx;\n"
        "test rcx, rdx;\n"
        "cmove r8, rbp;\n"
        "cmove rdi, rbp;\n"
        "sar rcx, 1;\n"
        "xor rdi, r8;\n"
        "xor rsi, r8;\n"
        "bt r8, 0x3f;\n"
        "cmovb rbx, rcx;\n"
        "mov r8, rax;\n"
        "sub rsi, rax;\n"
        "lea rcx, [rcx + rdi];\n"
        "cmovs r8, rbp;\n"
        "mov rdi, rbx;\n"
        "test rcx, rdx;\n"
        "cmove r8, rbp;\n"
        "cmove rdi, rbp;\n"
        "sar rcx, 1;\n"
        "xor rdi, r8;\n"
        "xor rsi, r8;\n"
        "bt r8, 0x3f;\n"
        "cmovb rbx, rcx;\n"
        "mov r8, rax;\n"
        "sub rsi, rax;\n"
        "lea rcx, [rcx + rdi];\n"
        "cmovs r8, rbp;\n"
        "mov rdi, rbx;\n"
        "test rcx, rdx;\n"
        "cmove r8, rbp;\n"
        "cmove rdi, rbp;\n"
        "sar rcx, 1;\n"
        "xor rdi, r8;\n"
        "xor rsi, r8;\n"
        "bt r8, 0x3f;\n"
        "cmovb rbx, rcx;\n"
        "mov r8, rax;\n"
        "sub rsi, rax;\n"
        "lea rcx, [rcx + rdi];\n"
        "cmovs r8, rbp;\n"
        "mov rdi, rbx;\n"
        "test rcx, rdx;\n"
        "cmove r8, rbp;\n"
        "cmove rdi, rbp;\n"
        "sar rcx, 1;\n"
        "xor rdi, r8;\n"
        "xor rsi, r8;\n"
        "bt r8, 0x3f;\n"
        "cmovb rbx, rcx;\n"
        "mov r8, rax;\n"
        "sub rsi, rax;\n"
        "lea rcx, [rcx + rdi];\n"
        "cmovs r8, rbp;\n"
        "mov rdi, rbx;\n"
        "test rcx, rdx;\n"
        "cmove r8, rbp;\n"
        "cmove rdi, rbp;\n"
        "sar rcx, 1;\n"
        "xor rdi, r8;\n"
        "xor rsi, r8;\n"
        "bt r8, 0x3f;\n"
        "cmovb rbx, rcx;\n"
        "mov r8, rax;\n"
        "sub rsi, rax;\n"
        "lea rcx, [rcx + rdi];\n"
        "cmovs r8, rbp;\n"
        "mov rdi, rbx;\n"
        "test rcx, rdx;\n"
        "cmove r8, rbp;\n"
        "cmove rdi, rbp;\n"
        "sar rcx, 1;\n"
        "xor rdi, r8;\n"
        "xor rsi, r8;\n"
        "bt r8, 0x3f;\n"
        "cmovb rbx, rcx;\n"
        "mov r8, rax;\n"
        "sub rsi, rax;\n"
        "lea rcx, [rcx + rdi];\n"
        "cmovs r8, rbp;\n"
        "mov rdi, rbx;\n"
        "test rcx, rdx;\n"
        "cmove r8, rbp;\n"
        "cmove rdi, rbp;\n"
        "sar rcx, 1;\n"
        "xor rdi, r8;\n"
        "xor rsi, r8;\n"
        "bt r8, 0x3f;\n"
        "cmovb rbx, rcx;\n"
        "mov r8, rax;\n"
        "sub rsi, rax;\n"
        "lea rcx, [rcx + rdi];\n"
        "cmovs r8, rbp;\n"
        "mov rdi, rbx;\n"
        "test rcx, rdx;\n"
        "cmove r8, rbp;\n"
        "cmove rdi, rbp;\n"
        "sar rcx, 1;\n"
        "xor rdi, r8;\n"
        "xor rsi, r8;\n"
        "bt r8, 0x3f;\n"
        "cmovb rbx, rcx;\n"
        "mov r8, rax;\n"
        "sub rsi, rax;\n"
        "lea rcx, [rcx + rdi];\n"
        "cmovs r8, rbp;\n"
        "mov rdi, rbx;\n"
        "test rcx, rdx;\n"
        "cmove r8, rbp;\n"
        "cmove rdi, rbp;\n"
        "sar rcx, 1;\n"
        "xor rdi, r8;\n"
        "xor rsi, r8;\n"
        "bt r8, 0x3f;\n"
        "cmovb rbx, rcx;\n"
        "mov r8, rax;\n"
        "sub rsi, rax;\n"
        "lea rcx, [rcx + rdi];\n"
        "cmovs r8, rbp;\n"
        "mov rdi, rbx;\n"
        "test rcx, rdx;\n"
        "cmove r8, rbp;\n"
        "cmove rdi, rbp;\n"
        "sar rcx, 1;\n"
        "xor rdi, r8;\n"
        "xor rsi, r8;\n"
        "bt r8, 0x3f;\n"
        "cmovb rbx, rcx;\n"
        "mov r8, rax;\n"
        "sub rsi, rax;\n"
        "lea rcx, [rcx + rdi];\n"
        "cmovs r8, rbp;\n"
        "mov rdi, rbx;\n"
        "test rcx, rdx;\n"
        "cmove r8, rbp;\n"
        "cmove rdi, rbp;\n"
        "sar rcx, 1;\n"
        "xor rdi, r8;\n"
        "xor rsi, r8;\n"
        "bt r8, 0x3f;\n"
        "cmovb rbx, rcx;\n"
        "mov r8, rax;\n"
        "sub rsi, rax;\n"
        "lea rcx, [rcx + rdi];\n"
        "cmovs r8, rbp;\n"
        "mov rdi, rbx;\n"
        "test rcx, rdx;\n"
        "cmove r8, rbp;\n"
        "cmove rdi, rbp;\n"
        "sar rcx, 1;\n"
        "xor rdi, r8;\n"
        "xor rsi, r8;\n"
        "bt r8, 0x3f;\n"
        "cmovb rbx, rcx;\n"
        "mov r8, rax;\n"
        "sub rsi, rax;\n"
        "lea rcx, [rcx + rdi];\n"
        "cmovs r8, rbp;\n"
        "mov rdi, rbx;\n"
        "test rcx, rdx;\n"
        "cmove r8, rbp;\n"
        "cmove rdi, rbp;\n"
        "sar rcx, 1;\n"
        "xor rdi, r8;\n"
        "xor rsi, r8;\n"
        "bt r8, 0x3f;\n"
        "cmovb rbx, rcx;\n"
        "mov r8, rax;\n"
        "sub rsi, rax;\n"
        "lea rcx, [rcx + rdi];\n"
        "cmovs r8, rbp;\n"
        "mov rdi, rbx;\n"
        "test rcx, rdx;\n"
        "cmove r8, rbp;\n"
        "cmove rdi, rbp;\n"
        "sar rcx, 1;\n"
        "xor rdi, r8;\n"
        "xor rsi, r8;\n"
        "bt r8, 0x3f;\n"
        "cmovb rbx, rcx;\n"
        "mov r8, rax;\n"
        "sub rsi, rax;\n"
        "lea rcx, [rcx + rdi];\n"
        "sar rcx, 1;\n"
        "mov eax, 0x100000;\n"
        "lea rdx, [rbx + rax];\n"
        "lea rdi, [rcx + rax];\n"
        "shl rdx, 0x16;\n"
        "shl rdi, 0x16;\n"
        "sar rdx, 0x2b;\n"
        "sar rdi, 0x2b;\n"
        "movabs rax, 0x20000100000;\n"
        "lea rbx, [rbx + rax];\n"
        "lea rcx, [rcx + rax];\n"
        "sar rbx, 0x2a;\n"
        "sar rcx, 0x2a;\n"
        "mov [rsp + " MAT!() "], rdx;\n"
        "mov [rsp + " MAT!() "+ 0x8], rbx;\n"
        "mov [rsp + " MAT!() "+ 0x10], rdi;\n"
        "mov [rsp + " MAT!() "+ 0x18], rcx;\n"
        "mov r12, " $fin ";\n"
        "imul rdi, r12;\n"
        "imul r12, rdx;\n"
        "mov r13, " $gin ";\n"
        "imul rbx, r13;\n"
        "imul r13, rcx;\n"
        "add r12, rbx;\n"
        "add r13, rdi;\n"
        "sar r12, 0x14;\n"
        "sar r13, 0x14;\n"
        "mov rbx, r12;\n"
        "and rbx, 0xfffff;\n"
        "movabs rax, 0xfffffe0000000000;\n"
        "or rbx, rax;\n"
        "mov rcx, r13;\n"
        "and rcx, 0xfffff;\n"
        "movabs rax, 0xc000000000000000;\n"
        "or rcx, rax;\n"
        "mov rax, 0xfffffffffffffffe;\n"
        "mov edx, 0x2;\n"
        "mov rdi, rbx;\n"
        "mov r8, rax;\n"
        "test rsi, rsi;\n"
        "cmovs r8, rbp;\n"
        "test rcx, 0x1;\n"
        "cmove r8, rbp;\n"
        "cmove rdi, rbp;\n"
        "xor rdi, r8;\n"
        "xor rsi, r8;\n"
        "bt r8, 0x3f;\n"
        "cmovb rbx, rcx;\n"
        "mov r8, rax;\n"
        "sub rsi, rax;\n"
        "lea rcx, [rcx + rdi];\n"
        "cmovs r8, rbp;\n"
        "mov rdi, rbx;\n"
        "test rcx, rdx;\n"
        "cmove r8, rbp;\n"
        "cmove rdi, rbp;\n"
        "sar rcx, 1;\n"
        "xor rdi, r8;\n"
        "xor rsi, r8;\n"
        "bt r8, 0x3f;\n"
        "cmovb rbx, rcx;\n"
        "mov r8, rax;\n"
        "sub rsi, rax;\n"
        "lea rcx, [rcx + rdi];\n"
        "cmovs r8, rbp;\n"
        "mov rdi, rbx;\n"
        "test rcx, rdx;\n"
        "cmove r8, rbp;\n"
        "cmove rdi, rbp;\n"
        "sar rcx, 1;\n"
        "xor rdi, r8;\n"
        "xor rsi, r8;\n"
        "bt r8, 0x3f;\n"
        "cmovb rbx, rcx;\n"
        "mov r8, rax;\n"
        "sub rsi, rax;\n"
        "lea rcx, [rcx + rdi];\n"
        "cmovs r8, rbp;\n"
        "mov rdi, rbx;\n"
        "test rcx, rdx;\n"
        "cmove r8, rbp;\n"
        "cmove rdi, rbp;\n"
        "sar rcx, 1;\n"
        "xor rdi, r8;\n"
        "xor rsi, r8;\n"
        "bt r8, 0x3f;\n"
        "cmovb rbx, rcx;\n"
        "mov r8, rax;\n"
        "sub rsi, rax;\n"
        "lea rcx, [rcx + rdi];\n"
        "cmovs r8, rbp;\n"
        "mov rdi, rbx;\n"
        "test rcx, rdx;\n"
        "cmove r8, rbp;\n"
        "cmove rdi, rbp;\n"
        "sar rcx, 1;\n"
        "xor rdi, r8;\n"
        "xor rsi, r8;\n"
        "bt r8, 0x3f;\n"
        "cmovb rbx, rcx;\n"
        "mov r8, rax;\n"
        "sub rsi, rax;\n"
        "lea rcx, [rcx + rdi];\n"
        "cmovs r8, rbp;\n"
        "mov rdi, rbx;\n"
        "test rcx, rdx;\n"
        "cmove r8, rbp;\n"
        "cmove rdi, rbp;\n"
        "sar rcx, 1;\n"
        "xor rdi, r8;\n"
        "xor rsi, r8;\n"
        "bt r8, 0x3f;\n"
        "cmovb rbx, rcx;\n"
        "mov r8, rax;\n"
        "sub rsi, rax;\n"
        "lea rcx, [rcx + rdi];\n"
        "cmovs r8, rbp;\n"
        "mov rdi, rbx;\n"
        "test rcx, rdx;\n"
        "cmove r8, rbp;\n"
        "cmove rdi, rbp;\n"
        "sar rcx, 1;\n"
        "xor rdi, r8;\n"
        "xor rsi, r8;\n"
        "bt r8, 0x3f;\n"
        "cmovb rbx, rcx;\n"
        "mov r8, rax;\n"
        "sub rsi, rax;\n"
        "lea rcx, [rcx + rdi];\n"
        "cmovs r8, rbp;\n"
        "mov rdi, rbx;\n"
        "test rcx, rdx;\n"
        "cmove r8, rbp;\n"
        "cmove rdi, rbp;\n"
        "sar rcx, 1;\n"
        "xor rdi, r8;\n"
        "xor rsi, r8;\n"
        "bt r8, 0x3f;\n"
        "cmovb rbx, rcx;\n"
        "mov r8, rax;\n"
        "sub rsi, rax;\n"
        "lea rcx, [rcx + rdi];\n"
        "cmovs r8, rbp;\n"
        "mov rdi, rbx;\n"
        "test rcx, rdx;\n"
        "cmove r8, rbp;\n"
        "cmove rdi, rbp;\n"
        "sar rcx, 1;\n"
        "xor rdi, r8;\n"
        "xor rsi, r8;\n"
        "bt r8, 0x3f;\n"
        "cmovb rbx, rcx;\n"
        "mov r8, rax;\n"
        "sub rsi, rax;\n"
        "lea rcx, [rcx + rdi];\n"
        "cmovs r8, rbp;\n"
        "mov rdi, rbx;\n"
        "test rcx, rdx;\n"
        "cmove r8, rbp;\n"
        "cmove rdi, rbp;\n"
        "sar rcx, 1;\n"
        "xor rdi, r8;\n"
        "xor rsi, r8;\n"
        "bt r8, 0x3f;\n"
        "cmovb rbx, rcx;\n"
        "mov r8, rax;\n"
        "sub rsi, rax;\n"
        "lea rcx, [rcx + rdi];\n"
        "cmovs r8, rbp;\n"
        "mov rdi, rbx;\n"
        "test rcx, rdx;\n"
        "cmove r8, rbp;\n"
        "cmove rdi, rbp;\n"
        "sar rcx, 1;\n"
        "xor rdi, r8;\n"
        "xor rsi, r8;\n"
        "bt r8, 0x3f;\n"
        "cmovb rbx, rcx;\n"
        "mov r8, rax;\n"
        "sub rsi, rax;\n"
        "lea rcx, [rcx + rdi];\n"
        "cmovs r8, rbp;\n"
        "mov rdi, rbx;\n"
        "test rcx, rdx;\n"
        "cmove r8, rbp;\n"
        "cmove rdi, rbp;\n"
        "sar rcx, 1;\n"
        "xor rdi, r8;\n"
        "xor rsi, r8;\n"
        "bt r8, 0x3f;\n"
        "cmovb rbx, rcx;\n"
        "mov r8, rax;\n"
        "sub rsi, rax;\n"
        "lea rcx, [rcx + rdi];\n"
        "cmovs r8, rbp;\n"
        "mov rdi, rbx;\n"
        "test rcx, rdx;\n"
        "cmove r8, rbp;\n"
        "cmove rdi, rbp;\n"
        "sar rcx, 1;\n"
        "xor rdi, r8;\n"
        "xor rsi, r8;\n"
        "bt r8, 0x3f;\n"
        "cmovb rbx, rcx;\n"
        "mov r8, rax;\n"
        "sub rsi, rax;\n"
        "lea rcx, [rcx + rdi];\n"
        "cmovs r8, rbp;\n"
        "mov rdi, rbx;\n"
        "test rcx, rdx;\n"
        "cmove r8, rbp;\n"
        "cmove rdi, rbp;\n"
        "sar rcx, 1;\n"
        "xor rdi, r8;\n"
        "xor rsi, r8;\n"
        "bt r8, 0x3f;\n"
        "cmovb rbx, rcx;\n"
        "mov r8, rax;\n"
        "sub rsi, rax;\n"
        "lea rcx, [rcx + rdi];\n"
        "cmovs r8, rbp;\n"
        "mov rdi, rbx;\n"
        "test rcx, rdx;\n"
        "cmove r8, rbp;\n"
        "cmove rdi, rbp;\n"
        "sar rcx, 1;\n"
        "xor rdi, r8;\n"
        "xor rsi, r8;\n"
        "bt r8, 0x3f;\n"
        "cmovb rbx, rcx;\n"
        "mov r8, rax;\n"
        "sub rsi, rax;\n"
        "lea rcx, [rcx + rdi];\n"
        "cmovs r8, rbp;\n"
        "mov rdi, rbx;\n"
        "test rcx, rdx;\n"
        "cmove r8, rbp;\n"
        "cmove rdi, rbp;\n"
        "sar rcx, 1;\n"
        "xor rdi, r8;\n"
        "xor rsi, r8;\n"
        "bt r8, 0x3f;\n"
        "cmovb rbx, rcx;\n"
        "mov r8, rax;\n"
        "sub rsi, rax;\n"
        "lea rcx, [rcx + rdi];\n"
        "cmovs r8, rbp;\n"
        "mov rdi, rbx;\n"
        "test rcx, rdx;\n"
        "cmove r8, rbp;\n"
        "cmove rdi, rbp;\n"
        "sar rcx, 1;\n"
        "xor rdi, r8;\n"
        "xor rsi, r8;\n"
        "bt r8, 0x3f;\n"
        "cmovb rbx, rcx;\n"
        "mov r8, rax;\n"
        "sub rsi, rax;\n"
        "lea rcx, [rcx + rdi];\n"
        "cmovs r8, rbp;\n"
        "mov rdi, rbx;\n"
        "test rcx, rdx;\n"
        "cmove r8, rbp;\n"
        "cmove rdi, rbp;\n"
        "sar rcx, 1;\n"
        "xor rdi, r8;\n"
        "xor rsi, r8;\n"
        "bt r8, 0x3f;\n"
        "cmovb rbx, rcx;\n"
        "mov r8, rax;\n"
        "sub rsi, rax;\n"
        "lea rcx, [rcx + rdi];\n"
        "cmovs r8, rbp;\n"
        "mov rdi, rbx;\n"
        "test rcx, rdx;\n"
        "cmove r8, rbp;\n"
        "cmove rdi, rbp;\n"
        "sar rcx, 1;\n"
        "xor rdi, r8;\n"
        "xor rsi, r8;\n"
        "bt r8, 0x3f;\n"
        "cmovb rbx, rcx;\n"
        "mov r8, rax;\n"
        "sub rsi, rax;\n"
        "lea rcx, [rcx + rdi];\n"
        "cmovs r8, rbp;\n"
        "mov rdi, rbx;\n"
        "test rcx, rdx;\n"
        "cmove r8, rbp;\n"
        "cmove rdi, rbp;\n"
        "sar rcx, 1;\n"
        "xor rdi, r8;\n"
        "xor rsi, r8;\n"
        "bt r8, 0x3f;\n"
        "cmovb rbx, rcx;\n"
        "mov r8, rax;\n"
        "sub rsi, rax;\n"
        "lea rcx, [rcx + rdi];\n"
        "sar rcx, 1;\n"
        "mov eax, 0x100000;\n"
        "lea r8, [rbx + rax];\n"
        "lea r10, [rcx + rax];\n"
        "shl r8, 0x16;\n"
        "shl r10, 0x16;\n"
        "sar r8, 0x2b;\n"
        "sar r10, 0x2b;\n"
        "movabs rax, 0x20000100000;\n"
        "lea r15, [rbx + rax];\n"
        "lea r11, [rcx + rax];\n"
        "sar r15, 0x2a;\n"
        "sar r11, 0x2a;\n"
        "mov rbx, r13;\n"
        "mov rcx, r12;\n"
        "imul r12, r8;\n"
        "imul rbx, r15;\n"
        "add r12, rbx;\n"
        "imul r13, r11;\n"
        "imul rcx, r10;\n"
        "add r13, rcx;\n"
        "sar r12, 0x14;\n"
        "sar r13, 0x14;\n"
        "mov rbx, r12;\n"
        "and rbx, 0xfffff;\n"
        "movabs rax, 0xfffffe0000000000;\n"
        "or rbx, rax;\n"
        "mov rcx, r13;\n"
        "and rcx, 0xfffff;\n"
        "movabs rax, 0xc000000000000000;\n"
        "or rcx, rax;\n"
        "mov rax, [rsp + " MAT!() "];\n"
        "imul rax, r8;\n"
        "mov rdx, [rsp + " MAT!() "+ 0x10];\n"
        "imul rdx, r15;\n"
        "imul r8, [rsp + " MAT!() "+ 0x8];\n"
        "imul r15, [rsp + " MAT!() "+ 0x18];\n"
        "add r15, r8;\n"
        "lea r9, [rax + rdx];\n"
        "mov rax, [rsp + " MAT!() "];\n"
        "imul rax, r10;\n"
        "mov rdx, [rsp + " MAT!() "+ 0x10];\n"
        "imul rdx, r11;\n"
        "imul r10, [rsp + " MAT!() "+ 0x8];\n"
        "imul r11, [rsp + " MAT!() "+ 0x18];\n"
        "add r11, r10;\n"
        "lea r13, [rax + rdx];\n"
        "mov rax, 0xfffffffffffffffe;\n"
        "mov edx, 0x2;\n"
        "mov rdi, rbx;\n"
        "mov r8, rax;\n"
        "test rsi, rsi;\n"
        "cmovs r8, rbp;\n"
        "test rcx, 0x1;\n"
        "cmove r8, rbp;\n"
        "cmove rdi, rbp;\n"
        "xor rdi, r8;\n"
        "xor rsi, r8;\n"
        "bt r8, 0x3f;\n"
        "cmovb rbx, rcx;\n"
        "mov r8, rax;\n"
        "sub rsi, rax;\n"
        "lea rcx, [rcx + rdi];\n"
        "cmovs r8, rbp;\n"
        "mov rdi, rbx;\n"
        "test rcx, rdx;\n"
        "cmove r8, rbp;\n"
        "cmove rdi, rbp;\n"
        "sar rcx, 1;\n"
        "xor rdi, r8;\n"
        "xor rsi, r8;\n"
        "bt r8, 0x3f;\n"
        "cmovb rbx, rcx;\n"
        "mov r8, rax;\n"
        "sub rsi, rax;\n"
        "lea rcx, [rcx + rdi];\n"
        "cmovs r8, rbp;\n"
        "mov rdi, rbx;\n"
        "test rcx, rdx;\n"
        "cmove r8, rbp;\n"
        "cmove rdi, rbp;\n"
        "sar rcx, 1;\n"
        "xor rdi, r8;\n"
        "xor rsi, r8;\n"
        "bt r8, 0x3f;\n"
        "cmovb rbx, rcx;\n"
        "mov r8, rax;\n"
        "sub rsi, rax;\n"
        "lea rcx, [rcx + rdi];\n"
        "cmovs r8, rbp;\n"
        "mov rdi, rbx;\n"
        "test rcx, rdx;\n"
        "cmove r8, rbp;\n"
        "cmove rdi, rbp;\n"
        "sar rcx, 1;\n"
        "xor rdi, r8;\n"
        "xor rsi, r8;\n"
        "bt r8, 0x3f;\n"
        "cmovb rbx, rcx;\n"
        "mov r8, rax;\n"
        "sub rsi, rax;\n"
        "lea rcx, [rcx + rdi];\n"
        "cmovs r8, rbp;\n"
        "mov rdi, rbx;\n"
        "test rcx, rdx;\n"
        "cmove r8, rbp;\n"
        "cmove rdi, rbp;\n"
        "sar rcx, 1;\n"
        "xor rdi, r8;\n"
        "xor rsi, r8;\n"
        "bt r8, 0x3f;\n"
        "cmovb rbx, rcx;\n"
        "mov r8, rax;\n"
        "sub rsi, rax;\n"
        "lea rcx, [rcx + rdi];\n"
        "cmovs r8, rbp;\n"
        "mov rdi, rbx;\n"
        "test rcx, rdx;\n"
        "cmove r8, rbp;\n"
        "cmove rdi, rbp;\n"
        "sar rcx, 1;\n"
        "xor rdi, r8;\n"
        "xor rsi, r8;\n"
        "bt r8, 0x3f;\n"
        "cmovb rbx, rcx;\n"
        "mov r8, rax;\n"
        "sub rsi, rax;\n"
        "lea rcx, [rcx + rdi];\n"
        "cmovs r8, rbp;\n"
        "mov rdi, rbx;\n"
        "test rcx, rdx;\n"
        "cmove r8, rbp;\n"
        "cmove rdi, rbp;\n"
        "sar rcx, 1;\n"
        "xor rdi, r8;\n"
        "xor rsi, r8;\n"
        "bt r8, 0x3f;\n"
        "cmovb rbx, rcx;\n"
        "mov r8, rax;\n"
        "sub rsi, rax;\n"
        "lea rcx, [rcx + rdi];\n"
        "cmovs r8, rbp;\n"
        "mov rdi, rbx;\n"
        "test rcx, rdx;\n"
        "cmove r8, rbp;\n"
        "cmove rdi, rbp;\n"
        "sar rcx, 1;\n"
        "xor rdi, r8;\n"
        "xor rsi, r8;\n"
        "bt r8, 0x3f;\n"
        "cmovb rbx, rcx;\n"
        "mov r8, rax;\n"
        "sub rsi, rax;\n"
        "lea rcx, [rcx + rdi];\n"
        "cmovs r8, rbp;\n"
        "mov rdi, rbx;\n"
        "test rcx, rdx;\n"
        "cmove r8, rbp;\n"
        "cmove rdi, rbp;\n"
        "sar rcx, 1;\n"
        "xor rdi, r8;\n"
        "xor rsi, r8;\n"
        "bt r8, 0x3f;\n"
        "cmovb rbx, rcx;\n"
        "mov r8, rax;\n"
        "sub rsi, rax;\n"
        "lea rcx, [rcx + rdi];\n"
        "cmovs r8, rbp;\n"
        "mov rdi, rbx;\n"
        "test rcx, rdx;\n"
        "cmove r8, rbp;\n"
        "cmove rdi, rbp;\n"
        "sar rcx, 1;\n"
        "xor rdi, r8;\n"
        "xor rsi, r8;\n"
        "bt r8, 0x3f;\n"
        "cmovb rbx, rcx;\n"
        "mov r8, rax;\n"
        "sub rsi, rax;\n"
        "lea rcx, [rcx + rdi];\n"
        "cmovs r8, rbp;\n"
        "mov rdi, rbx;\n"
        "test rcx, rdx;\n"
        "cmove r8, rbp;\n"
        "cmove rdi, rbp;\n"
        "sar rcx, 1;\n"
        "xor rdi, r8;\n"
        "xor rsi, r8;\n"
        "bt r8, 0x3f;\n"
        "cmovb rbx, rcx;\n"
        "mov r8, rax;\n"
        "sub rsi, rax;\n"
        "lea rcx, [rcx + rdi];\n"
        "cmovs r8, rbp;\n"
        "mov rdi, rbx;\n"
        "test rcx, rdx;\n"
        "cmove r8, rbp;\n"
        "cmove rdi, rbp;\n"
        "sar rcx, 1;\n"
        "xor rdi, r8;\n"
        "xor rsi, r8;\n"
        "bt r8, 0x3f;\n"
        "cmovb rbx, rcx;\n"
        "mov r8, rax;\n"
        "sub rsi, rax;\n"
        "lea rcx, [rcx + rdi];\n"
        "cmovs r8, rbp;\n"
        "mov rdi, rbx;\n"
        "test rcx, rdx;\n"
        "cmove r8, rbp;\n"
        "cmove rdi, rbp;\n"
        "sar rcx, 1;\n"
        "xor rdi, r8;\n"
        "xor rsi, r8;\n"
        "bt r8, 0x3f;\n"
        "cmovb rbx, rcx;\n"
        "mov r8, rax;\n"
        "sub rsi, rax;\n"
        "lea rcx, [rcx + rdi];\n"
        "cmovs r8, rbp;\n"
        "mov rdi, rbx;\n"
        "test rcx, rdx;\n"
        "cmove r8, rbp;\n"
        "cmove rdi, rbp;\n"
        "sar rcx, 1;\n"
        "xor rdi, r8;\n"
        "xor rsi, r8;\n"
        "bt r8, 0x3f;\n"
        "cmovb rbx, rcx;\n"
        "mov r8, rax;\n"
        "sub rsi, rax;\n"
        "lea rcx, [rcx + rdi];\n"
        "cmovs r8, rbp;\n"
        "mov rdi, rbx;\n"
        "test rcx, rdx;\n"
        "cmove r8, rbp;\n"
        "cmove rdi, rbp;\n"
        "sar rcx, 1;\n"
        "xor rdi, r8;\n"
        "xor rsi, r8;\n"
        "bt r8, 0x3f;\n"
        "cmovb rbx, rcx;\n"
        "mov r8, rax;\n"
        "sub rsi, rax;\n"
        "lea rcx, [rcx + rdi];\n"
        "cmovs r8, rbp;\n"
        "mov rdi, rbx;\n"
        "test rcx, rdx;\n"
        "cmove r8, rbp;\n"
        "cmove rdi, rbp;\n"
        "sar rcx, 1;\n"
        "xor rdi, r8;\n"
        "xor rsi, r8;\n"
        "bt r8, 0x3f;\n"
        "cmovb rbx, rcx;\n"
        "mov r8, rax;\n"
        "sub rsi, rax;\n"
        "lea rcx, [rcx + rdi];\n"
        "cmovs r8, rbp;\n"
        "mov rdi, rbx;\n"
        "test rcx, rdx;\n"
        "cmove r8, rbp;\n"
        "cmove rdi, rbp;\n"
        "sar rcx, 1;\n"
        "xor rdi, r8;\n"
        "xor rsi, r8;\n"
        "bt r8, 0x3f;\n"
        "cmovb rbx, rcx;\n"
        "mov r8, rax;\n"
        "sub rsi, rax;\n"
        "lea rcx, [rcx + rdi];\n"
        "cmovs r8, rbp;\n"
        "mov rdi, rbx;\n"
        "test rcx, rdx;\n"
        "cmove r8, rbp;\n"
        "cmove rdi, rbp;\n"
        "sar rcx, 1;\n"
        "xor rdi, r8;\n"
        "xor rsi, r8;\n"
        "bt r8, 0x3f;\n"
        "cmovb rbx, rcx;\n"
        "mov r8, rax;\n"
        "sub rsi, rax;\n"
        "lea rcx, [rcx + rdi];\n"
        "cmovs r8, rbp;\n"
        "mov rdi, rbx;\n"
        "test rcx, rdx;\n"
        "cmove r8, rbp;\n"
        "cmove rdi, rbp;\n"
        "sar rcx, 1;\n"
        "xor rdi, r8;\n"
        "xor rsi, r8;\n"
        "bt r8, 0x3f;\n"
        "cmovb rbx, rcx;\n"
        "mov r8, rax;\n"
        "sub rsi, rax;\n"
        "lea rcx, [rcx + rdi];\n"
        "sar rcx, 1;\n"
        "mov eax, 0x100000;\n"
        "lea r8, [rbx + rax];\n"
        "lea r12, [rcx + rax];\n"
        "shl r8, 0x15;\n"
        "shl r12, 0x15;\n"
        "sar r8, 0x2b;\n"
        "sar r12, 0x2b;\n"
        "movabs rax, 0x20000100000;\n"
        "lea r10, [rbx + rax];\n"
        "lea r14, [rcx + rax];\n"
        "sar r10, 0x2b;\n"
        "sar r14, 0x2b;\n"
        "mov rax, r9;\n"
        "imul rax, r8;\n"
        "mov rdx, r13;\n"
        "imul rdx, r10;\n"
        "imul r8, r15;\n"
        "imul r10, r11;\n"
        "add r10, r8;\n"
        "lea r8, [rax + rdx];\n"
        "mov rax, r9;\n"
        "imul rax, r12;\n"
        "mov rdx, r13;\n"
        "imul rdx, r14;\n"
        "imul r12, r15;\n"
        "imul r14, r11;\n"
        "add r14, r12;\n"
        "lea r12, [rax + rdx]"
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

        Q!("    endbr64         " ),

        // Save registers and make room for temporaries

        Q!("    push            " "rbx"),
        Q!("    push            " "rbp"),
        Q!("    push            " "r12"),
        Q!("    push            " "r13"),
        Q!("    push            " "r14"),
        Q!("    push            " "r15"),

        Q!("    sub             " "rsp, " NSPACE!()),

        // Save the return pointer for the end so we can overwrite rdi later

        Q!("    mov             " res!() ", rdi"),

        // Copy the prime p_521 = 2^521 - 1 into the f variable

        Q!("    xor             " "eax, eax"),
        Q!("    not             " "rax"),
        Q!("    mov             " "[rsp + " F!() "], rax"),
        Q!("    mov             " "[rsp + " F!() "+ 8], rax"),
        Q!("    mov             " "[rsp + " F!() "+ 16], rax"),
        Q!("    mov             " "[rsp + " F!() "+ 24], rax"),
        Q!("    mov             " "[rsp + " F!() "+ 32], rax"),
        Q!("    mov             " "[rsp + " F!() "+ 40], rax"),
        Q!("    mov             " "[rsp + " F!() "+ 48], rax"),
        Q!("    mov             " "[rsp + " F!() "+ 56], rax"),
        Q!("    mov             " "eax, 0x1FF"),
        Q!("    mov             " "[rsp + " F!() "+ 64], rax"),

        // Copy the input into the g variable, but reduce it strictly mod p_521
        // so that g <= f as assumed in the bound proof. This code fragment is
        // very similar to bignum_mod_p521_9.

        Q!("    mov             " "r8, [rsi + 64]"),
        Q!("    mov             " "ebx, 0x1FF"),
        Q!("    and             " "rbx, r8"),
        Q!("    shr             " "r8, 9"),

        Q!("    stc             " ),
        Q!("    adc             " "r8, [rsi]"),
        Q!("    mov             " "r9, [rsi + 8]"),
        Q!("    adc             " "r9, 0"),
        Q!("    mov             " "r10, [rsi + 16]"),
        Q!("    adc             " "r10, 0"),
        Q!("    mov             " "r11, [rsi + 24]"),
        Q!("    adc             " "r11, 0"),
        Q!("    mov             " "r12, [rsi + 32]"),
        Q!("    adc             " "r12, 0"),
        Q!("    mov             " "r13, [rsi + 40]"),
        Q!("    adc             " "r13, 0"),
        Q!("    mov             " "r14, [rsi + 48]"),
        Q!("    adc             " "r14, 0"),
        Q!("    mov             " "r15, [rsi + 56]"),
        Q!("    adc             " "r15, 0"),
        Q!("    adc             " "rbx, 0"),

        Q!("    cmp             " "rbx, 512"),

        Q!("    sbb             " "r8, 0"),
        Q!("    mov             " "[rsp + " G!() "], r8"),
        Q!("    sbb             " "r9, 0"),
        Q!("    mov             " "[rsp + " G!() "+ 8], r9"),
        Q!("    sbb             " "r10, 0"),
        Q!("    mov             " "[rsp + " G!() "+ 16], r10"),
        Q!("    sbb             " "r11, 0"),
        Q!("    mov             " "[rsp + " G!() "+ 24], r11"),
        Q!("    sbb             " "r12, 0"),
        Q!("    mov             " "[rsp + " G!() "+ 32], r12"),
        Q!("    sbb             " "r13, 0"),
        Q!("    mov             " "[rsp + " G!() "+ 40], r13"),
        Q!("    sbb             " "r14, 0"),
        Q!("    mov             " "[rsp + " G!() "+ 48], r14"),
        Q!("    sbb             " "r15, 0"),
        Q!("    mov             " "[rsp + " G!() "+ 56], r15"),
        Q!("    sbb             " "rbx, 0"),
        Q!("    and             " "rbx, 0x1FF"),
        Q!("    mov             " "[rsp + " G!() "+ 64], rbx"),

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

        Q!("    xor             " "eax, eax"),
        Q!("    mov             " "[rsp + " U!() "], rax"),
        Q!("    mov             " "[rsp + " U!() "+ 8], rax"),
        Q!("    mov             " "[rsp + " U!() "+ 16], rax"),
        Q!("    mov             " "[rsp + " U!() "+ 24], rax"),
        Q!("    mov             " "[rsp + " U!() "+ 32], rax"),
        Q!("    mov             " "[rsp + " U!() "+ 40], rax"),
        Q!("    mov             " "[rsp + " U!() "+ 48], rax"),
        Q!("    mov             " "[rsp + " U!() "+ 56], rax"),
        Q!("    mov             " "[rsp + " U!() "+ 64], rax"),

        Q!("    mov             " "ebx, 16"),
        Q!("    mov             " "[rsp + " V!() "], rax"),
        Q!("    mov             " "[rsp + " V!() "+ 8], rax"),
        Q!("    mov             " "[rsp + " V!() "+ 16], rax"),
        Q!("    mov             " "[rsp + " V!() "+ 24], rax"),
        Q!("    mov             " "[rsp + " V!() "+ 32], rax"),
        Q!("    mov             " "[rsp + " V!() "+ 40], rbx"),
        Q!("    mov             " "[rsp + " V!() "+ 48], rax"),
        Q!("    mov             " "[rsp + " V!() "+ 56], rax"),
        Q!("    mov             " "[rsp + " V!() "+ 64], rax"),

        // Start of main loop. We jump into the middle so that the divstep
        // portion is common to the special 21st iteration after a uniform
        // first 20.

        Q!("    mov             " i!() ", 21"),
        Q!("    mov             " d!() ", 1"),
        Q!("    jmp             " Label!("Lbignum_inv_p521_midloop", 2, After)),

        Q!(Label!("Lbignum_inv_p521_loop", 3) ":"),

        // Separate out the matrix into sign-magnitude pairs

        Q!("    mov             " "r9, r8"),
        Q!("    sar             " "r9, 63"),
        Q!("    xor             " "r8, r9"),
        Q!("    sub             " "r8, r9"),

        Q!("    mov             " "r11, r10"),
        Q!("    sar             " "r11, 63"),
        Q!("    xor             " "r10, r11"),
        Q!("    sub             " "r10, r11"),

        Q!("    mov             " "r13, r12"),
        Q!("    sar             " "r13, 63"),
        Q!("    xor             " "r12, r13"),
        Q!("    sub             " "r12, r13"),

        Q!("    mov             " "r15, r14"),
        Q!("    sar             " "r15, 63"),
        Q!("    xor             " "r14, r15"),
        Q!("    sub             " "r14, r15"),

        // Adjust the initial values to allow for complement instead of negation
        // This initial offset is the same for [f,g] and [u,v] compositions.
        // Save it in temporary storage for the [u,v] part and do [f,g] first.

        Q!("    mov             " "rax, r8"),
        Q!("    and             " "rax, r9"),
        Q!("    mov             " "rdi, r10"),
        Q!("    and             " "rdi, r11"),
        Q!("    add             " "rdi, rax"),
        Q!("    mov             " tmp!() ", rdi"),

        Q!("    mov             " "rax, r12"),
        Q!("    and             " "rax, r13"),
        Q!("    mov             " "rsi, r14"),
        Q!("    and             " "rsi, r15"),
        Q!("    add             " "rsi, rax"),
        Q!("    mov             " tmp2!() ", rsi"),

        // Now the computation of the updated f and g values. This maintains a
        // 2-word carry between stages so we can conveniently insert the shift
        // right by 59 before storing back, and not overwrite digits we need
        // again of the old f and g values.
        //
        // Digit 0 of [f,g]

        Q!("    xor             " "ebx, ebx"),
        Q!("    mov             " "rax, [rsp + " F!() "]"),
        Q!("    xor             " "rax, r9"),
        Q!("    mul             " "r8"),
        Q!("    add             " "rdi, rax"),
        Q!("    adc             " "rbx, rdx"),
        Q!("    mov             " "rax, [rsp + " G!() "]"),
        Q!("    xor             " "rax, r11"),
        Q!("    mul             " "r10"),
        Q!("    add             " "rdi, rax"),
        Q!("    adc             " "rbx, rdx"),

        Q!("    xor             " "ebp, ebp"),
        Q!("    mov             " "rax, [rsp + " F!() "]"),
        Q!("    xor             " "rax, r13"),
        Q!("    mul             " "r12"),
        Q!("    add             " "rsi, rax"),
        Q!("    adc             " "rbp, rdx"),
        Q!("    mov             " "rax, [rsp + " G!() "]"),
        Q!("    xor             " "rax, r15"),
        Q!("    mul             " "r14"),
        Q!("    add             " "rsi, rax"),
        Q!("    adc             " "rbp, rdx"),

        // Digit 1 of [f,g]

        Q!("    xor             " "ecx, ecx"),
        Q!("    mov             " "rax, [rsp + " F!() "+ " N!() "]"),
        Q!("    xor             " "rax, r9"),
        Q!("    mul             " "r8"),
        Q!("    add             " "rbx, rax"),
        Q!("    adc             " "rcx, rdx"),
        Q!("    mov             " "rax, [rsp + " G!() "+ " N!() "]"),
        Q!("    xor             " "rax, r11"),
        Q!("    mul             " "r10"),
        Q!("    add             " "rbx, rax"),
        Q!("    adc             " "rcx, rdx"),
        Q!("    shrd            " "rdi, rbx, 59"),
        Q!("    mov             " "[rsp + " F!() "], rdi"),

        Q!("    xor             " "edi, edi"),
        Q!("    mov             " "rax, [rsp + " F!() "+ " N!() "]"),
        Q!("    xor             " "rax, r13"),
        Q!("    mul             " "r12"),
        Q!("    add             " "rbp, rax"),
        Q!("    adc             " "rdi, rdx"),
        Q!("    mov             " "rax, [rsp + " G!() "+ " N!() "]"),
        Q!("    xor             " "rax, r15"),
        Q!("    mul             " "r14"),
        Q!("    add             " "rbp, rax"),
        Q!("    adc             " "rdi, rdx"),
        Q!("    shrd            " "rsi, rbp, 59"),
        Q!("    mov             " "[rsp + " G!() "], rsi"),

        // Digit 2 of [f,g]

        Q!("    xor             " "esi, esi"),
        Q!("    mov             " "rax, [rsp + " F!() "+ 2 * " N!() "]"),
        Q!("    xor             " "rax, r9"),
        Q!("    mul             " "r8"),
        Q!("    add             " "rcx, rax"),
        Q!("    adc             " "rsi, rdx"),
        Q!("    mov             " "rax, [rsp + " G!() "+ 2 * " N!() "]"),
        Q!("    xor             " "rax, r11"),
        Q!("    mul             " "r10"),
        Q!("    add             " "rcx, rax"),
        Q!("    adc             " "rsi, rdx"),
        Q!("    shrd            " "rbx, rcx, 59"),
        Q!("    mov             " "[rsp + " F!() "+ " N!() "], rbx"),

        Q!("    xor             " "ebx, ebx"),
        Q!("    mov             " "rax, [rsp + " F!() "+ 2 * " N!() "]"),
        Q!("    xor             " "rax, r13"),
        Q!("    mul             " "r12"),
        Q!("    add             " "rdi, rax"),
        Q!("    adc             " "rbx, rdx"),
        Q!("    mov             " "rax, [rsp + " G!() "+ 2 * " N!() "]"),
        Q!("    xor             " "rax, r15"),
        Q!("    mul             " "r14"),
        Q!("    add             " "rdi, rax"),
        Q!("    adc             " "rbx, rdx"),
        Q!("    shrd            " "rbp, rdi, 59"),
        Q!("    mov             " "[rsp + " G!() "+ " N!() "], rbp"),

        // Digit 3 of [f,g]

        Q!("    xor             " "ebp, ebp"),
        Q!("    mov             " "rax, [rsp + " F!() "+ 3 * " N!() "]"),
        Q!("    xor             " "rax, r9"),
        Q!("    mul             " "r8"),
        Q!("    add             " "rsi, rax"),
        Q!("    adc             " "rbp, rdx"),
        Q!("    mov             " "rax, [rsp + " G!() "+ 3 * " N!() "]"),
        Q!("    xor             " "rax, r11"),
        Q!("    mul             " "r10"),
        Q!("    add             " "rsi, rax"),
        Q!("    adc             " "rbp, rdx"),
        Q!("    shrd            " "rcx, rsi, 59"),
        Q!("    mov             " "[rsp + " F!() "+ 2 * " N!() "], rcx"),

        Q!("    xor             " "ecx, ecx"),
        Q!("    mov             " "rax, [rsp + " F!() "+ 3 * " N!() "]"),
        Q!("    xor             " "rax, r13"),
        Q!("    mul             " "r12"),
        Q!("    add             " "rbx, rax"),
        Q!("    adc             " "rcx, rdx"),
        Q!("    mov             " "rax, [rsp + " G!() "+ 3 * " N!() "]"),
        Q!("    xor             " "rax, r15"),
        Q!("    mul             " "r14"),
        Q!("    add             " "rbx, rax"),
        Q!("    adc             " "rcx, rdx"),
        Q!("    shrd            " "rdi, rbx, 59"),
        Q!("    mov             " "[rsp + " G!() "+ 2 * " N!() "], rdi"),

        // Digit 4 of [f,g]

        Q!("    xor             " "edi, edi"),
        Q!("    mov             " "rax, [rsp + " F!() "+ 4 * " N!() "]"),
        Q!("    xor             " "rax, r9"),
        Q!("    mul             " "r8"),
        Q!("    add             " "rbp, rax"),
        Q!("    adc             " "rdi, rdx"),
        Q!("    mov             " "rax, [rsp + " G!() "+ 4 * " N!() "]"),
        Q!("    xor             " "rax, r11"),
        Q!("    mul             " "r10"),
        Q!("    add             " "rbp, rax"),
        Q!("    adc             " "rdi, rdx"),
        Q!("    shrd            " "rsi, rbp, 59"),
        Q!("    mov             " "[rsp + " F!() "+ 3 * " N!() "], rsi"),

        Q!("    xor             " "esi, esi"),
        Q!("    mov             " "rax, [rsp + " F!() "+ 4 * " N!() "]"),
        Q!("    xor             " "rax, r13"),
        Q!("    mul             " "r12"),
        Q!("    add             " "rcx, rax"),
        Q!("    adc             " "rsi, rdx"),
        Q!("    mov             " "rax, [rsp + " G!() "+ 4 * " N!() "]"),
        Q!("    xor             " "rax, r15"),
        Q!("    mul             " "r14"),
        Q!("    add             " "rcx, rax"),
        Q!("    adc             " "rsi, rdx"),
        Q!("    shrd            " "rbx, rcx, 59"),
        Q!("    mov             " "[rsp + " G!() "+ 3 * " N!() "], rbx"),

        // Digit 5 of [f,g]

        Q!("    xor             " "ebx, ebx"),
        Q!("    mov             " "rax, [rsp + " F!() "+ 5 * " N!() "]"),
        Q!("    xor             " "rax, r9"),
        Q!("    mul             " "r8"),
        Q!("    add             " "rdi, rax"),
        Q!("    adc             " "rbx, rdx"),
        Q!("    mov             " "rax, [rsp + " G!() "+ 5 * " N!() "]"),
        Q!("    xor             " "rax, r11"),
        Q!("    mul             " "r10"),
        Q!("    add             " "rdi, rax"),
        Q!("    adc             " "rbx, rdx"),
        Q!("    shrd            " "rbp, rdi, 59"),
        Q!("    mov             " "[rsp + " F!() "+ 4 * " N!() "], rbp"),

        Q!("    xor             " "ebp, ebp"),
        Q!("    mov             " "rax, [rsp + " F!() "+ 5 * " N!() "]"),
        Q!("    xor             " "rax, r13"),
        Q!("    mul             " "r12"),
        Q!("    add             " "rsi, rax"),
        Q!("    adc             " "rbp, rdx"),
        Q!("    mov             " "rax, [rsp + " G!() "+ 5 * " N!() "]"),
        Q!("    xor             " "rax, r15"),
        Q!("    mul             " "r14"),
        Q!("    add             " "rsi, rax"),
        Q!("    adc             " "rbp, rdx"),
        Q!("    shrd            " "rcx, rsi, 59"),
        Q!("    mov             " "[rsp + " G!() "+ 4 * " N!() "], rcx"),

        // Digit 6 of [f,g]

        Q!("    xor             " "ecx, ecx"),
        Q!("    mov             " "rax, [rsp + " F!() "+ 6 * " N!() "]"),
        Q!("    xor             " "rax, r9"),
        Q!("    mul             " "r8"),
        Q!("    add             " "rbx, rax"),
        Q!("    adc             " "rcx, rdx"),
        Q!("    mov             " "rax, [rsp + " G!() "+ 6 * " N!() "]"),
        Q!("    xor             " "rax, r11"),
        Q!("    mul             " "r10"),
        Q!("    add             " "rbx, rax"),
        Q!("    adc             " "rcx, rdx"),
        Q!("    shrd            " "rdi, rbx, 59"),
        Q!("    mov             " "[rsp + " F!() "+ 5 * " N!() "], rdi"),

        Q!("    xor             " "edi, edi"),
        Q!("    mov             " "rax, [rsp + " F!() "+ 6 * " N!() "]"),
        Q!("    xor             " "rax, r13"),
        Q!("    mul             " "r12"),
        Q!("    add             " "rbp, rax"),
        Q!("    adc             " "rdi, rdx"),
        Q!("    mov             " "rax, [rsp + " G!() "+ 6 * " N!() "]"),
        Q!("    xor             " "rax, r15"),
        Q!("    mul             " "r14"),
        Q!("    add             " "rbp, rax"),
        Q!("    adc             " "rdi, rdx"),
        Q!("    shrd            " "rsi, rbp, 59"),
        Q!("    mov             " "[rsp + " G!() "+ 5 * " N!() "], rsi"),

        // Digit 7 of [f,g]

        Q!("    xor             " "esi, esi"),
        Q!("    mov             " "rax, [rsp + " F!() "+ 7 * " N!() "]"),
        Q!("    xor             " "rax, r9"),
        Q!("    mul             " "r8"),
        Q!("    add             " "rcx, rax"),
        Q!("    adc             " "rsi, rdx"),
        Q!("    mov             " "rax, [rsp + " G!() "+ 7 * " N!() "]"),
        Q!("    xor             " "rax, r11"),
        Q!("    mul             " "r10"),
        Q!("    add             " "rcx, rax"),
        Q!("    adc             " "rsi, rdx"),
        Q!("    shrd            " "rbx, rcx, 59"),
        Q!("    mov             " "[rsp + " F!() "+ 6 * " N!() "], rbx"),

        Q!("    xor             " "ebx, ebx"),
        Q!("    mov             " "rax, [rsp + " F!() "+ 7 * " N!() "]"),
        Q!("    xor             " "rax, r13"),
        Q!("    mul             " "r12"),
        Q!("    add             " "rdi, rax"),
        Q!("    adc             " "rbx, rdx"),
        Q!("    mov             " "rax, [rsp + " G!() "+ 7 * " N!() "]"),
        Q!("    xor             " "rax, r15"),
        Q!("    mul             " "r14"),
        Q!("    add             " "rdi, rax"),
        Q!("    adc             " "rbx, rdx"),
        Q!("    shrd            " "rbp, rdi, 59"),
        Q!("    mov             " "[rsp + " G!() "+ 6 * " N!() "], rbp"),

        // Digits 8 and 9 of [f,g]

        Q!("    mov             " "rax, [rsp + " F!() "+ 8 * " N!() "]"),
        Q!("    xor             " "rax, r9"),
        Q!("    mov             " "rbp, rax"),
        Q!("    sar             " "rbp, 63"),
        Q!("    and             " "rbp, r8"),
        Q!("    neg             " "rbp"),
        Q!("    mul             " "r8"),
        Q!("    add             " "rsi, rax"),
        Q!("    adc             " "rbp, rdx"),
        Q!("    mov             " "rax, [rsp + " G!() "+ 8 * " N!() "]"),
        Q!("    xor             " "rax, r11"),
        Q!("    mov             " "rdx, rax"),
        Q!("    sar             " "rdx, 63"),
        Q!("    and             " "rdx, r10"),
        Q!("    sub             " "rbp, rdx"),
        Q!("    mul             " "r10"),
        Q!("    add             " "rsi, rax"),
        Q!("    adc             " "rbp, rdx"),
        Q!("    shrd            " "rcx, rsi, 59"),
        Q!("    mov             " "[rsp + " F!() "+ 7 * " N!() "], rcx"),
        Q!("    shrd            " "rsi, rbp, 59"),

        Q!("    mov             " "rax, [rsp + " F!() "+ 8 * " N!() "]"),
        Q!("    mov             " "[rsp + " F!() "+ 8 * " N!() "], rsi"),

        Q!("    xor             " "rax, r13"),
        Q!("    mov             " "rsi, rax"),
        Q!("    sar             " "rsi, 63"),
        Q!("    and             " "rsi, r12"),
        Q!("    neg             " "rsi"),
        Q!("    mul             " "r12"),
        Q!("    add             " "rbx, rax"),
        Q!("    adc             " "rsi, rdx"),
        Q!("    mov             " "rax, [rsp + " G!() "+ 8 * " N!() "]"),
        Q!("    xor             " "rax, r15"),
        Q!("    mov             " "rdx, rax"),
        Q!("    sar             " "rdx, 63"),
        Q!("    and             " "rdx, r14"),
        Q!("    sub             " "rsi, rdx"),
        Q!("    mul             " "r14"),
        Q!("    add             " "rbx, rax"),
        Q!("    adc             " "rsi, rdx"),
        Q!("    shrd            " "rdi, rbx, 59"),
        Q!("    mov             " "[rsp + " G!() "+ 7 * " N!() "], rdi"),
        Q!("    shrd            " "rbx, rsi, 59"),
        Q!("    mov             " "[rsp + " G!() "+ 8 * " N!() "], rbx"),

        // Get the initial carries back from storage and do the [u,v] accumulation

        Q!("    mov             " "rbx, " tmp!()),
        Q!("    mov             " "rbp, " tmp2!()),

        // Digit 0 of [u,v]

        Q!("    xor             " "ecx, ecx"),
        Q!("    mov             " "rax, [rsp + " U!() "]"),
        Q!("    xor             " "rax, r9"),
        Q!("    mul             " "r8"),
        Q!("    add             " "rbx, rax"),
        Q!("    adc             " "rcx, rdx"),
        Q!("    mov             " "rax, [rsp + " V!() "]"),
        Q!("    xor             " "rax, r11"),
        Q!("    mul             " "r10"),
        Q!("    add             " "rbx, rax"),
        Q!("    adc             " "rcx, rdx"),

        Q!("    xor             " "esi, esi"),
        Q!("    mov             " "rax, [rsp + " U!() "]"),
        Q!("    xor             " "rax, r13"),
        Q!("    mul             " "r12"),
        Q!("    mov             " "[rsp + " U!() "], rbx"),
        Q!("    add             " "rbp, rax"),
        Q!("    adc             " "rsi, rdx"),
        Q!("    mov             " "rax, [rsp + " V!() "]"),
        Q!("    xor             " "rax, r15"),
        Q!("    mul             " "r14"),
        Q!("    add             " "rbp, rax"),
        Q!("    adc             " "rsi, rdx"),
        Q!("    mov             " "[rsp + " V!() "], rbp"),

        // Digit 1 of [u,v]

        Q!("    xor             " "ebx, ebx"),
        Q!("    mov             " "rax, [rsp + " U!() "+ " N!() "]"),
        Q!("    xor             " "rax, r9"),
        Q!("    mul             " "r8"),
        Q!("    add             " "rcx, rax"),
        Q!("    adc             " "rbx, rdx"),
        Q!("    mov             " "rax, [rsp + " V!() "+ " N!() "]"),
        Q!("    xor             " "rax, r11"),
        Q!("    mul             " "r10"),
        Q!("    add             " "rcx, rax"),
        Q!("    adc             " "rbx, rdx"),

        Q!("    xor             " "ebp, ebp"),
        Q!("    mov             " "rax, [rsp + " U!() "+ " N!() "]"),
        Q!("    xor             " "rax, r13"),
        Q!("    mul             " "r12"),
        Q!("    mov             " "[rsp + " U!() "+ " N!() "], rcx"),
        Q!("    add             " "rsi, rax"),
        Q!("    adc             " "rbp, rdx"),
        Q!("    mov             " "rax, [rsp + " V!() "+ " N!() "]"),
        Q!("    xor             " "rax, r15"),
        Q!("    mul             " "r14"),
        Q!("    add             " "rsi, rax"),
        Q!("    adc             " "rbp, rdx"),
        Q!("    mov             " "[rsp + " V!() "+ " N!() "], rsi"),

        // Digit 2 of [u,v]

        Q!("    xor             " "ecx, ecx"),
        Q!("    mov             " "rax, [rsp + " U!() "+ 2 * " N!() "]"),
        Q!("    xor             " "rax, r9"),
        Q!("    mul             " "r8"),
        Q!("    add             " "rbx, rax"),
        Q!("    adc             " "rcx, rdx"),
        Q!("    mov             " "rax, [rsp + " V!() "+ 2 * " N!() "]"),
        Q!("    xor             " "rax, r11"),
        Q!("    mul             " "r10"),
        Q!("    add             " "rbx, rax"),
        Q!("    adc             " "rcx, rdx"),

        Q!("    xor             " "esi, esi"),
        Q!("    mov             " "rax, [rsp + " U!() "+ 2 * " N!() "]"),
        Q!("    xor             " "rax, r13"),
        Q!("    mul             " "r12"),
        Q!("    mov             " "[rsp + " U!() "+ 2 * " N!() "], rbx"),
        Q!("    add             " "rbp, rax"),
        Q!("    adc             " "rsi, rdx"),
        Q!("    mov             " "rax, [rsp + " V!() "+ 2 * " N!() "]"),
        Q!("    xor             " "rax, r15"),
        Q!("    mul             " "r14"),
        Q!("    add             " "rbp, rax"),
        Q!("    adc             " "rsi, rdx"),
        Q!("    mov             " "[rsp + " V!() "+ 2 * " N!() "], rbp"),

        // Digit 3 of [u,v]

        Q!("    xor             " "ebx, ebx"),
        Q!("    mov             " "rax, [rsp + " U!() "+ 3 * " N!() "]"),
        Q!("    xor             " "rax, r9"),
        Q!("    mul             " "r8"),
        Q!("    add             " "rcx, rax"),
        Q!("    adc             " "rbx, rdx"),
        Q!("    mov             " "rax, [rsp + " V!() "+ 3 * " N!() "]"),
        Q!("    xor             " "rax, r11"),
        Q!("    mul             " "r10"),
        Q!("    add             " "rcx, rax"),
        Q!("    adc             " "rbx, rdx"),

        Q!("    xor             " "ebp, ebp"),
        Q!("    mov             " "rax, [rsp + " U!() "+ 3 * " N!() "]"),
        Q!("    xor             " "rax, r13"),
        Q!("    mul             " "r12"),
        Q!("    mov             " "[rsp + " U!() "+ 3 * " N!() "], rcx"),
        Q!("    add             " "rsi, rax"),
        Q!("    adc             " "rbp, rdx"),
        Q!("    mov             " "rax, [rsp + " V!() "+ 3 * " N!() "]"),
        Q!("    xor             " "rax, r15"),
        Q!("    mul             " "r14"),
        Q!("    add             " "rsi, rax"),
        Q!("    adc             " "rbp, rdx"),
        Q!("    mov             " "[rsp + " V!() "+ 3 * " N!() "], rsi"),

        // Digit 4 of [u,v]

        Q!("    xor             " "ecx, ecx"),
        Q!("    mov             " "rax, [rsp + " U!() "+ 4 * " N!() "]"),
        Q!("    xor             " "rax, r9"),
        Q!("    mul             " "r8"),
        Q!("    add             " "rbx, rax"),
        Q!("    adc             " "rcx, rdx"),
        Q!("    mov             " "rax, [rsp + " V!() "+ 4 * " N!() "]"),
        Q!("    xor             " "rax, r11"),
        Q!("    mul             " "r10"),
        Q!("    add             " "rbx, rax"),
        Q!("    adc             " "rcx, rdx"),

        Q!("    xor             " "esi, esi"),
        Q!("    mov             " "rax, [rsp + " U!() "+ 4 * " N!() "]"),
        Q!("    xor             " "rax, r13"),
        Q!("    mul             " "r12"),
        Q!("    mov             " "[rsp + " U!() "+ 4 * " N!() "], rbx"),
        Q!("    add             " "rbp, rax"),
        Q!("    adc             " "rsi, rdx"),
        Q!("    mov             " "rax, [rsp + " V!() "+ 4 * " N!() "]"),
        Q!("    xor             " "rax, r15"),
        Q!("    mul             " "r14"),
        Q!("    add             " "rbp, rax"),
        Q!("    adc             " "rsi, rdx"),
        Q!("    mov             " "[rsp + " V!() "+ 4 * " N!() "], rbp"),

        // Digit 5 of [u,v]

        Q!("    xor             " "ebx, ebx"),
        Q!("    mov             " "rax, [rsp + " U!() "+ 5 * " N!() "]"),
        Q!("    xor             " "rax, r9"),
        Q!("    mul             " "r8"),
        Q!("    add             " "rcx, rax"),
        Q!("    adc             " "rbx, rdx"),
        Q!("    mov             " "rax, [rsp + " V!() "+ 5 * " N!() "]"),
        Q!("    xor             " "rax, r11"),
        Q!("    mul             " "r10"),
        Q!("    add             " "rcx, rax"),
        Q!("    adc             " "rbx, rdx"),

        Q!("    xor             " "ebp, ebp"),
        Q!("    mov             " "rax, [rsp + " U!() "+ 5 * " N!() "]"),
        Q!("    xor             " "rax, r13"),
        Q!("    mul             " "r12"),
        Q!("    mov             " "[rsp + " U!() "+ 5 * " N!() "], rcx"),
        Q!("    add             " "rsi, rax"),
        Q!("    adc             " "rbp, rdx"),
        Q!("    mov             " "rax, [rsp + " V!() "+ 5 * " N!() "]"),
        Q!("    xor             " "rax, r15"),
        Q!("    mul             " "r14"),
        Q!("    add             " "rsi, rax"),
        Q!("    adc             " "rbp, rdx"),
        Q!("    mov             " "[rsp + " V!() "+ 5 * " N!() "], rsi"),

        // Digit 6 of [u,v]

        Q!("    xor             " "ecx, ecx"),
        Q!("    mov             " "rax, [rsp + " U!() "+ 6 * " N!() "]"),
        Q!("    xor             " "rax, r9"),
        Q!("    mul             " "r8"),
        Q!("    add             " "rbx, rax"),
        Q!("    adc             " "rcx, rdx"),
        Q!("    mov             " "rax, [rsp + " V!() "+ 6 * " N!() "]"),
        Q!("    xor             " "rax, r11"),
        Q!("    mul             " "r10"),
        Q!("    add             " "rbx, rax"),
        Q!("    adc             " "rcx, rdx"),

        Q!("    xor             " "esi, esi"),
        Q!("    mov             " "rax, [rsp + " U!() "+ 6 * " N!() "]"),
        Q!("    xor             " "rax, r13"),
        Q!("    mul             " "r12"),
        Q!("    mov             " "[rsp + " U!() "+ 6 * " N!() "], rbx"),
        Q!("    add             " "rbp, rax"),
        Q!("    adc             " "rsi, rdx"),
        Q!("    mov             " "rax, [rsp + " V!() "+ 6 * " N!() "]"),
        Q!("    xor             " "rax, r15"),
        Q!("    mul             " "r14"),
        Q!("    add             " "rbp, rax"),
        Q!("    adc             " "rsi, rdx"),
        Q!("    mov             " "[rsp + " V!() "+ 6 * " N!() "], rbp"),

        // Digit 7 of [u,v]

        Q!("    xor             " "ebx, ebx"),
        Q!("    mov             " "rax, [rsp + " U!() "+ 7 * " N!() "]"),
        Q!("    xor             " "rax, r9"),
        Q!("    mul             " "r8"),
        Q!("    add             " "rcx, rax"),
        Q!("    adc             " "rbx, rdx"),
        Q!("    mov             " "rax, [rsp + " V!() "+ 7 * " N!() "]"),
        Q!("    xor             " "rax, r11"),
        Q!("    mul             " "r10"),
        Q!("    add             " "rcx, rax"),
        Q!("    adc             " "rbx, rdx"),

        Q!("    xor             " "ebp, ebp"),
        Q!("    mov             " "rax, [rsp + " U!() "+ 7 * " N!() "]"),
        Q!("    xor             " "rax, r13"),
        Q!("    mul             " "r12"),
        Q!("    mov             " "[rsp + " U!() "+ 7 * " N!() "], rcx"),
        Q!("    add             " "rsi, rax"),
        Q!("    adc             " "rbp, rdx"),
        Q!("    mov             " "rax, [rsp + " V!() "+ 7 * " N!() "]"),
        Q!("    xor             " "rax, r15"),
        Q!("    mul             " "r14"),
        Q!("    add             " "rsi, rax"),
        Q!("    adc             " "rbp, rdx"),
        Q!("    mov             " "[rsp + " V!() "+ 7 * " N!() "], rsi"),

        // Digits 8 and 9 of u (top is unsigned)

        Q!("    mov             " "rax, [rsp + " U!() "+ 8 * " N!() "]"),
        Q!("    xor             " "rax, r9"),
        Q!("    mov             " "rcx, r9"),
        Q!("    and             " "rcx, r8"),
        Q!("    neg             " "rcx"),
        Q!("    mul             " "r8"),
        Q!("    add             " "rbx, rax"),
        Q!("    adc             " "rcx, rdx"),
        Q!("    mov             " "rax, [rsp + " V!() "+ 8 * " N!() "]"),
        Q!("    xor             " "rax, r11"),
        Q!("    mov             " "rdx, r11"),
        Q!("    and             " "rdx, r10"),
        Q!("    sub             " "rcx, rdx"),
        Q!("    mul             " "r10"),
        Q!("    add             " "rbx, rax"),
        Q!("    adc             " "rdx, rcx"),

        // Modular reduction of u

        Q!("    mov             " "rax, rdx"),
        Q!("    shld            " "rdx, rbx, 55"),
        Q!("    sar             " "rax, 63"),
        Q!("    add             " "rdx, rax"),
        Q!("    mov             " "rax, rdx"),
        Q!("    shl             " "rdx, 9"),
        Q!("    sub             " "rbx, rdx"),
        Q!("    mov             " "rdx, rax"),
        Q!("    sar             " "rax, 63"),
        Q!("    mov             " "rcx, [rsp + " U!() "]"),
        Q!("    add             " "rcx, rdx"),
        Q!("    mov             " "[rsp + " U!() "], rcx"),
        Q!("    mov             " "rcx, [rsp + " U!() "+ " N!() "]"),
        Q!("    adc             " "rcx, rax"),
        Q!("    mov             " "[rsp + " U!() "+ " N!() "], rcx"),
        Q!("    mov             " "rcx, [rsp + " U!() "+ 2 * " N!() "]"),
        Q!("    adc             " "rcx, rax"),
        Q!("    mov             " "[rsp + " U!() "+ 2 * " N!() "], rcx"),
        Q!("    mov             " "rcx, [rsp + " U!() "+ 3 * " N!() "]"),
        Q!("    adc             " "rcx, rax"),
        Q!("    mov             " "[rsp + " U!() "+ 3 * " N!() "], rcx"),
        Q!("    mov             " "rcx, [rsp + " U!() "+ 4 * " N!() "]"),
        Q!("    adc             " "rcx, rax"),
        Q!("    mov             " "[rsp + " U!() "+ 4 * " N!() "], rcx"),
        Q!("    mov             " "rcx, [rsp + " U!() "+ 5 * " N!() "]"),
        Q!("    adc             " "rcx, rax"),
        Q!("    mov             " "[rsp + " U!() "+ 5 * " N!() "], rcx"),
        Q!("    mov             " "rcx, [rsp + " U!() "+ 6 * " N!() "]"),
        Q!("    adc             " "rcx, rax"),
        Q!("    mov             " "[rsp + " U!() "+ 6 * " N!() "], rcx"),
        Q!("    mov             " "rcx, [rsp + " U!() "+ 7 * " N!() "]"),
        Q!("    adc             " "rcx, rax"),
        Q!("    mov             " "[rsp + " U!() "+ 7 * " N!() "], rcx"),
        Q!("    adc             " "rbx, rax"),

        // Preload for last use of old u digit 8

        Q!("    mov             " "rax, [rsp + " U!() "+ 8 * " N!() "]"),
        Q!("    mov             " "[rsp + " U!() "+ 8 * " N!() "], rbx"),

        // Digits 8 and 9 of v (top is unsigned)

        Q!("    xor             " "rax, r13"),
        Q!("    mov             " "rbx, r13"),
        Q!("    and             " "rbx, r12"),
        Q!("    neg             " "rbx"),
        Q!("    mul             " "r12"),
        Q!("    add             " "rbp, rax"),
        Q!("    adc             " "rbx, rdx"),
        Q!("    mov             " "rax, [rsp + " V!() "+ 8 * " N!() "]"),
        Q!("    xor             " "rax, r15"),
        Q!("    mov             " "rdx, r15"),
        Q!("    and             " "rdx, r14"),
        Q!("    sub             " "rbx, rdx"),
        Q!("    mul             " "r14"),
        Q!("    add             " "rbp, rax"),
        Q!("    adc             " "rdx, rbx"),

        // Modular reduction of v

        Q!("    mov             " "rax, rdx"),
        Q!("    shld            " "rdx, rbp, 55"),
        Q!("    sar             " "rax, 63"),
        Q!("    add             " "rdx, rax"),
        Q!("    mov             " "rax, rdx"),
        Q!("    shl             " "rdx, 9"),
        Q!("    sub             " "rbp, rdx"),
        Q!("    mov             " "rdx, rax"),
        Q!("    sar             " "rax, 63"),
        Q!("    mov             " "rcx, [rsp + " V!() "]"),
        Q!("    add             " "rcx, rdx"),
        Q!("    mov             " "[rsp + " V!() "], rcx"),
        Q!("    mov             " "rcx, [rsp + " V!() "+ " N!() "]"),
        Q!("    adc             " "rcx, rax"),
        Q!("    mov             " "[rsp + " V!() "+ " N!() "], rcx"),
        Q!("    mov             " "rcx, [rsp + " V!() "+ 2 * " N!() "]"),
        Q!("    adc             " "rcx, rax"),
        Q!("    mov             " "[rsp + " V!() "+ 2 * " N!() "], rcx"),
        Q!("    mov             " "rcx, [rsp + " V!() "+ 3 * " N!() "]"),
        Q!("    adc             " "rcx, rax"),
        Q!("    mov             " "[rsp + " V!() "+ 3 * " N!() "], rcx"),
        Q!("    mov             " "rcx, [rsp + " V!() "+ 4 * " N!() "]"),
        Q!("    adc             " "rcx, rax"),
        Q!("    mov             " "[rsp + " V!() "+ 4 * " N!() "], rcx"),
        Q!("    mov             " "rcx, [rsp + " V!() "+ 5 * " N!() "]"),
        Q!("    adc             " "rcx, rax"),
        Q!("    mov             " "[rsp + " V!() "+ 5 * " N!() "], rcx"),
        Q!("    mov             " "rcx, [rsp + " V!() "+ 6 * " N!() "]"),
        Q!("    adc             " "rcx, rax"),
        Q!("    mov             " "[rsp + " V!() "+ 6 * " N!() "], rcx"),
        Q!("    mov             " "rcx, [rsp + " V!() "+ 7 * " N!() "]"),
        Q!("    adc             " "rcx, rax"),
        Q!("    mov             " "[rsp + " V!() "+ 7 * " N!() "], rcx"),
        Q!("    adc             " "rbp, rax"),
        Q!("    mov             " "[rsp + " V!() "+ 8 * " N!() "], rbp"),

        Q!(Label!("Lbignum_inv_p521_midloop", 2) ":"),

        divstep59!(d!(), ff!(), gg!()),
        Q!("    mov             " d!() ", rsi"),

        // Next iteration

        Q!("    dec             " i!()),
        Q!("    jnz             " Label!("Lbignum_inv_p521_loop", 3, Before)),

        // The 21st and last iteration does not need anything except the
        // u value and the sign of f; the latter can be obtained from the
        // lowest word of f. So it's done differently from the main loop.
        // Find the sign of the new f. For this we just need one digit
        // since we know (for in-scope cases) that f is either +1 or -1.
        // We don't explicitly shift right by 59 either, but looking at
        // bit 63 (or any bit >= 60) of the unshifted result is enough
        // to distinguish -1 from +1; this is then made into a mask.

        Q!("    mov             " "rax, [rsp + " F!() "]"),
        Q!("    mov             " "rcx, [rsp + " G!() "]"),
        Q!("    imul            " "rax, r8"),
        Q!("    imul            " "rcx, r10"),
        Q!("    add             " "rax, rcx"),
        Q!("    sar             " "rax, 63"),

        // Now separate out the matrix into sign-magnitude pairs
        // and adjust each one based on the sign of f.
        //
        // Note that at this point we expect |f|=1 and we got its
        // sign above, so then since [f,0] == x * [u,v] (mod p_521)
        // we want to flip the sign of u according to that of f.

        Q!("    mov             " "r9, r8"),
        Q!("    sar             " "r9, 63"),
        Q!("    xor             " "r8, r9"),
        Q!("    sub             " "r8, r9"),
        Q!("    xor             " "r9, rax"),

        Q!("    mov             " "r11, r10"),
        Q!("    sar             " "r11, 63"),
        Q!("    xor             " "r10, r11"),
        Q!("    sub             " "r10, r11"),
        Q!("    xor             " "r11, rax"),

        Q!("    mov             " "r13, r12"),
        Q!("    sar             " "r13, 63"),
        Q!("    xor             " "r12, r13"),
        Q!("    sub             " "r12, r13"),
        Q!("    xor             " "r13, rax"),

        Q!("    mov             " "r15, r14"),
        Q!("    sar             " "r15, 63"),
        Q!("    xor             " "r14, r15"),
        Q!("    sub             " "r14, r15"),
        Q!("    xor             " "r15, rax"),

        // Adjust the initial value to allow for complement instead of negation

        Q!("    mov             " "rax, r8"),
        Q!("    and             " "rax, r9"),
        Q!("    mov             " "rbx, r10"),
        Q!("    and             " "rbx, r11"),
        Q!("    add             " "rbx, rax"),

        // Digit 0 of u

        Q!("    xor             " "ecx, ecx"),
        Q!("    mov             " "rax, [rsp + " U!() "]"),
        Q!("    xor             " "rax, r9"),
        Q!("    mul             " "r8"),
        Q!("    add             " "rbx, rax"),
        Q!("    adc             " "rcx, rdx"),
        Q!("    mov             " "rax, [rsp + " V!() "]"),
        Q!("    xor             " "rax, r11"),
        Q!("    mul             " "r10"),
        Q!("    add             " "rbx, rax"),
        Q!("    mov             " "[rsp + " U!() "], rbx"),
        Q!("    adc             " "rcx, rdx"),

        // Digit 1 of u

        Q!("    xor             " "ebx, ebx"),
        Q!("    mov             " "rax, [rsp + " U!() "+ " N!() "]"),
        Q!("    xor             " "rax, r9"),
        Q!("    mul             " "r8"),
        Q!("    add             " "rcx, rax"),
        Q!("    adc             " "rbx, rdx"),
        Q!("    mov             " "rax, [rsp + " V!() "+ " N!() "]"),
        Q!("    xor             " "rax, r11"),
        Q!("    mul             " "r10"),
        Q!("    add             " "rcx, rax"),
        Q!("    mov             " "[rsp + " U!() "+ " N!() "], rcx"),
        Q!("    adc             " "rbx, rdx"),

        // Digit 2 of u

        Q!("    xor             " "ecx, ecx"),
        Q!("    mov             " "rax, [rsp + " U!() "+ 2 * " N!() "]"),
        Q!("    xor             " "rax, r9"),
        Q!("    mul             " "r8"),
        Q!("    add             " "rbx, rax"),
        Q!("    adc             " "rcx, rdx"),
        Q!("    mov             " "rax, [rsp + " V!() "+ 2 * " N!() "]"),
        Q!("    xor             " "rax, r11"),
        Q!("    mul             " "r10"),
        Q!("    add             " "rbx, rax"),
        Q!("    mov             " "[rsp + " U!() "+ 2 * " N!() "], rbx"),
        Q!("    adc             " "rcx, rdx"),

        // Digit 3 of u

        Q!("    xor             " "ebx, ebx"),
        Q!("    mov             " "rax, [rsp + " U!() "+ 3 * " N!() "]"),
        Q!("    xor             " "rax, r9"),
        Q!("    mul             " "r8"),
        Q!("    add             " "rcx, rax"),
        Q!("    adc             " "rbx, rdx"),
        Q!("    mov             " "rax, [rsp + " V!() "+ 3 * " N!() "]"),
        Q!("    xor             " "rax, r11"),
        Q!("    mul             " "r10"),
        Q!("    add             " "rcx, rax"),
        Q!("    mov             " "[rsp + " U!() "+ 3 * " N!() "], rcx"),
        Q!("    adc             " "rbx, rdx"),

        // Digit 4 of u

        Q!("    xor             " "ecx, ecx"),
        Q!("    mov             " "rax, [rsp + " U!() "+ 4 * " N!() "]"),
        Q!("    xor             " "rax, r9"),
        Q!("    mul             " "r8"),
        Q!("    add             " "rbx, rax"),
        Q!("    adc             " "rcx, rdx"),
        Q!("    mov             " "rax, [rsp + " V!() "+ 4 * " N!() "]"),
        Q!("    xor             " "rax, r11"),
        Q!("    mul             " "r10"),
        Q!("    add             " "rbx, rax"),
        Q!("    mov             " "[rsp + " U!() "+ 4 * " N!() "], rbx"),
        Q!("    adc             " "rcx, rdx"),

        // Digit 5 of u

        Q!("    xor             " "ebx, ebx"),
        Q!("    mov             " "rax, [rsp + " U!() "+ 5 * " N!() "]"),
        Q!("    xor             " "rax, r9"),
        Q!("    mul             " "r8"),
        Q!("    add             " "rcx, rax"),
        Q!("    adc             " "rbx, rdx"),
        Q!("    mov             " "rax, [rsp + " V!() "+ 5 * " N!() "]"),
        Q!("    xor             " "rax, r11"),
        Q!("    mul             " "r10"),
        Q!("    add             " "rcx, rax"),
        Q!("    mov             " "[rsp + " U!() "+ 5 * " N!() "], rcx"),
        Q!("    adc             " "rbx, rdx"),

        // Digit 6 of u

        Q!("    xor             " "ecx, ecx"),
        Q!("    mov             " "rax, [rsp + " U!() "+ 6 * " N!() "]"),
        Q!("    xor             " "rax, r9"),
        Q!("    mul             " "r8"),
        Q!("    add             " "rbx, rax"),
        Q!("    adc             " "rcx, rdx"),
        Q!("    mov             " "rax, [rsp + " V!() "+ 6 * " N!() "]"),
        Q!("    xor             " "rax, r11"),
        Q!("    mul             " "r10"),
        Q!("    add             " "rbx, rax"),
        Q!("    mov             " "[rsp + " U!() "+ 6 * " N!() "], rbx"),
        Q!("    adc             " "rcx, rdx"),

        // Digit 7 of u

        Q!("    xor             " "ebx, ebx"),
        Q!("    mov             " "rax, [rsp + " U!() "+ 7 * " N!() "]"),
        Q!("    xor             " "rax, r9"),
        Q!("    mul             " "r8"),
        Q!("    add             " "rcx, rax"),
        Q!("    adc             " "rbx, rdx"),
        Q!("    mov             " "rax, [rsp + " V!() "+ 7 * " N!() "]"),
        Q!("    xor             " "rax, r11"),
        Q!("    mul             " "r10"),
        Q!("    add             " "rcx, rax"),
        Q!("    mov             " "[rsp + " U!() "+ 7 * " N!() "], rcx"),
        Q!("    adc             " "rbx, rdx"),

        // Digits 8 and 9 of u (top is unsigned)

        Q!("    mov             " "rax, [rsp + " U!() "+ 8 * " N!() "]"),
        Q!("    xor             " "rax, r9"),
        Q!("    mov             " "rcx, r9"),
        Q!("    and             " "rcx, r8"),
        Q!("    neg             " "rcx"),
        Q!("    mul             " "r8"),
        Q!("    add             " "rbx, rax"),
        Q!("    adc             " "rcx, rdx"),
        Q!("    mov             " "rax, [rsp + " V!() "+ 8 * " N!() "]"),
        Q!("    xor             " "rax, r11"),
        Q!("    mov             " "rdx, r11"),
        Q!("    and             " "rdx, r10"),
        Q!("    sub             " "rcx, rdx"),
        Q!("    mul             " "r10"),
        Q!("    add             " "rbx, rax"),
        Q!("    adc             " "rdx, rcx"),

        // Modular reduction of u

        Q!("    mov             " "rax, rdx"),
        Q!("    shld            " "rdx, rbx, 55"),
        Q!("    sar             " "rax, 63"),
        Q!("    add             " "rdx, rax"),
        Q!("    mov             " "rax, rdx"),
        Q!("    shl             " "rdx, 9"),
        Q!("    sub             " "rbx, rdx"),
        Q!("    mov             " "rdx, rax"),
        Q!("    sar             " "rax, 63"),
        Q!("    mov             " "rcx, [rsp + " U!() "]"),
        Q!("    add             " "rcx, rdx"),
        Q!("    mov             " "[rsp + " U!() "], rcx"),
        Q!("    mov             " "rcx, [rsp + " U!() "+ " N!() "]"),
        Q!("    adc             " "rcx, rax"),
        Q!("    mov             " "[rsp + " U!() "+ " N!() "], rcx"),
        Q!("    mov             " "rcx, [rsp + " U!() "+ 2 * " N!() "]"),
        Q!("    adc             " "rcx, rax"),
        Q!("    mov             " "[rsp + " U!() "+ 2 * " N!() "], rcx"),
        Q!("    mov             " "rcx, [rsp + " U!() "+ 3 * " N!() "]"),
        Q!("    adc             " "rcx, rax"),
        Q!("    mov             " "[rsp + " U!() "+ 3 * " N!() "], rcx"),
        Q!("    mov             " "rcx, [rsp + " U!() "+ 4 * " N!() "]"),
        Q!("    adc             " "rcx, rax"),
        Q!("    mov             " "[rsp + " U!() "+ 4 * " N!() "], rcx"),
        Q!("    mov             " "rcx, [rsp + " U!() "+ 5 * " N!() "]"),
        Q!("    adc             " "rcx, rax"),
        Q!("    mov             " "[rsp + " U!() "+ 5 * " N!() "], rcx"),
        Q!("    mov             " "rcx, [rsp + " U!() "+ 6 * " N!() "]"),
        Q!("    adc             " "rcx, rax"),
        Q!("    mov             " "[rsp + " U!() "+ 6 * " N!() "], rcx"),
        Q!("    mov             " "rcx, [rsp + " U!() "+ 7 * " N!() "]"),
        Q!("    adc             " "rcx, rax"),
        Q!("    mov             " "[rsp + " U!() "+ 7 * " N!() "], rcx"),
        Q!("    adc             " "rbx, rax"),
        Q!("    mov             " "[rsp + " U!() "+ 8 * " N!() "], rbx"),

        // Further strict reduction ready for the output, which just means
        // a conditional subtraction of p_521

        Q!("    xor             " "eax, eax"),
        Q!("    not             " "rax"),
        Q!("    mov             " "r8, [rsp + " U!() "]"),
        Q!("    sub             " "r8, rax"),
        Q!("    mov             " "r9, [rsp + " U!() "+ " N!() "]"),
        Q!("    sbb             " "r9, rax"),
        Q!("    mov             " "r10, [rsp + " U!() "+ 2 * " N!() "]"),
        Q!("    sbb             " "r10, rax"),
        Q!("    mov             " "r11, [rsp + " U!() "+ 3 * " N!() "]"),
        Q!("    sbb             " "r11, rax"),
        Q!("    mov             " "r12, [rsp + " U!() "+ 4 * " N!() "]"),
        Q!("    sbb             " "r12, rax"),
        Q!("    mov             " "r13, [rsp + " U!() "+ 5 * " N!() "]"),
        Q!("    sbb             " "r13, rax"),
        Q!("    mov             " "r14, [rsp + " U!() "+ 6 * " N!() "]"),
        Q!("    sbb             " "r14, rax"),
        Q!("    mov             " "r15, [rsp + " U!() "+ 7 * " N!() "]"),
        Q!("    sbb             " "r15, rax"),
        Q!("    mov             " "eax, 0x1FF"),
        Q!("    mov             " "rbp, [rsp + " U!() "+ 8 * " N!() "]"),
        Q!("    sbb             " "rbp, rax"),

        Q!("    cmovc           " "r8, [rsp + " U!() "]"),
        Q!("    cmovc           " "r9, [rsp + " U!() "+ " N!() "]"),
        Q!("    cmovc           " "r10, [rsp + " U!() "+ 2 * " N!() "]"),
        Q!("    cmovc           " "r11, [rsp + " U!() "+ 3 * " N!() "]"),
        Q!("    cmovc           " "r12, [rsp + " U!() "+ 4 * " N!() "]"),
        Q!("    cmovc           " "r13, [rsp + " U!() "+ 5 * " N!() "]"),
        Q!("    cmovc           " "r14, [rsp + " U!() "+ 6 * " N!() "]"),
        Q!("    cmovc           " "r15, [rsp + " U!() "+ 7 * " N!() "]"),
        Q!("    cmovc           " "rbp, [rsp + " U!() "+ 8 * " N!() "]"),

        // Store it back to the final output

        Q!("    mov             " "rdi, " res!()),
        Q!("    mov             " "[rdi], r8"),
        Q!("    mov             " "[rdi + " N!() "], r9"),
        Q!("    mov             " "[rdi + 2 * " N!() "], r10"),
        Q!("    mov             " "[rdi + 3 * " N!() "], r11"),
        Q!("    mov             " "[rdi + 4 * " N!() "], r12"),
        Q!("    mov             " "[rdi + 5 * " N!() "], r13"),
        Q!("    mov             " "[rdi + 6 * " N!() "], r14"),
        Q!("    mov             " "[rdi + 7 * " N!() "], r15"),
        Q!("    mov             " "[rdi + 8 * " N!() "], rbp"),

        // Restore stack and registers

        Q!("    add             " "rsp, " NSPACE!()),

        Q!("    pop             " "r15"),
        Q!("    pop             " "r14"),
        Q!("    pop             " "r13"),
        Q!("    pop             " "r12"),
        Q!("    pop             " "rbp"),
        Q!("    pop             " "rbx"),

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
