// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0
//
// The qemu plugin `admin/ct-qemu` traces with, in qemu-arm or qemu-aarch64.
// Between the marks `rind/src/low/arm/ct_qemu.rs` executes, it writes to
// `out` the address of every instruction and memory access each thread
// makes, as 12-byte records of a kind (`I`, `R`, or `W`), a size in bytes,
// two zero bytes, and a little-endian 64-bit address. Values are left out,
// so two runs with different secrets trace the same unless an address
// depends on one.

#include <qemu-plugin.h>
#include <stdio.h>
#include <string.h>

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;

// `hint #82` and `hint #83`, which execute as no-ops, in ARM mode and in A64.
#define ARM_MARK_START 0xe320f052u
#define ARM_MARK_STOP 0xe320f053u
#define A64_MARK_START 0xd5032a5fu
#define A64_MARK_STOP 0xd5032a7fu

static uint32_t mark_start, mark_stop;
static FILE *out;
// Whether each thread is between the marks.
static qemu_plugin_u64 tracing;

static void record(char kind, unsigned size, uint64_t addr) {
    unsigned char r[12] = {(unsigned char)kind, (unsigned char)size, 0, 0};
    for (int i = 0; i < 8; i++) {
        r[4 + i] = (unsigned char)(addr >> (8 * i));
    }
    fwrite(r, sizeof r, 1, out);
}

// An instruction's handle lasts only while it is translated, so its size
// and address are packed into the callback's `udata`, which is 64 bits on
// the hosts qemu-user runs on here: the size above the 56 bits a user-space
// address fits in.
#define ADDR_BITS 56

static void insn_exec(unsigned int vcpu, void *udata) {
    uint64_t packed = (uintptr_t)udata;
    record('I', packed >> ADDR_BITS, packed & ((1ull << ADDR_BITS) - 1));
}

// Memory callbacks have no conditional form, so this tests the flag itself.
static void mem_access(unsigned int vcpu, qemu_plugin_meminfo_t info, uint64_t vaddr,
                       void *udata) {
    if (qemu_plugin_u64_get(tracing, vcpu)) {
        char kind = qemu_plugin_mem_is_store(info) ? 'W' : 'R';
        record(kind, 1u << qemu_plugin_mem_size_shift(info), vaddr);
    }
}

static void tb_trans(struct qemu_plugin_tb *tb, void *udata) {
    for (size_t i = 0; i < qemu_plugin_tb_n_insns(tb); i++) {
        struct qemu_plugin_insn *insn = qemu_plugin_tb_get_insn(tb, i);
        uint32_t word = 0;
        if (qemu_plugin_insn_size(insn) == 4) {
            qemu_plugin_insn_data(insn, &word, sizeof word);
        }
        if (word == mark_start || word == mark_stop) {
            qemu_plugin_register_vcpu_insn_exec_inline_per_vcpu(
                insn, QEMU_PLUGIN_INLINE_STORE_U64, tracing, word == mark_start);
            continue;
        }
        uint64_t packed = (uint64_t)qemu_plugin_insn_size(insn) << ADDR_BITS |
                          qemu_plugin_insn_vaddr(insn);
        qemu_plugin_register_vcpu_insn_exec_cond_cb(insn, insn_exec, QEMU_PLUGIN_CB_NO_REGS,
                                                    QEMU_PLUGIN_COND_NE, tracing, 0,
                                                    (void *)(uintptr_t)packed);
        qemu_plugin_register_vcpu_mem_cb(insn, mem_access, QEMU_PLUGIN_CB_NO_REGS,
                                         QEMU_PLUGIN_MEM_RW, NULL);
    }
}

static void at_exit(void *udata) {
    fclose(out);
}

QEMU_PLUGIN_EXPORT int qemu_plugin_install(qemu_plugin_id_t id, const qemu_info_t *info,
                                           int argc, char **argv) {
    const char *path = NULL;
    for (int i = 0; i < argc; i++) {
        if (strncmp(argv[i], "out=", 4) == 0) {
            path = argv[i] + 4;
        }
    }
    if (strcmp(info->target_name, "arm") == 0) {
        mark_start = ARM_MARK_START;
        mark_stop = ARM_MARK_STOP;
    } else if (strcmp(info->target_name, "aarch64") == 0) {
        mark_start = A64_MARK_START;
        mark_stop = A64_MARK_STOP;
    } else {
        fprintf(stderr, "ct-qemu-plugin: no marks for %s\n", info->target_name);
        return -1;
    }
    if (path == NULL || (out = fopen(path, "wb")) == NULL) {
        fprintf(stderr, "ct-qemu-plugin: pass out=<path> to write the trace to\n");
        return -1;
    }
    tracing = qemu_plugin_scoreboard_u64(qemu_plugin_scoreboard_new(sizeof(uint64_t)));
    qemu_plugin_register_vcpu_tb_trans_cb(id, tb_trans, NULL);
    qemu_plugin_register_atexit_cb(id, at_exit, NULL);
    return 0;
}
