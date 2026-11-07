#!/usr/bin/env bash
# Replay a fuzz target's corpus once on each CPU tier the host can reach by
# denying features, so the inputs the fuzzer found on the runner's own paths
# also check the slower ones. Each tier denies what the one before it denied
# and more, walking down the tiers TESTING.md lists, since a faster path that
# needs only some of a tier's denied features would otherwise still run. The
# target must take `RIND_CPU_DISABLE_*`, as a build with
# `--cfg rind_cpu_disable` does. Extra arguments go to libFuzzer.
#
# Usage: sh/fuzz-replay.sh TARGET CORPUS [ARGS...]
set -euo pipefail

target=${1:?usage: sh/fuzz-replay.sh TARGET CORPUS [ARGS...]}
corpus=${2:?usage: sh/fuzz-replay.sh TARGET CORPUS [ARGS...]}
shift 2

# The features each tier denies beyond the one before. fuzz.yml fuzzes on
# x86_64 itself, so that list skips the runner's own paths. On x86_64, the
# tiers are: VAES without AVX-512; AVX2 and ADX without VAES or the SHA
# extensions; Haswell's AVX2 without ADX; Sandy Bridge's AVX without AVX2 or
# MOVBE, which reaches rind's VEX-encoded AES-GCM rather than Vale's; AES-NI
# without AVX; SSSE3 without AES-NI; and SSE2.
case "$(uname -m)" in
    x86_64)
        tiers=(
            "avx512f avx512bw"
            "vaes sha sha512 intel"
            "adx"
            "avx2 movbe"
            "avx"
            "aes pclmulqdq sse41"
            "ssse3"
        )
        ;;
    aarch64)
        tiers=(
            ""
            "sha3"
            "aes pmull sha2"
        )
        ;;
    *)
        echo "error: no CPU tiers for $(uname -m)" >&2
        exit 1
        ;;
esac

deny=()
for tier in "${tiers[@]}"; do
    for feature in $tier; do
        deny+=("RIND_CPU_DISABLE_$feature=1")
    done
    echo "==> replaying $corpus denying: ${deny[*]:-nothing}" >&2
    env "${deny[@]}" "$target" -runs=0 "$@" "$corpus"
done
