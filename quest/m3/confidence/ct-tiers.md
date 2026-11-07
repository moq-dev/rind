# [M] A constant-time check on every tier

## Goal

Every secret-handling path [TESTING.md](/TESTING.md)'s tiers table lists has a constant-time check, closing the gaps it links here:
- Intel's AVX SHA-1, SHA-256, and SHA-512, which Sandy and Ivy Bridge run: valgrind checks them only on an Intel host, and GitHub's runners are AMD;
- aarch64's SHA-3 and SHA-512 instruction paths, and the path for cores without SHA-3: it is unknown which of them valgrind runs on the arm64 runner.

## Plan

- Intel AVX SHA: a `ct_sde_...` test on SDE's Sandy Bridge model, as `ct_sde_hmac` checks the SHA extensions on Arrow Lake.
- aarch64: find which paths `admin/ctgrind` takes on the arm64 runner (`RIND_TEST_ARM_*`-style assertions say it), deny what valgrind runs to reach the others, and trace-compare what it cannot run under qemu-aarch64, as `admin/ct-qemu` does for armv7.
