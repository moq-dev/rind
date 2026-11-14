# [M] A child forked mid self-test never hangs

## Goal

`rind-fips`'s `fork::a_child_forked_mid_self_test_tests_and_exits` passes
every run: a process that forks while another thread runs `self_test` leaves
the child a module it can test and exit from.

## Plan

On main at 645d9d1b the test's forked child hangs in about 1% of runs
(3 of 300 with `cargo nextest run -p rind-fips --test fork
-E 'test(mid_self_test)' --stress-count 300`), hitting its 10-second
deadline, and the hang drops PRs from the merge queue under `just ci`.
`selftest::RUNNING` is already held across `fork`, so the child inherits
another lock taken by the worker thread inside a CAST, such as one in rind
(the HMAC_DRBG `Once` that
[kixel-ai/rind#723](https://github.com/kixel-ai/rind/pull/723) replaces),
the allocator, or std. Attach gdb to a hung child (raise the deadline
locally) to name the lock, then take it in the module's fork handlers or
remove it from the self-test path, as the module does for its own locks.
Check whether #723 alone fixes it before writing more.
