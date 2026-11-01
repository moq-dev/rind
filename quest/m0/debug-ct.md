# [S] Constant-time in debug builds too

## Goal

`admin/ctgrind` passes on debug builds as well as release builds on every
backend, so the nightly debug ctgrind jobs pass and no secret path relies on
release optimizations to stay constant-time.

## Plan

Decided by the maintainer on 2026-11-01. The aarch64 debug ctgrind job in run
41339867326 reported secret-dependent branches in `low::generic::p521`
(`mont_mul`, `bignum_mod_n521`, `add`; test `scalar_ops`, since #133) and in
`mid::rsa_priv::exponents` (`divide_by_gcd`, `reduce_e`, `invert_e`,
`divide_exact_e`; test `key_generation_known_answer`, since #182). It
reproduces on x86_64 at main `1db7d66` with `admin/ctgrind unit --
low::generic::p521::tests::scalar_ops high::rsa::tests::key_generation_known_answer`
in a debug build. Release builds are clean, so the likely cause is debug
overflow checks branching on secret values.

- Confirm the cause, then fix it in the code with explicit wrapping and
  carrying arithmetic rather than by dropping the debug jobs or adding
  suppressions.
- Sweep every secret-handling module for the same pattern, not just these
  two, by running the full debug ctgrind suite on x86_64 and armv7 here and
  dispatching the aarch64 one.
- Keep release performance unchanged; check with the affected benches.
