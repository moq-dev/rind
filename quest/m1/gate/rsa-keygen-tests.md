# [XS] Drop the redundant RSA key generation tests

## Goal

The gate stops running RSA key generation tests that repeat other tests'
coverage, saving about 6-7 CPU-seconds, with no coverage lost.

## Plan

- Delete `test_rsa_bench` (`rind/src/mid/rsa_priv/generate.rs:323`). It
  takes 5.9 s, the gate's longest test, and generates 32 RSA-2048 keys from
  one transcript without asserting anything. `key_generation_known_answer`
  checks that transcript, and `rind-bench/benches/rsa_gen.rs` times it.
- Fold `high::rsa::key_generation_smoke_test` (0.93 s) into crosschecks'
  `check_key_generation`, so one random key per size is both accepted by
  aws-lc-rs and signs and verifies. 4096, 6144, and 8192 bits stay under
  `SLOW_TESTS`.
- Lower the proptest cases of `low::generic::p521` `scalar_ops` and
  `scalar_multiply` to 32, as `kem.rs` does (-2.7 CPU-s).
