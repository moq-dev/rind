# Every primitive is tested as thoroughly as the best libraries test theirs

## Goal

Every primitive, on every backend and CPU tier, has published test vectors, a differential fuzz target, a differential test, and a constant-time check that also catches variable-time instructions. Mutation testing shows the tests catch changes to rind's Rust.

## Plan

Decided with the maintainer on 2026-11-07, in m3. rind already has these:
- differential fuzz targets against aws-lc-rs, run nightly;
- Wycheproof and cross-checks against aws-lc-rs;
- Intel SDE CPU models for every x86_64 dispatch path;
- ctgrind, `admin/ct-sde`, and `admin/ct-qemu` for secret-dependent branches and addresses.

All three constant-time tools state they can't see variable-time instructions. OSS-Fuzz, cryptofuzz, and NIST ACVP are planned in [m4 assurance](/quest/m4/assurance/README.md) and aren't repeated here.

- Fix what a check finds in its own quest's PR when it's small; otherwise plan a follow-up.
- Slow suites run in their own workflows, not in `just ci`, as `AGENTS.md` asks.

## Required

- [Every published test vector rind can run](/quest/m3/confidence/vectors.md) - C2SP's CCTV and latest Wycheproof, and aws-lc's and BoringSSL's vector files
- [No variable-time instruction on a secret path](/quest/m3/confidence/vartime-scan.md) - a static scan of the compiled secret paths
- [Statistical timing tests](/quest/m3/confidence/timing.md) - dudect-style tests, and the Marvin toolkit for RSA
- [Mutation testing](/quest/m3/confidence/mutants.md) - cargo-mutants shows which changes the tests miss
- [A differential fuzz target for every primitive](/quest/m3/confidence/fuzz-every-primitive.md) - signing, ciphers, MD5, and GCM's any-IV API compared with aws-lc
- [Fuzz the tiers GitHub's runners cannot reach](/quest/m3/confidence/fuzz-tiers.md) - corpus replay under SDE for AVX-512 and SHA512, and under qemu for armv7
- [A constant-time check on every tier](/quest/m3/confidence/ct-tiers.md) - Intel's AVX SHA under SDE, and aarch64's SHA-3 and SHA-512 paths
