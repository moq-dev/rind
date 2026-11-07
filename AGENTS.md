rind is a pure-Rust cryptography library for [MoQ](https://github.com/moq-dev/moq), derived from [graviola](https://github.com/ctz/graviola), which it no longer tracks.
This is one Rust workspace: the `rind` library, its `rind-<consumer>` adapter crates such as `rind-rustls`, and the unpublished bench, cpuid, timing, and fuzz crates.
[ARCHITECTURE.md](ARCHITECTURE.md) covers the `low`/`mid`/`high` layering, [PLATFORMS.md](PLATFORMS.md) the CPU requirements, and [CONTRIBUTING.md](CONTRIBUTING.md) how to run the tests.

# Required

- Refuse what is unsupported, never fall back. Exactly one backend compiles per architecture; a target without one fails to compile, and a CPU missing a required feature fails with an error naming it.
- Treat every input as hostile: keys, signatures, ciphertexts, encodings. Malformed input is an error, never a panic, and its cost is bounded by design.
- Secret-dependent code runs in constant time: no branch, memory index, or variable-time instruction depends on a secret. New secret-handling paths get a ctgrind test (`admin/ctgrind`).
- Pick the fastest permissively licensed source for each primitive on each backend. Prefer a formally verified one (s2n-bignum, libcrux/HACL*, fiat-crypto) unless another is more than about 10% faster; for bulk encryption (AEAD and header protection), the fastest wins outright. New arithmetic states where its correctness argument comes from.
- Test every primitive against Wycheproof where vectors exist, and differentially against aws-lc-rs (a dev-dependency only).
- Design the API so misuse fails to compile: types over runtime checks, one way to do each job. Borrow an aws-lc-rs or ring name only when it is as clear; the migration guide maps theirs to rind's.
- When in doubt about behavior (what to accept, refuse, or wipe), follow aws-lc-rs: it is the library rind would use if it didn't require C.
- Wipe keys, keyed state, and heap scratch derived from a private key before they are freed, since that scratch can be as good as the key. Wipe nothing else: digest contexts, decrypted messages, stack temporaries, other scratch, and copies inside a call stay unwiped. Safe Rust cannot read them, so wiping them costs speed for nothing.
- Benchmark performance-sensitive changes against aws-lc-rs.
- An adapter for a third-party crate lives in its own `rind-<consumer>` crate, so that crate's major bump never forces one in `rind`. The adapter's version begins with the breaking part of its upstream's (rind-rustls 0.23.x for rustls 0.23), so its own breaking change waits for upstream's.

# Development

PRs target `main`. The `just ci` gate holds only fast, high-signal tests; slow suites run in the other workflows.

```bash
just check        # Lint, compile, and test what the branch changed
just fix          # Auto-fix lint/formatting, same scope
```

Quests: before any work, run `quest context` and follow it.
