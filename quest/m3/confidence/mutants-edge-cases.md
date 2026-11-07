# [M] Surviving mutants that need crafted inputs

## Goal

The surviving mutants that random inputs and published vectors never reach are killed by tests, or shown equivalent and recorded, and their `exclude_re` entries in `.cargo/mutants.toml` that point here are gone:

- The AVX2 Ed25519 backend (`edwards25519_scalarmuldouble_avx2.rs`): `Fe4::split`, `Fe4::reduce`, its constant tables, and `non_adjacent_form`. A mask in `reduce` set to all ones passes every test with ADX denied, which runs this path.
- P-256's Booth recoding in `mid/p256.rs`, and the point at infinity in P-256's, P-384's, and P-521's twin multiplication.
- RSA key derivation's borrow in `divide_exact_odd`, and SHA-1's AVX2 message schedule (`Expander::step`).

## Plan

- Test each `Fe4` operation differentially against the scalar field arithmetic, with limbs at the bounds each operation accepts, rather than through whole scalar multiplications.
- Build the ECDSA signatures whose `u1·G + u2·Q` is the point at infinity, and take Wycheproof's where it has them.
