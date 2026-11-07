# [M] Mutation testing on AVX-512

## Goal

`admin/mutants` reaches the code only AVX-512 CPUs run: RSAZ's AVX-512 exponentiation (`rsaz_avx512.rs`, `rsaz.rs`), ML-KEM's 8-way sampling (`mlkem768_sample_poly_ntt_8x.rs`), AES-GCM's AVX-512 kernel (`aes_gcm.rs`), and the CPU checks that pick them. Each mutant there that no test catches is killed by a test or recorded with its reason, and the `exclude_re` entries in `.cargo/mutants.toml` that point here are gone.

## Plan

- No campaign host has AVX-512: `desktop` is Arrow Lake and `nixos` Zen 3. Run the tests under Intel SDE with an AVX-512 model, such as `-spr`, from `nix develop .#sde` as `admin/x86-cpu` does. Add a row to `admin/mutants`' runner that does this, or probe GitHub's x86_64 runners for AVX-512 first, since one that has it needs no emulator.
- Add the result to `mutants.yml` if it fits a nightly run.
