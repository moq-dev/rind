# [M] Adapter API

## Goal

Each `rind-*` adapter's own API is as small and safe as its upstream allows:

- rind-rustls mirrors rustls's providers: `kx_group` and `cipher_suite`
  modules, every group a `&dyn` static, `DEFAULT_*` lists in
  `default_provider()`'s order, and `Ticketer`.
- rind-rcgen loads and generates P-256, P-384, and Ed25519 keys (RSA load
  only), exports PKCS#8 wiped on drop, and returns `rcgen::Error`, so no rind
  type appears in its API.
- Entry points that rind invented, such as `default_provider()`, call
  `rind::cpu::check()` and return its error at setup. Statics that upstream
  requires (`DEFAULT_PROVIDER`) document calling it first.

## Plan

The decisions and their alternatives are in the
[epic](/quest/m1/moq/api/README.md). This runs after the rind children, so
the adapters move onto rind's final API once.

The inventory also found these, which don't need a decision:

- Key-load failures in rind-rustls and rind-rcgen drop the rind error's
  reason; keep it.
- rind-object-store reports its errors as `store: "rind"`, but object_store
  uses that field to name the storage backend.
- rind-rustls's hybrid key exchange carries dead branches for
  SECP256R1MLKEM768 ordering and FIPS.
- rind-dimpl re-checks its key-exchange group at runtime, and rind-rustls
  picks AES-GCM's variant by key length; store the algorithm instead.
- rind-cpuid's feature list lacks `popcnt`, which rind requires.

MoQ uses only each adapter's provider entry point, so check MoQ's planned
call sites (moq-dev/moq `quest/m2/rind/`) against the new signatures.

## Required

- [Errors by role](/quest/m1/moq/api/errors.md) - the last rind change the adapters move onto
