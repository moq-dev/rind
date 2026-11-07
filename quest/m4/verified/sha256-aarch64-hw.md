# [L] aarch64 SHA-256 on the SHA-2 instructions is proven

## Goal

SHA-256, and HMAC, HKDF, and PBKDF2 over it, earn the ✓ on aarch64 with the crypto extension, the hash under every TLS 1.3 handshake's transcript and key schedule there.

## Plan

- Runs: aws-lc's `sha256_block_data_order_hw` (`low/aarch64/aws_lc/sha256_block_data_order_hw.*.s`, 123 instructions), under the padding, HMAC, HKDF, and PBKDF2 glue `proofs/` proves. It keeps a register copy off each round's dependency chain, where LLVM's code for rind's intrinsics puts one on it, so it is faster than those intrinsics. pyca's Lean-proven routine is 1.9x slower.
- Already proven: nothing. s2n-bignum models `sha256h`, `sha256h2`, `sha256su0`, and `sha256su1` but has no SHA-256 routine.
- Route: a HOL Light proof of the routine in s2n-bignum's aarch64 model against [awslabs/s2n-bignum#415](https://github.com/awslabs/s2n-bignum/pull/415)'s FIPS 180-4 SHA-256 spec, which [#450](https://github.com/awslabs/s2n-bignum/pull/450)'s x86_64 proof also uses, estimated at 3-5 person-weeks for someone fluent in s2n-bignum. It then enters `proofs/Rind/Aarch64/ShaBlocks.lean` as an axiom, retiring that hypothesis's SHA-256 half on this tier.
- Spec pin: build on [awslabs/s2n-bignum#415](https://github.com/awslabs/s2n-bignum/pull/415)'s spec at a pinned commit while it is unmerged, and move to the merged version when it lands; `benchmarks/verified.toml`'s ✓ notes the pin (decided with the maintainer on 2026-11-07 on [moq-dev/rind#448](https://github.com/moq-dev/rind/pull/448)).
- Upstream: offering this work to awslabs/s2n-bignum is optional, and there is no standing approval: stop and ask the maintainer before posting there or anywhere outside the moq-dev and kixelated orgs (decided with the maintainer on 2026-11-07 on [moq-dev/rind#448](https://github.com/moq-dev/rind/pull/448)).

## Required

- [rind's own HOL Light proofs live in proofs/hol-light](/quest/m4/verified/hol-light.md) - where the HOL Light proofs live and CI checks them
