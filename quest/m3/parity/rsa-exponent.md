# [XS] 33-bit RSA public exponents

## Goal

rind accepts RSA public exponents up to 33 bits, as ring and aws-lc do, so
rind-ring accepts every key ring does and its README drops the caveat.

## Plan

Decided by the maintainer on 2026-10-31, from rind-ring's differences from
ring.

- The even-or-one refusal from the API audit stays; only the width grows.
- Check the exponent's width on both backends (graviola and libcrux) and the
  public-key, components, and key-pair paths, and keep public-exponent
  arithmetic out of ctgrind's secret set.
- Differential test against aws-lc-rs at 2^32 + 1 and just past 33 bits, and
  update rind-ring's README and tests.
