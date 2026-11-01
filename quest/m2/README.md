# m2: later work

## Goal

Work that follows the release MoQ switches to: the speed and armv7 work that
does not block it.

## Required

- [Fastest at every algorithm](/quest/m2/speed/README.md) - every algorithm on every path as fast as any permissive source
- [RSA key generation refuses primes too close together](/quest/m2/rsa-prime-distance.md) - generation draws a new q when |p - q| is within 2^(nlen/2 - 100), as FIPS 186-5 and aws-lc require
- [Constant-time in armv7 debug builds too](/quest/m2/debug-ct.md) - armv7 debug ctgrind passes, finishing the sweep the nightly jobs do not cover
