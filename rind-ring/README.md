<h1 align="center">rind-ring</h1>
<img width="40%" align="right" src="https://raw.githubusercontent.com/moq-dev/rind/main/admin/picture.png">

[![Latest release](https://img.shields.io/crates/v/rind-ring)](https://crates.io/crates/rind-ring)
[![Documentation](https://img.shields.io/docsrs/rind-ring)](https://docs.rs/rind-ring/)

This crate offers [ring](https://github.com/briansmith/ring) 0.17's API, name for name, backed by [rind](https://github.com/moq-dev/rind/), a fork of [Graviola](https://github.com/ctz/graviola/).
A crate on ring swaps it in by renaming its dependency, with no code
changes:

```toml
[dependencies]
ring = { package = "rind-ring", version = "0.1" }
```

ring's `alloc`, `std`, and `dev_urandom_fallback` features are accepted
and change nothing. The rename reaches only the crate that makes it: Cargo
cannot patch a dependency's `ring` with a crate of another name, so a
dependency that names ring still builds ring.

rind-ring panics wherever ring panics, such as `pbkdf2::derive` on an
output over (2^32 - 1) hash outputs, so its signatures match ring's
exactly (maintainer, 2026-10-31). rind itself never panics on caller
input.

These items are not offered, so code using them fails to build:

- `aead::chacha20_poly1305_openssh`: rind refuses it, having no SSH consumer.
- `rsa::KeyPairComponents` and `rsa::KeyPair::from_components`: building a
  key from components means encoding its secret parts as DER, which
  branches on their leading bytes. Load the key as PKCS#1 or PKCS#8.
- `io`, `test`, `deprecated_test`, and `test_file!`: ring's DER reader and
  test harness, which are no cryptography. `test::rand`'s fixed random
  sources could not work, since rind draws its own randomness.

And these behave differently:

- Where ring takes a `rand::SecureRandom` to generate a key or sign,
  rind draws from the system random source itself, as
  `rand::SystemRandom`, the only `SecureRandom`, does.
- A `error::KeyRejected`'s `Display` gives rind's reason, not ring's
  name for it, which ring documents as changing between releases.
- rind panics on a CPU missing a feature it requires, and ring's
  signatures have no way to report one, so call `rind::cpu::check()` at
  startup.

License: Apache-2.0 OR ISC OR MIT-0
