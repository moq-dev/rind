<h1 align="center">rind-snow</h1>
<img width="40%" align="right" src="https://raw.githubusercontent.com/moq-dev/rind/main/admin/logo.png">

[![Latest release](https://img.shields.io/crates/v/rind-snow)](https://crates.io/crates/rind-snow)
[![Documentation](https://img.shields.io/docsrs/rind-snow)](https://docs.rs/rind-snow/)

This crate provides a `CryptoResolver` for [snow](https://github.com/mcginty/snow), the Noise Protocol Framework, backed by [rind](https://github.com/moq-dev/rind/), a fork of [Graviola](https://github.com/ctz/graviola/).

Hand it to each builder:

```rust
// Refuses a CPU missing a feature rind requires.
let initiator = snow::Builder::with_resolver(params, rind_snow::resolver()?)
    .local_private_key(&key.private)?
    .build_initiator()?;
```

It resolves X25519, ChaCha20-Poly1305, AES-256-GCM, SHA-256, SHA-512, and the system random source.
A protocol naming BLAKE2 or Curve448 fails to build. For BLAKE2, put snow's default resolver behind it (snow 0.10 has no Curve448):

```rust
use snow::resolvers::{DefaultResolver, FallbackResolver};

let resolver = FallbackResolver::new(rind_snow::resolver()?, Box::new(DefaultResolver));
let initiator = snow::Builder::with_resolver(params, Box::new(resolver))
    .local_private_key(&key.private)?
    .build_initiator()?;
```

Build snow with `default-features = false` when nothing needs its default resolver, which compiles RustCrypto's primitives.

rind is young, and Noise is a security-critical handshake: weigh that before deploying it.

License: Apache-2.0 OR ISC OR MIT-0
