//! <h1 align="center">rind-ring</h1>
//! <img width="40%" align="right" src="https://raw.githubusercontent.com/moq-dev/rind/main/admin/picture.png">
//!
//! This crate offers [ring](https://github.com/briansmith/ring) 0.17's API, name for name, backed by [rind](https://github.com/moq-dev/rind/), a fork of [Graviola](https://github.com/ctz/graviola/).
//! A crate on ring swaps it in by renaming its dependency, with no code
//! changes:
//!
//! ```toml
//! [dependencies]
//! ring = { package = "rind-ring", version = "0.1" }
//! ```
//!
//! ring's `alloc`, `std`, and `dev_urandom_fallback` features are accepted
//! and change nothing. The rename reaches only the crate that makes it: Cargo
//! cannot patch a dependency's `ring` with a crate of another name, so a
//! dependency that names ring still builds ring.
//!
//! These items are not offered, so code using them fails to build:
//!
//! - `aead::chacha20_poly1305_openssh`: rind refuses it, having no SSH consumer.
//! - `rsa::KeyPairComponents` and `rsa::KeyPair::from_components`: building a
//!   key from components means encoding its secret parts as DER, which
//!   branches on their leading bytes. Load the key as PKCS#1 or PKCS#8.
//! - `io`, `test`, `deprecated_test`, and `test_file!`: ring's DER reader and
//!   test harness, which are no cryptography. `test::rand`'s fixed random
//!   sources could not work, since rind draws its own randomness.
//!
//! These inputs ring takes are refused with an error:
//!
//! - An RSA public exponent over 32 bits, which ring takes up to 33 bits.
//! - An ECDSA or RSA PKCS#8 document carrying attributes, which rind's parser
//!   refuses. An Ed25519 one loads as in ring, as does one whose public key
//!   has the `[1] EXPLICIT` tag early ring versions wrote.
//!
//! And these behave differently:
//!
//! - `pbkdf2::derive` returns `Result<(), error::Unspecified>`, failing for
//!   an output over (2^32 - 1) hash outputs, where ring returns `()` and
//!   panics. A call that ignores the result draws an `unused_must_use`
//!   warning.
//! - Where ring takes a [`rand::SecureRandom`] to generate a key or sign,
//!   rind draws from the system random source itself, as
//!   [`rand::SystemRandom`], the only `SecureRandom`, does.
//! - A [`error::KeyRejected`]'s `Display` gives rind's reason, not ring's
//!   name for it, which ring documents as changing between releases.
//! - rind panics on a CPU missing a feature it requires, and ring's
//!   signatures have no way to report one, so call `rind::cpu::check()` at
//!   startup.

// ring's API has these shapes, which a drop-in keeps.
#![allow(clippy::len_without_is_empty, clippy::new_without_default)]
#![warn(missing_docs, unreachable_pub)]

use core::fmt;

pub mod aead;
pub mod agreement;
#[doc(hidden)]
#[deprecated(note = "ring deprecates it too; compare with `hmac::verify` or a constant-time crate")]
pub mod deprecated_constant_time;
mod der;
pub mod digest;
pub mod error;
pub mod hkdf;
pub mod hmac;
pub mod pbkdf2;
pub mod pkcs8;
pub mod rand;
pub mod rsa;
pub mod signature;

#[doc(hidden)]
#[allow(deprecated)]
#[deprecated(
    note = "ring deprecates it too; compare with `hmac::verify` or a constant-time crate"
)]
pub use deprecated_constant_time as constant_time;

mod sealed {
    /// Implemented only inside rind-ring.
    pub trait Sealed {}
}

/// Writes bytes as lowercase hex, as ring's `Debug` output does.
fn write_hex(f: &mut fmt::Formatter<'_>, bytes: &[u8]) -> fmt::Result {
    bytes.iter().try_for_each(|byte| write!(f, "{byte:02x}"))
}

/// Debugs as quoted hex.
struct Hex<'a>(&'a [u8]);

impl fmt::Debug for Hex<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("\"")?;
        write_hex(f, self.0)?;
        f.write_str("\"")
    }
}
