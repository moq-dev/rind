//! Counter nonce sequences, as RFC 5116 section 3.2 builds nonces.

use super::{NONCE_LEN, Nonce, NonceSequence};
use crate::error::Unspecified;

macro_rules! counter {
    ($name:ident, $builder:ident, $int:ty, $id_len:literal, $bits:literal) => {
        #[doc = concat!("Nonces of a ", $id_len, "-byte identifier then a big-endian ", $bits, "-bit counter, failing past a limit of nonces.")]
        pub struct $name {
            limit: $int,
            generated: $int,
            identifier: [u8; $id_len],
            counter: $int,
        }

        #[doc = concat!("Builds a [`", stringify!($name), "`], by default from identifier and counter zero, with no limit short of the counter's.")]
        pub struct $builder {
            limit: $int,
            identifier: [u8; $id_len],
            counter: $int,
        }

        impl Default for $builder {
            fn default() -> Self {
                Self::new()
            }
        }

        impl $builder {
            /// Starts a builder with the defaults.
            #[must_use]
            pub fn new() -> Self {
                Self {
                    limit: <$int>::MAX,
                    identifier: [0; $id_len],
                    counter: 0,
                }
            }

            /// Sets the identifier every nonce begins with.
            #[must_use]
            pub fn identifier<T: Into<[u8; $id_len]>>(mut self, identifier: T) -> Self {
                self.identifier = identifier.into();
                self
            }

            /// Sets the counter of the first nonce.
            #[must_use]
            pub fn counter(mut self, counter: $int) -> Self {
                self.counter = counter;
                self
            }

            /// Sets how many nonces the sequence gives.
            #[must_use]
            pub fn limit(mut self, limit: $int) -> Self {
                self.limit = limit;
                self
            }

            /// Builds the sequence.
            #[must_use]
            pub fn build(self) -> $name {
                $name {
                    limit: self.limit,
                    generated: 0,
                    identifier: self.identifier,
                    counter: self.counter,
                }
            }
        }

        impl $name {
            /// The identifier every nonce begins with.
            #[must_use]
            pub fn identifier(&self) -> [u8; $id_len] {
                self.identifier
            }

            /// The counter of the next nonce.
            #[must_use]
            pub fn counter(&self) -> $int {
                self.counter
            }

            /// How many nonces the sequence has given.
            #[must_use]
            pub fn generated(&self) -> $int {
                self.generated
            }

            /// How many nonces the sequence gives.
            #[must_use]
            pub fn limit(&self) -> $int {
                self.limit
            }
        }

        impl NonceSequence for $name {
            fn advance(&mut self) -> Result<Nonce, Unspecified> {
                self.generated = self.generated.checked_add(1).ok_or(Unspecified)?;
                if self.generated > self.limit {
                    return Err(Unspecified);
                }
                let mut nonce = [0u8; NONCE_LEN];
                nonce[..$id_len].copy_from_slice(&self.identifier);
                nonce[$id_len..].copy_from_slice(&self.counter.to_be_bytes());
                self.counter = self.counter.wrapping_add(1);
                Ok(Nonce(nonce))
            }
        }
    };
}

counter!(Counter32, Counter32Builder, u32, 8, 32);
counter!(Counter64, Counter64Builder, u64, 4, 64);
