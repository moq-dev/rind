#[cfg(feature = "__bench_codspeed")]
pub use codspeed_criterion_compat::*;
#[cfg(not(feature = "__bench_codspeed"))]
pub use criterion::*;

/// Message sizes for ciphers and AEADs: a short token, QUIC datagrams at and
/// near the common 1200- and 1350-byte MTUs, and a full TLS record.
#[allow(dead_code)]
pub const SIZES: [(usize, &str); 4] = [
    (32, "32B"),
    (1200, "1200B"),
    (1350, "1350B"),
    (16384, "16KB"),
];

/// [`SIZES`], plus one hash block and a file-sized input, for hashes and MACs.
#[allow(dead_code)]
pub const HASH_SIZES: [(usize, &str); 6] = [
    (32, "32B"),
    (64, "64B"),
    (1200, "1200B"),
    (1350, "1350B"),
    (8192, "8KB"),
    (16384, "16KB"),
];
