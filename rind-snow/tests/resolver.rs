//! Checks rind's resolver against snow's default, RustCrypto's: handshakes and
//! transport between the two, each primitive differentially, and malformed
//! input.

use snow::params::{CipherChoice, DHChoice, HashChoice, NoiseParams};
use snow::resolvers::{BoxedCryptoResolver, CryptoResolver, DefaultResolver, FallbackResolver};
use snow::{Builder, Error, HandshakeState, TransportState};

const SUITES: [&str; 4] = [
    "25519_ChaChaPoly_SHA256",
    "25519_ChaChaPoly_SHA512",
    "25519_AESGCM_SHA256",
    "25519_AESGCM_SHA512",
];

fn rind() -> BoxedCryptoResolver {
    rind_snow::resolver().unwrap()
}

fn random(len: usize) -> Vec<u8> {
    let mut out = vec![0u8; len];
    rind::rand::fill(&mut out).unwrap();
    out
}

/// Runs `initiator` and `responder` to the end of their handshake.
fn handshake(
    mut initiator: HandshakeState,
    mut responder: HandshakeState,
) -> Result<(TransportState, TransportState), Error> {
    let mut message = vec![0u8; 65535];
    let mut payload = vec![0u8; 65535];
    let (mut writer, mut reader) = (&mut initiator, &mut responder);
    while !(writer.is_handshake_finished() && reader.is_handshake_finished()) {
        let len = writer.write_message(b"handshake payload", &mut message)?;
        let len = reader.read_message(&message[..len], &mut payload)?;
        assert_eq!(&payload[..len], b"handshake payload");
        (writer, reader) = (reader, writer);
    }
    Ok((
        initiator.into_transport_mode()?,
        responder.into_transport_mode()?,
    ))
}

/// Sends messages of each size both ways, rekeys both directions, and sends
/// them again.
fn transport(a: &mut TransportState, b: &mut TransportState) {
    for _ in 0..2 {
        send(a, b);
        send(b, a);
        a.rekey_outgoing();
        b.rekey_incoming();
        b.rekey_outgoing();
        a.rekey_incoming();
    }
}

fn send(writer: &mut TransportState, reader: &mut TransportState) {
    let mut message = vec![0u8; 65535];
    let mut received = vec![0u8; 65535];
    for len in [0, 1, 15, 16, 17, 1000, 65535 - 16] {
        let payload = random(len);
        let len = writer.write_message(&payload, &mut message).unwrap();
        let len = reader.read_message(&message[..len], &mut received).unwrap();
        assert_eq!(received[..len], payload);
    }
}

fn builder<'a>(protocol: &str, resolver: BoxedCryptoResolver) -> Builder<'a> {
    let params: NoiseParams = protocol.parse().unwrap();
    Builder::with_resolver(params, resolver)
}

/// A static key pair for `protocol`, from snow's default resolver.
fn keypair(protocol: &str) -> snow::Keypair {
    builder(protocol, Box::new(DefaultResolver))
        .generate_keypair()
        .unwrap()
}

#[test]
fn interop() {
    for suite in SUITES {
        // KK sends no static keys, IK one, and XX both.
        for pattern in ["XX", "IK", "KK", "NNpsk0"] {
            let protocol = format!("Noise_{pattern}_{suite}");
            let initiator_key = builder(&protocol, rind()).generate_keypair().unwrap();
            let responder_key = keypair(&protocol);
            let psk: [u8; 32] = random(32).try_into().unwrap();

            for rind_initiates in [true, false] {
                let (initiator_resolver, responder_resolver): (
                    BoxedCryptoResolver,
                    BoxedCryptoResolver,
                ) = if rind_initiates {
                    (rind(), Box::new(DefaultResolver))
                } else {
                    (Box::new(DefaultResolver), rind())
                };

                let mut initiator = builder(&protocol, initiator_resolver);
                let mut responder = builder(&protocol, responder_resolver);
                if pattern == "NNpsk0" {
                    initiator = initiator.psk(0, &psk).unwrap();
                    responder = responder.psk(0, &psk).unwrap();
                } else {
                    initiator = initiator.local_private_key(&initiator_key.private).unwrap();
                    responder = responder.local_private_key(&responder_key.private).unwrap();
                }
                if pattern == "IK" || pattern == "KK" {
                    initiator = initiator.remote_public_key(&responder_key.public).unwrap();
                }
                if pattern == "KK" {
                    responder = responder.remote_public_key(&initiator_key.public).unwrap();
                }

                let (mut initiator, mut responder) = handshake(
                    initiator.build_initiator().unwrap(),
                    responder.build_responder().unwrap(),
                )
                .unwrap();
                if pattern == "XX" {
                    assert_eq!(
                        responder.get_remote_static(),
                        Some(&initiator_key.public[..]),
                        "{protocol}"
                    );
                }
                transport(&mut initiator, &mut responder);
            }
        }
    }
}

#[test]
fn ciphers_match_default() {
    for choice in [CipherChoice::ChaChaPoly, CipherChoice::AESGCM] {
        let mut ours = rind().resolve_cipher(&choice).unwrap();
        let mut theirs = DefaultResolver.resolve_cipher(&choice).unwrap();
        assert_eq!(ours.name(), theirs.name());

        for len in [0, 1, 63, 64, 65, 1000, 4096] {
            let key: [u8; 32] = random(32).try_into().unwrap();
            ours.set(&key);
            theirs.set(&key);
            let nonce = u64::from_le_bytes(random(8).try_into().unwrap());
            let aad = random(len % 77);
            let plaintext = random(len);

            let mut expected = vec![0u8; len + 16];
            assert_eq!(
                theirs.encrypt(nonce, &aad, &plaintext, &mut expected),
                len + 16
            );
            let mut sealed = vec![0u8; len + 16];
            assert_eq!(ours.encrypt(nonce, &aad, &plaintext, &mut sealed), len + 16);
            assert_eq!(sealed, expected, "{choice:?} {len}");

            let mut opened = vec![0u8; len];
            assert_eq!(ours.decrypt(nonce, &aad, &sealed, &mut opened), Ok(len));
            assert_eq!(opened, plaintext);

            // Any flipped bit, or another nonce or AAD, fails to open.
            for at in [0, sealed.len() / 2, sealed.len() - 1] {
                let mut tampered = sealed.clone();
                tampered[at] ^= 1;
                assert_eq!(
                    ours.decrypt(nonce, &aad, &tampered, &mut opened),
                    Err(Error::Decrypt)
                );
            }
            assert_eq!(
                ours.decrypt(nonce ^ 1, &aad, &sealed, &mut opened),
                Err(Error::Decrypt)
            );
            assert_eq!(
                ours.decrypt(nonce, b"other", &sealed, &mut opened),
                Err(Error::Decrypt)
            );
        }

        // Rekeying derives the same key as snow's own rekey.
        let key: [u8; 32] = random(32).try_into().unwrap();
        ours.set(&key);
        theirs.set(&key);
        ours.rekey();
        theirs.rekey();
        let (mut a, mut b) = ([0u8; 16], [0u8; 16]);
        ours.encrypt(0, &[], &[], &mut a);
        theirs.encrypt(0, &[], &[], &mut b);
        assert_eq!(a, b);
    }
}

#[test]
fn cipher_refuses_malformed_input() {
    for choice in [CipherChoice::ChaChaPoly, CipherChoice::AESGCM] {
        let mut cipher = rind().resolve_cipher(&choice).unwrap();
        let mut out = [0u8; 64];
        // Before a key is set, sealing uses a random key, so another cipher
        // fresh from the resolver cannot open it, and opening fails.
        let mut unkeyed = [0u8; 16];
        assert_eq!(cipher.encrypt(0, &[], &[], &mut unkeyed), 16);
        let other = rind().resolve_cipher(&choice).unwrap();
        assert_eq!(
            other.decrypt(0, &[], &unkeyed, &mut out),
            Err(Error::Decrypt)
        );
        assert_eq!(
            cipher.decrypt(0, &[], &[0; 32], &mut out),
            Err(Error::Decrypt)
        );

        cipher.set(&[7; 32]);
        let mut sealed = [0u8; 32 + 16];
        cipher.encrypt(0, &[], &[1; 32], &mut sealed);
        // Shorter than a tag.
        assert_eq!(
            cipher.decrypt(0, &[], &sealed[..15], &mut out),
            Err(Error::Decrypt)
        );
        // Too little room for the plaintext.
        assert_eq!(
            cipher.decrypt(0, &[], &sealed, &mut out[..31]),
            Err(Error::Decrypt)
        );
        assert_eq!(cipher.decrypt(0, &[], &sealed, &mut out), Ok(32));
    }
}

#[test]
fn hashes_match_default() {
    for choice in [HashChoice::SHA256, HashChoice::SHA512] {
        let mut ours = rind().resolve_hash(&choice).unwrap();
        let mut theirs = DefaultResolver.resolve_hash(&choice).unwrap();
        assert_eq!(ours.name(), theirs.name());
        assert_eq!(ours.block_len(), theirs.block_len());
        assert_eq!(ours.hash_len(), theirs.hash_len());
        let hash_len = ours.hash_len();

        for len in [0, 1, 111, 112, 128, 1000] {
            let data = random(len);
            let (mut a, mut b) = ([0u8; 64], [0u8; 64]);
            // `result` starts a new hash, so the second matches the first.
            for _ in 0..2 {
                ours.input(&data);
                theirs.input(&data);
                ours.result(&mut a);
                theirs.result(&mut b);
                assert_eq!(a[..hash_len], b[..hash_len], "{choice:?} {len}");
            }
            ours.input(b"discarded");
            ours.reset();
            ours.input(&data);
            ours.result(&mut a);
            assert_eq!(a[..hash_len], b[..hash_len]);

            let key = random(hash_len);
            ours.hmac(&key, &data, &mut a);
            theirs.hmac(&key, &data, &mut b);
            assert_eq!(a[..hash_len], b[..hash_len]);

            let mut ours_out = [[0u8; 64]; 3];
            let mut theirs_out = [[0u8; 64]; 3];
            let [o1, o2, o3] = &mut ours_out;
            ours.hkdf(&key, &data, 3, o1, o2, o3);
            let [t1, t2, t3] = &mut theirs_out;
            theirs.hkdf(&key, &data, 3, t1, t2, t3);
            assert_eq!(ours_out, theirs_out);
        }
    }
}

#[test]
fn x25519_matches_default() {
    let mut rng = DefaultResolver.resolve_rng().unwrap();
    for _ in 0..16 {
        let mut ours = rind().resolve_dh(&DHChoice::Curve25519).unwrap();
        let mut theirs = DefaultResolver.resolve_dh(&DHChoice::Curve25519).unwrap();
        assert_eq!(ours.name(), theirs.name());

        ours.generate(&mut *rng).unwrap();
        assert_eq!(ours.privkey().len(), ours.priv_len());
        theirs.set(ours.privkey());
        assert_eq!(ours.pubkey(), theirs.pubkey());
        assert_eq!(ours.pubkey().len(), ours.pub_len());

        let mut peer = DefaultResolver.resolve_dh(&DHChoice::Curve25519).unwrap();
        peer.generate(&mut *rng).unwrap();
        // snow passes its remote key buffer whole, longer than the key.
        let mut remote = [0u8; 56];
        remote[..32].copy_from_slice(peer.pubkey());
        let (mut a, mut b) = ([0u8; 56], [0u8; 56]);
        ours.dh(&remote, &mut a).unwrap();
        theirs.dh(&remote, &mut b).unwrap();
        assert_eq!(a, b);
    }
}

#[test]
fn x25519_refuses_malformed_input() {
    let mut dh = rind().resolve_dh(&DHChoice::Curve25519).unwrap();
    let mut out = [0u8; 32];
    let peer = [9u8; 32];
    // Before a key is set.
    assert_eq!(dh.dh(&peer, &mut out), Err(Error::Dh));
    assert!(dh.pubkey().is_empty());

    dh.set(&[1; 32]);
    assert_eq!(dh.privkey(), [1; 32]);
    dh.dh(&peer, &mut out).unwrap();
    // A key too short, a small-order point, or too little room for the output.
    assert_eq!(dh.dh(&peer[..31], &mut out), Err(Error::Dh));
    assert_eq!(dh.dh(&[0; 32], &mut out), Err(Error::Dh));
    assert_eq!(dh.dh(&peer, &mut out[..31]), Err(Error::Dh));

    // A private key of the wrong length leaves no key.
    for len in [0, 31, 33] {
        dh.set(&vec![1; len]);
        assert!(dh.pubkey().is_empty() && dh.privkey().is_empty());
        assert_eq!(dh.dh(&peer, &mut out), Err(Error::Dh));
    }
}

#[test]
fn wrong_length_static_key_fails_handshake() {
    let protocol = "Noise_XX_25519_ChaChaPoly_SHA256";
    let responder_key = keypair(protocol);
    for len in [31, 33] {
        let initiator = builder(protocol, rind())
            .local_private_key(&vec![1; len])
            .unwrap()
            .build_initiator()
            .unwrap();
        let responder = builder(protocol, Box::new(DefaultResolver))
            .local_private_key(&responder_key.private)
            .unwrap()
            .build_responder()
            .unwrap();
        assert!(matches!(handshake(initiator, responder), Err(Error::Dh)));
    }
}

#[test]
fn refuses_what_it_lacks() {
    let resolver = rind();
    assert!(resolver.resolve_dh(&DHChoice::Curve448).is_none());
    assert!(resolver.resolve_hash(&HashChoice::Blake2s).is_none());
    assert!(resolver.resolve_hash(&HashChoice::Blake2b).is_none());
    assert!(
        builder("Noise_NN_25519_ChaChaPoly_BLAKE2s", rind())
            .build_initiator()
            .is_err()
    );

    // Behind a fallback, the fallback fills the gap.
    let protocol = "Noise_NN_25519_ChaChaPoly_BLAKE2s";
    let fallback = || Box::new(FallbackResolver::new(rind(), Box::new(DefaultResolver)));
    let (mut initiator, mut responder) = handshake(
        builder(protocol, fallback()).build_initiator().unwrap(),
        builder(protocol, Box::new(DefaultResolver))
            .build_responder()
            .unwrap(),
    )
    .unwrap();
    transport(&mut initiator, &mut responder);
}
