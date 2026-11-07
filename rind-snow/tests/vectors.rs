//! Runs cacophony's Noise test vectors through snow on rind's resolver.
//!
//! `vectors/cacophony.json` holds the vectors from
//! <https://github.com/haskell-cryptography/cacophony> (Unlicense) at
//! 8ee9d41e34a1a596cfa3ab12aa4069ff87dc1247, kept to rind's four suites and to
//! patterns that between them use every token, a one-way handshake, and PSKs:
//! N, X, NN, NK, XX, IK, KK, NNpsk0, XXpsk3, and IKpsk2.

use serde::Deserialize;
use snow::{Builder, HandshakeState};

#[derive(Deserialize)]
struct Vectors {
    vectors: Vec<Vector>,
}

#[derive(Deserialize)]
struct Vector {
    protocol_name: String,
    init_prologue: String,
    init_psks: Option<Vec<String>>,
    init_static: Option<String>,
    init_ephemeral: String,
    init_remote_static: Option<String>,
    resp_prologue: String,
    resp_psks: Option<Vec<String>>,
    resp_static: Option<String>,
    resp_ephemeral: Option<String>,
    resp_remote_static: Option<String>,
    handshake_hash: String,
    messages: Vec<Message>,
}

#[derive(Deserialize)]
struct Message {
    payload: String,
    ciphertext: String,
}

fn bytes(hex: &str) -> Vec<u8> {
    hex::decode(hex).unwrap()
}

struct Side<'a> {
    prologue: &'a str,
    psks: &'a Option<Vec<String>>,
    local_static: &'a Option<String>,
    ephemeral: Option<&'a String>,
    remote_static: &'a Option<String>,
}

fn build(protocol: &str, side: Side<'_>, initiator: bool) -> HandshakeState {
    let params: snow::params::NoiseParams = protocol.parse().unwrap();
    let psks: Vec<[u8; 32]> = side
        .psks
        .iter()
        .flatten()
        .map(|psk| bytes(psk).try_into().unwrap())
        .collect();
    let prologue = bytes(side.prologue);
    let local_static = side.local_static.as_deref().map(bytes);
    let ephemeral = side.ephemeral.map(|e| bytes(e));
    let remote_static = side.remote_static.as_deref().map(bytes);

    let mut builder = Builder::with_resolver(params.clone(), rind_snow::resolver().unwrap())
        .prologue(&prologue)
        .unwrap();
    let positions = params
        .handshake
        .modifiers
        .list
        .iter()
        .filter_map(|m| match m {
            snow::params::HandshakeModifier::Psk(n) => Some(*n),
            _ => None,
        });
    for (position, psk) in positions.zip(&psks) {
        builder = builder.psk(position, psk).unwrap();
    }
    if let Some(key) = &local_static {
        builder = builder.local_private_key(key).unwrap();
    }
    if let Some(key) = &remote_static {
        builder = builder.remote_public_key(key).unwrap();
    }
    if let Some(key) = &ephemeral {
        builder = builder.fixed_ephemeral_key_for_testing_only(key);
    }
    if initiator {
        builder.build_initiator().unwrap()
    } else {
        builder.build_responder().unwrap()
    }
}

#[test]
fn cacophony() {
    let vectors: Vectors = serde_json::from_str(include_str!("vectors/cacophony.json")).unwrap();
    assert_eq!(vectors.vectors.len(), 40);

    for vector in &vectors.vectors {
        let name = &vector.protocol_name;
        let mut init = build(
            name,
            Side {
                prologue: &vector.init_prologue,
                psks: &vector.init_psks,
                local_static: &vector.init_static,
                ephemeral: Some(&vector.init_ephemeral),
                remote_static: &vector.init_remote_static,
            },
            true,
        );
        let mut resp = build(
            name,
            Side {
                prologue: &vector.resp_prologue,
                psks: &vector.resp_psks,
                local_static: &vector.resp_static,
                ephemeral: vector.resp_ephemeral.as_ref(),
                remote_static: &vector.resp_remote_static,
            },
            false,
        );

        let mut sent = vec![0u8; 65535];
        let mut received = vec![0u8; 65535];
        let mut messages = vector.messages.iter().enumerate();
        while !init.is_handshake_finished() {
            let (i, message) = messages.next().unwrap();
            let (writer, reader) = if i % 2 == 0 {
                (&mut init, &mut resp)
            } else {
                (&mut resp, &mut init)
            };
            let payload = bytes(&message.payload);
            let len = writer.write_message(&payload, &mut sent).unwrap();
            assert_eq!(
                hex::encode(&sent[..len]),
                message.ciphertext,
                "{name} message {i}"
            );
            let len = reader.read_message(&sent[..len], &mut received).unwrap();
            assert_eq!(received[..len], payload, "{name} message {i}");
        }
        assert_eq!(
            hex::encode(init.get_handshake_hash()),
            vector.handshake_hash,
            "{name}"
        );
        assert_eq!(
            hex::encode(resp.get_handshake_hash()),
            vector.handshake_hash,
            "{name}"
        );

        let params: snow::params::NoiseParams = name.parse().unwrap();
        let oneway = params.handshake.pattern.is_oneway();
        let mut init = init.into_transport_mode().unwrap();
        let mut resp = resp.into_transport_mode().unwrap();
        for (i, message) in messages {
            let (writer, reader) = if oneway || i % 2 == 0 {
                (&mut init, &mut resp)
            } else {
                (&mut resp, &mut init)
            };
            let payload = bytes(&message.payload);
            let len = writer.write_message(&payload, &mut sent).unwrap();
            assert_eq!(
                hex::encode(&sent[..len]),
                message.ciphertext,
                "{name} message {i}"
            );
            let len = reader.read_message(&sent[..len], &mut received).unwrap();
            assert_eq!(received[..len], payload, "{name} message {i}");
        }
    }
}
