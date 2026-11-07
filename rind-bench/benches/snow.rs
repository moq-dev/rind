//! snow's transport messages over each resolver, sealed by one peer and
//! opened by the other, so each row is what both peers pay together.

mod criterion;
use criterion::{Criterion, SIZES, Throughput, criterion_group, criterion_main};
use snow::resolvers::{BoxedCryptoResolver, DefaultResolver, FallbackResolver, RingResolver};
use snow::{Builder, TransportState};

fn resolver(name: &str) -> BoxedCryptoResolver {
    match name {
        "rustcrypto" => Box::new(DefaultResolver),
        // ring has no X25519 for snow, which the handshake alone uses.
        "ring" => Box::new(FallbackResolver::new(
            Box::new(RingResolver),
            Box::new(DefaultResolver),
        )),
        _ => rind_snow::resolver().unwrap(),
    }
}

/// Runs an NN handshake for `protocol` with both peers on `name`'s resolver.
fn session(protocol: &str, name: &str) -> (TransportState, TransportState) {
    let mut initiator = Builder::with_resolver(protocol.parse().unwrap(), resolver(name))
        .build_initiator()
        .unwrap();
    let mut responder = Builder::with_resolver(protocol.parse().unwrap(), resolver(name))
        .build_responder()
        .unwrap();
    let (mut message, mut payload) = ([0u8; 128], [0u8; 128]);
    let len = initiator.write_message(&[], &mut message).unwrap();
    responder
        .read_message(&message[..len], &mut payload)
        .unwrap();
    let len = responder.write_message(&[], &mut message).unwrap();
    initiator
        .read_message(&message[..len], &mut payload)
        .unwrap();
    (
        initiator.into_transport_mode().unwrap(),
        responder.into_transport_mode().unwrap(),
    )
}

fn transport(c: &mut Criterion) {
    for cipher in ["ChaChaPoly", "AESGCM"] {
        let protocol = format!("Noise_NN_25519_{cipher}_SHA256");
        let mut group = c.benchmark_group(format!("snow-transport/{cipher}"));
        for (size, label) in SIZES {
            group.throughput(Throughput::Bytes(size as u64));
            for name in ["rind", "ring", "rustcrypto"] {
                let (mut sender, mut receiver) = session(&protocol, name);
                let payload = vec![0x42u8; size];
                let mut message = vec![0u8; size + 16];
                let mut opened = vec![0u8; size];
                group.bench_function(format!("{label}/{name}"), |b| {
                    b.iter(|| {
                        let len = sender.write_message(&payload, &mut message).unwrap();
                        receiver.read_message(&message[..len], &mut opened).unwrap()
                    })
                });
            }
        }
        group.finish();
    }
}

criterion_group!(benches, transport);
criterion_main!(benches);
