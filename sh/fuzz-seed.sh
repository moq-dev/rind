#!/usr/bin/env bash
# Seed the `keys` fuzz target's corpus from the test keys: each seed is the
# loader's selector byte (see fuzz/fuzzer/keys.rs) followed by a key.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

corpus=fuzz/corpus/keys
mkdir -p "$corpus"

ecdsa=rind/src/high/ecdsa
rsa=rind/src/high/rsa
asn1=rind/src/high/asn1/testdata
ring=rind-ring/tests/ring

# seed SELECTOR FILE...
seed() {
    local selector=$1
    shift
    for file in "$@"; do
        { printf %b "\\x$(printf %02x "$selector")"; cat "$file"; } >"$corpus/$selector-$(basename "$file")"
    done
}

seed 0 "$ecdsa/secp256r1.pkcs8.der" "$asn1/nistp256-p8.bin"
seed 1 "$ecdsa/secp384r1.pkcs8.der"
seed 2 "$ecdsa/secp521r1.pkcs8.der"
seed 3 "$ecdsa"/secp256r1*.der "$asn1/nistp256-sec1.bin"
seed 4 "$ecdsa/secp384r1.der"
seed 5 "$ecdsa/secp521r1.der"
seed 9 "$ring/ecdsa_test_public_key_p256.der" "$asn1/spki-ec-nistp256.bin"
seed 12 "$rsa"/*.pkcs8.der
seed 13 "$rsa"/rsa{2048,2048-q-above-p,3072,4096,6144,8192}.der "$asn1/rsaprivatekey-1k.bin" \
    "$ring/signature_rsa_example_private_key.der"
for selector in 14 15 16; do
    seed "$selector" "$rsa"/*.pub.der "$asn1/rsapublickey-1k.bin" "$asn1/spki-rsa-2k.bin" \
        "$ring/rsa_test_public_key_2048.der"
done
seed 20 "$asn1"/ed25519-p8v*.bin
seed 22 "$ring/ed25519_test_public_key.der"
# An all-zero ML-KEM-768 encapsulation key passes the modulus check.
{ printf '\x17'; head -c 1184 /dev/zero; } >"$corpus/23-zero"
