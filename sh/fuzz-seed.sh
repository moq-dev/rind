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

# pkcs8_v2 SELECTOR FILE FIELD: the PKCS#8 v1 FILE as version 2, ending in
# the public key FIELD, a file of its DER, or none if FIELD is empty.
pkcs8_v2() {
    local selector=$1 file=$2 field=$3 header len
    # A long-form length of one or two bytes follows the tag.
    header=$((2 + 0x$(od -An -tx1 -j1 -N1 "$file" | tr -d ' ') - 0x80))
    len=$(($(wc -c <"$file") - header + $(wc -c <"$field")))
    {
        printf %b "\\x$(printf %02x "$selector")\\x30"
        if ((len < 0x100)); then
            printf %b "\\x81\\x$(printf %02x "$len")"
        else
            printf %b "\\x82\\x$(printf %02x $((len >> 8)))\\x$(printf %02x $((len & 0xff)))"
        fi
        printf '\x02\x01\x01'
        tail -c +$((header + 4)) "$file"
        cat "$field"
    } >"$corpus/$selector-v2-$(basename "$file")"
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

# Version 2 documents, which the ECDSA and RSA loaders refuse: one with its
# public key, one with an empty one, and two without, which aws-lc-rs takes.
field=$(mktemp)
trap 'rm -f "$field"' EXIT
{ printf '\x81\x42\x00'; tail -c 65 "$ecdsa/secp256r1.der"; } >"$field"
pkcs8_v2 0 "$ecdsa/secp256r1.pkcs8.der" "$field"
printf '\x81\x01\x00' >"$field"
pkcs8_v2 12 "$rsa/rsa2048.pkcs8.der" "$field"
: >"$field"
pkcs8_v2 2 "$ecdsa/secp521r1.pkcs8.der" "$field"
pkcs8_v2 12 "$rsa/rsa3072.pkcs8.der" "$field"
