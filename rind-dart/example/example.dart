// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

import 'dart:convert';
import 'dart:typed_data';

import 'package:rind/rind.dart';

void main() {
  final key = Uint8List(32);
  fillRandom(key);

  final aead = AeadKey(AeadAlgorithm.chacha20Poly1305, key);
  // Never reuse a nonce with one key; RandomizedNonceKey picks its own.
  final nonce = Nonce.assumeUniqueForKey(Uint8List(12));
  final sealed = aead.seal(nonce, utf8.encode('hello'));
  print(utf8.decode(aead.open(nonce, sealed)));

  final pair = EcdsaKeyPair.generate(EcdsaSigningAlgorithm.p256Sha256Asn1);
  final signature = pair.sign(utf8.encode('hello'));
  final verifier = PublicKey(
    VerificationAlgorithm.ecdsaP256Sha256Asn1,
    pair.publicKey.bytes,
  );
  verifier.verify(utf8.encode('hello'), signature);
}
