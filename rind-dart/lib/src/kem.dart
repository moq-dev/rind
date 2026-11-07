// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

part of 'bindings.dart';

/// A key encapsulation mechanism.
enum KemAlgorithm {
  /// ML-KEM-768 (FIPS 203).
  mlKem768(0, 1184, 1088);

  const KemAlgorithm(this._id, this._publicKeyLength, this._ciphertextLength);

  final int _id;
  final int _publicKeyLength;
  final int _ciphertextLength;
}

/// A private key that decapsulates the secrets its [publicKey] encapsulates.
final class DecapsulationKey extends _Handle {
  /// Generates a random key for [algorithm].
  DecapsulationKey.generate(this.algorithm)
    : super(
        _newHandle((out) => _decapsulationKeyGenerate(algorithm._id, out)),
        _decapsulationKeyFinalizer,
      );

  /// The algorithm the key is for.
  final KemAlgorithm algorithm;

  /// The encapsulation key to send to the peer.
  EncapsulationKey get publicKey => EncapsulationKey(
    algorithm,
    _output(
      algorithm._publicKeyLength,
      (out) => _decapsulationKeyPublicKey(_pointer, out.address, out.length),
    ),
  );

  /// Recovers the shared secret from [ciphertext].
  ///
  /// A ciphertext of the wrong length throws [RindError.wrongLength]. Any
  /// other tampering yields an unrelated secret (FIPS 203's implicit
  /// rejection), so the peer learns nothing until the secret is used.
  Uint8List decapsulate(Uint8List ciphertext) => _output(
    32,
    (out) => _decapsulate(
      _pointer,
      ciphertext.address,
      ciphertext.length,
      out.address,
      out.length,
    ),
  );
}

/// A peer's public key, which encapsulates secrets to it.
final class EncapsulationKey extends _Handle {
  /// Parses an encapsulation key for [algorithm].
  EncapsulationKey(this.algorithm, Uint8List bytes)
    : bytes = Uint8List.fromList(bytes),
      super(
        _newHandle(
          (out) => _encapsulationKeyNew(
            algorithm._id,
            bytes.address,
            bytes.length,
            out,
          ),
        ),
        _encapsulationKeyFinalizer,
      );

  /// The algorithm the key is for.
  final KemAlgorithm algorithm;

  /// The key's encoding.
  final Uint8List bytes;

  /// Encapsulates a fresh random secret, returning the ciphertext to send to
  /// the key's holder and the secret.
  ({Uint8List ciphertext, Uint8List sharedSecret}) encapsulate() {
    final ciphertext = Uint8List(algorithm._ciphertextLength);
    final secret = Uint8List(32);
    _check(
      _encapsulate(
        _pointer,
        ciphertext.address,
        ciphertext.length,
        secret.address,
        secret.length,
      ),
    );
    return (ciphertext: ciphertext, sharedSecret: secret);
  }
}
