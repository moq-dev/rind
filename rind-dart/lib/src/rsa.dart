// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

part of 'bindings.dart';

/// An RSA-OAEP algorithm: its hash, which MGF1 uses too.
final class OaepAlgorithm {
  const OaepAlgorithm._(this._id, this._name);

  final int _id;
  final String _name;

  /// RSA-OAEP with SHA-256.
  static const sha256 = OaepAlgorithm._(0, 'RSA-OAEP-SHA256');

  /// RSA-OAEP with SHA-384.
  static const sha384 = OaepAlgorithm._(1, 'RSA-OAEP-SHA384');

  /// RSA-OAEP with SHA-512.
  static const sha512 = OaepAlgorithm._(2, 'RSA-OAEP-SHA512');

  @override
  String toString() => _name;
}

/// RSA-OAEP with SHA-1, for protocols that still require it.
const oaepSha1 = OaepAlgorithm._(100, 'RSA-OAEP-SHA1');

/// An RSA private key that decrypts RSA-OAEP ciphertexts.
///
/// Generating a key and decrypting take milliseconds to seconds, so run
/// them off the UI isolate, as with `Isolate.run`.
final class RsaDecryptingKey extends _Handle {
  RsaDecryptingKey._(this.algorithm, int source, int size, Uint8List der)
    : super(
        _native(
          der,
          (bytes) => _newHandle(
            (out) => _decryptingKeyNew(
              algorithm._id,
              source,
              size,
              bytes,
              der.length,
              out,
            ),
          ),
        ),
        _decryptingKeyFinalizer,
      );

  /// Generates a random key of [size] for [algorithm].
  RsaDecryptingKey.generate(OaepAlgorithm algorithm, RsaKeySize size)
    : this._(algorithm, 0, size.index, Uint8List(0));

  /// Parses a PKCS#8 private key for [algorithm].
  RsaDecryptingKey.fromPkcs8(OaepAlgorithm algorithm, Uint8List der)
    : this._(algorithm, 1, 0, der);

  /// Parses a PKCS#1 `RSAPrivateKey` for [algorithm].
  RsaDecryptingKey.fromPkcs1(OaepAlgorithm algorithm, Uint8List der)
    : this._(algorithm, 2, 0, der);

  /// The algorithm the key decrypts with.
  final OaepAlgorithm algorithm;

  /// The public key, which encrypts to this key.
  RsaEncryptingKey get publicKey => RsaEncryptingKey._(
    algorithm,
    _newHandle((out) => _decryptingKeyPublicKey(_pointer, out)),
  );

  /// Decrypts [ciphertext] sealed with [label], throwing
  /// [RindError.decryptFailed] if it does not decrypt.
  Uint8List decrypt(Uint8List ciphertext, {Uint8List? label}) {
    label ??= Uint8List(0);
    return _native(ciphertext, (input) {
      return _native(label!, (labelPointer) {
        return _native(Uint8List(_modulusLength), (out) {
          final len = _check(
            _decrypt(
              _pointer,
              input,
              ciphertext.length,
              labelPointer,
              label!.length,
              out,
              _modulusLength,
            ),
          );
          return Uint8List.fromList(out.asTypedList(len));
        });
      });
    });
  }

  Uint8List _export(int what) => _output(
    _exportLength,
    (out) => _decryptingKeyExport(_pointer, what, out.address, out.length),
  );

  /// Encodes the private key as PKCS#8.
  Uint8List toPkcs8() => _export(1);

  /// Encodes the public key as a `SubjectPublicKeyInfo`.
  Uint8List toSpki() => _export(4);
}

/// An RSA public key that encrypts with RSA-OAEP.
final class RsaEncryptingKey extends _Handle {
  RsaEncryptingKey._(this.algorithm, Pointer<Void> _pointer)
    : super(_pointer, _encryptingKeyFinalizer);

  RsaEncryptingKey._parse(
    this.algorithm,
    int source,
    Uint8List bytes, [
    Uint8List? exponent,
  ]) : super(
         _new(algorithm, source, bytes, exponent ?? Uint8List(0)),
         _encryptingKeyFinalizer,
       );

  static Pointer<Void> _new(
    OaepAlgorithm algorithm,
    int source,
    Uint8List bytes,
    Uint8List exponent,
  ) => _newHandle(
    (out) => _encryptingKeyNew(
      algorithm._id,
      source,
      bytes.address,
      bytes.length,
      exponent.address,
      exponent.length,
      out,
    ),
  );

  /// Parses a PKCS#1 `RSAPublicKey` or a `SubjectPublicKeyInfo` for
  /// [algorithm], refusing a modulus below 2048 bits.
  RsaEncryptingKey(OaepAlgorithm algorithm, Uint8List der)
    : this._parse(algorithm, 0, der);

  /// Loads a key for [algorithm] from its big-endian modulus [n] and
  /// exponent [e], as a JWK carries them.
  RsaEncryptingKey.fromComponents(
    OaepAlgorithm algorithm, {
    required Uint8List n,
    required Uint8List e,
  }) : this._parse(algorithm, 2, n, e);

  /// The algorithm the key encrypts with.
  final OaepAlgorithm algorithm;

  /// Encrypts [message] with [label], returning a ciphertext as long as the
  /// modulus, and throwing [RindError.wrongLength] for a message longer
  /// than [maxMessageLength].
  Uint8List encrypt(Uint8List message, {Uint8List? label}) {
    label ??= Uint8List(0);
    return _output(
      _modulusLength,
      (out) => _encrypt(
        _pointer,
        message.address,
        message.length,
        label!.address,
        label.length,
        out.address,
        out.length,
      ),
    );
  }

  /// The longest message the key encrypts, in bytes.
  int get maxMessageLength => _check(_encryptingKeyMaxMessageLen(_pointer));

  /// The key's PKCS#1 `RSAPublicKey` encoding.
  Uint8List get bytes => _export(0);

  /// Encodes the key as a `SubjectPublicKeyInfo`.
  Uint8List toSpki() => _export(1);

  Uint8List _export(int spki) => _output(
    _exportLength,
    (out) => _encryptingKeyExport(_pointer, spki, out.address, out.length),
  );
}
