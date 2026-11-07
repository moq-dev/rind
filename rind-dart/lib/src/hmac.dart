// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

part of 'bindings.dart';

/// An HMAC algorithm.
final class HmacAlgorithm {
  const HmacAlgorithm._(this._id, this.tagLength, this._name);

  // Shared with HKDF and PBKDF2.
  final int _id;
  final String _name;

  /// The length of a tag, in bytes.
  final int tagLength;

  /// HMAC-SHA256.
  static const sha256 = HmacAlgorithm._(0, 32, 'HMAC-SHA256');

  /// HMAC-SHA384.
  static const sha384 = HmacAlgorithm._(1, 48, 'HMAC-SHA384');

  /// HMAC-SHA512.
  static const sha512 = HmacAlgorithm._(2, 64, 'HMAC-SHA512');

  @override
  String toString() => _name;
}

/// HMAC-SHA1, which only legacy protocols should use.
const hmacSha1 = HmacAlgorithm._(100, 20, 'HMAC-SHA1');

/// An HMAC key, whose keyed hash states are computed once.
final class HmacKey extends _Handle {
  /// Keys [algorithm] with [key], which may be any length.
  HmacKey(this.algorithm, Uint8List key)
    : super(
        _newHandle(
          (out) => _hmacKeyNew(algorithm._id, key.address, key.length, out),
        ),
        _hmacKeyFinalizer,
      );

  /// The algorithm the key is for.
  final HmacAlgorithm algorithm;

  /// Returns the tag of [data].
  Uint8List sign(Uint8List data) => _output(
    algorithm.tagLength,
    (out) =>
        _hmacSign(_pointer, data.address, data.length, out.address, out.length),
  );

  /// Checks in constant time that [tag] is the tag of [data], throwing
  /// [RindError.badSignature] if not.
  void verify(Uint8List data, Uint8List tag) {
    _check(
      _hmacVerify(_pointer, data.address, data.length, tag.address, tag.length),
    );
  }
}

/// An HMAC of a message given in parts.
final class HmacContext extends _Handle {
  /// Starts a message under [key].
  HmacContext(HmacKey key)
    : _tagLength = key.algorithm.tagLength,
      super(
        _newHandle((out) => _hmacContextNew(key._pointer, out)),
        _hmacContextFinalizer,
      );

  final int _tagLength;
  bool _signed = false;

  /// Adds [data] to the message.
  void update(Uint8List data) {
    _live();
    _check(_hmacContextUpdate(_pointer, data.address, data.length));
  }

  /// Returns the message's tag. The context is spent after.
  Uint8List sign() {
    _live();
    _signed = true;
    _hmacContextFinalizer.detach(this);
    return _output(
      _tagLength,
      (out) => _hmacContextSign(_pointer, out.address, out.length),
    );
  }

  void _live() {
    if (_signed) throw StateError('HmacContext already signed');
  }
}
