import 'dart:typed_data';

import 'package:pointycastle/export.dart';

/// No-op padding implementation for [AesPadding.noPadding].
///
/// Data must already be block-aligned before encryption; this padding adds
/// and removes nothing, ensuring interoperability with systems that expect
/// raw unpadded AES output.
class NoPaddingImpl implements Padding {
  @override
  String get algorithmName => 'NoPadding';

  @override
  void init([CipherParameters? params]) {}

  @override
  int addPadding(Uint8List data, int offset) => 0;

  @override
  int padCount(Uint8List data) => 0;

  // Required by the Padding interface but never invoked by PaddedBlockCipherImpl,
  // which uses addPadding/padCount instead. Throws loudly if some future
  // PointyCastle release starts calling it.
  @override
  Uint8List process(bool pad, Uint8List data) =>
      throw UnsupportedError('NoPaddingImpl.process is not used by Fortis.');
}

/// Custom zero-byte padding implementation.
///
/// ⚠️ Ambiguous if data legitimately ends with `0x00` bytes. Prefer PKCS#7.
class ZeroBytePaddingImpl implements Padding {
  @override
  String get algorithmName => 'ZeroBytePadding';

  @override
  void init([CipherParameters? params]) {}

  @override
  int addPadding(Uint8List data, int offset) {
    final count = data.length - offset;

    for (var i = offset; i < data.length; i++) {
      data[i] = 0;
    }

    return count;
  }

  @override
  int padCount(Uint8List data) {
    var i = data.length - 1;

    while (i >= 0 && data[i] == 0) {
      i--;
    }

    return data.length - 1 - i;
  }

  // Required by the Padding interface but never invoked by PaddedBlockCipherImpl,
  // which uses addPadding/padCount instead. Throws loudly if some future
  // PointyCastle release starts calling it.
  @override
  Uint8List process(bool pad, Uint8List data) => throw UnsupportedError(
    'ZeroBytePaddingImpl.process is not used by Fortis.',
  );
}
