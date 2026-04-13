import 'dart:typed_data';

import 'package:pointycastle/export.dart';

import '../aes/aes_key.dart';
import '../../exceptions/fortis_config_exception.dart';
import '../../exceptions/fortis_key_exception.dart';
import 'ecdh_private_key.dart';
import 'ecdh_public_key.dart';

/// Performs ECDH key agreement and key derivation.
///
/// Use [deriveKey] to produce a [FortisAesKey] directly (recommended),
/// or [deriveSharedSecret] to get the raw shared secret bytes.
///
/// For deriving an AES key from an externally-obtained shared secret,
/// use the static [hkdfDeriveKey] method.
///
/// ```dart
/// final derivation = Fortis.ecdh()
///     .curve(EcdhCurve.p256)
///     .keyDerivation(myPrivateKey);
///
/// // Derive an AES key directly
/// final aesKey = derivation.deriveKey(theirPublicKey);
///
/// // Or get the raw shared secret
/// final secret = derivation.deriveSharedSecret(theirPublicKey);
/// ```
class EcdhKeyDerivation {
  final FortisEcdhPrivateKey _privateKey;
  final int _aesKeySize;

  /// Creates an [EcdhKeyDerivation] with the given [privateKey] and optional
  /// [aesKeySize] (in bits, defaults to 256).
  EcdhKeyDerivation({
    required FortisEcdhPrivateKey privateKey,
    int aesKeySize = 256,
  }) : _privateKey = privateKey,
       _aesKeySize = aesKeySize;

  /// Computes the raw ECDH shared secret with the given [publicKey].
  ///
  /// Returns the x-coordinate of the shared point as a byte array,
  /// left-padded to the curve's field size.
  ///
  /// Throws [FortisKeyException] if the keys use different curves.
  Uint8List deriveSharedSecret(FortisEcdhPublicKey publicKey) {
    if (_privateKey.curve != publicKey.curve) {
      throw FortisKeyException(
        'ECDH keys must use the same curve. '
        'Private key uses ${_privateKey.curve}, '
        'but public key uses ${publicKey.curve}.',
      );
    }

    final agreement = ECDHBasicAgreement()..init(_privateKey.key);
    final sharedSecretInt = agreement.calculateAgreement(publicKey.key);

    return _padToFieldSize(
      _encodeBigIntAsUnsigned(sharedSecretInt),
      _privateKey.curve.fieldSizeBytes,
    );
  }

  /// Derives a [FortisAesKey] from the ECDH shared secret with [publicKey].
  ///
  /// Uses HKDF (RFC 5869) with SHA-256 to derive an AES key of the
  /// configured size. Optional [salt] and [info] parameters control the
  /// HKDF derivation.
  ///
  /// Throws [FortisKeyException] if the keys use different curves.
  FortisAesKey deriveKey(
    FortisEcdhPublicKey publicKey, {
    Uint8List? salt,
    Uint8List? info,
  }) {
    final sharedSecret = deriveSharedSecret(publicKey);
    return hkdfDeriveKey(
      sharedSecret,
      aesKeySize: _aesKeySize,
      salt: salt,
      info: info,
    );
  }

  /// Derives a [FortisAesKey] from an arbitrary shared secret using HKDF.
  ///
  /// This is a static utility for when you already have a shared secret
  /// (e.g., from [deriveSharedSecret]) and want to derive an AES key.
  ///
  /// [aesKeySize] must be 128, 192, or 256 bits. Defaults to 256.
  ///
  /// Throws [FortisConfigException] if [aesKeySize] is invalid.
  static FortisAesKey hkdfDeriveKey(
    Uint8List sharedSecret, {
    int aesKeySize = 256,
    Uint8List? salt,
    Uint8List? info,
  }) {
    _validateAesKeySize(aesKeySize);

    final keyLengthBytes = aesKeySize ~/ 8;
    final hkdf = HKDFKeyDerivator(SHA256Digest());
    hkdf.init(HkdfParameters(sharedSecret, keyLengthBytes, salt, info));

    final output = Uint8List(keyLengthBytes);
    hkdf.deriveKey(null, 0, output, 0);

    return FortisAesKey.fromTrustedBytes(output);
  }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

void _validateAesKeySize(int size) {
  if (size != 128 && size != 192 && size != 256) {
    throw FortisConfigException(
      'aesKeySize must be 128, 192, or 256 bits, got $size.',
    );
  }
}

/// Left-pads [bytes] with zeros to exactly [fieldSize] bytes.
Uint8List _padToFieldSize(Uint8List bytes, int fieldSize) {
  if (bytes.length >= fieldSize) return bytes;
  final padded = Uint8List(fieldSize);
  padded.setRange(fieldSize - bytes.length, fieldSize, bytes);
  return padded;
}

/// Encodes a non-negative [BigInt] as an unsigned big-endian byte array.
Uint8List _encodeBigIntAsUnsigned(BigInt value) {
  final hexStr = value.toRadixString(16);
  final padded = hexStr.length.isOdd ? '0$hexStr' : hexStr;
  final bytes = Uint8List(padded.length ~/ 2);
  for (var i = 0; i < bytes.length; i++) {
    bytes[i] = int.parse(padded.substring(i * 2, i * 2 + 2), radix: 16);
  }
  return bytes;
}
