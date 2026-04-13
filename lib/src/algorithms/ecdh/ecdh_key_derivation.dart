import 'dart:typed_data';

import 'package:pointycastle/export.dart';

import '../aes/aes_key.dart';
import '../../exceptions/fortis_config_exception.dart';
import '../../exceptions/fortis_key_exception.dart';
import 'ecdh_private_key.dart';
import 'ecdh_public_key.dart';

/// Performs ECDH key agreement and key derivation.
///
/// Use [deriveKey] to produce raw derived bytes via HKDF,
/// or [deriveAesKey] to get a [FortisAesKey] directly.
///
/// For raw shared secret bytes (without HKDF), use [deriveSharedSecret].
///
/// ```dart
/// final derivation = Fortis.ecdh()
///     .curve(EcdhCurve.p256)
///     .keyDerivation(myPrivateKey);
///
/// // Derive raw key bytes
/// final keyBytes = derivation.deriveKey(theirPublicKey);
///
/// // Derive an AES key directly
/// final aesKey = derivation.deriveAesKey(theirPublicKey);
///
/// // Or get the raw shared secret
/// final secret = derivation.deriveSharedSecret(theirPublicKey);
/// ```
class EcdhKeyDerivation {
  final FortisEcdhPrivateKey _privateKey;
  final int _keySize;

  /// Creates an [EcdhKeyDerivation] with the given [privateKey] and optional
  /// [keySize] (in bits, defaults to 256).
  EcdhKeyDerivation({
    required FortisEcdhPrivateKey privateKey,
    int keySize = 256,
  }) : _privateKey = privateKey,
       _keySize = keySize;

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

  /// Derives key bytes from the ECDH shared secret with [publicKey].
  ///
  /// Uses HKDF (RFC 5869) with SHA-256 to derive a key of the
  /// configured size. Optional [salt] and [info] parameters control the
  /// HKDF derivation.
  ///
  /// Throws [FortisKeyException] if the keys use different curves.
  Uint8List deriveKey(
    FortisEcdhPublicKey publicKey, {
    Uint8List? salt,
    Uint8List? info,
  }) {
    final sharedSecret = deriveSharedSecret(publicKey);
    return hkdf(sharedSecret, keySize: _keySize, salt: salt, info: info);
  }

  /// Derives a [FortisAesKey] from the ECDH shared secret with [publicKey].
  ///
  /// Uses HKDF (RFC 5869) with SHA-256. The configured [keySize] must be
  /// 128, 192, or 256 (valid AES key sizes).
  ///
  /// Throws [FortisConfigException] if key size is not a valid AES key size.
  /// Throws [FortisKeyException] if the keys use different curves.
  FortisAesKey deriveAesKey(
    FortisEcdhPublicKey publicKey, {
    Uint8List? salt,
    Uint8List? info,
  }) {
    _validateAesKeySize(_keySize);
    return FortisAesKey.fromTrustedBytes(
      deriveKey(publicKey, salt: salt, info: info),
    );
  }

  /// Derives key bytes from an arbitrary shared secret using HKDF.
  ///
  /// This is a static utility for when you already have a shared secret
  /// (e.g., from [deriveSharedSecret]) and want to derive key bytes.
  ///
  /// [keySize] must be a positive multiple of 8 bits. Defaults to 256.
  ///
  /// Throws [FortisConfigException] if [keySize] is invalid.
  static Uint8List hkdf(
    Uint8List sharedSecret, {
    int keySize = 256,
    Uint8List? salt,
    Uint8List? info,
  }) {
    _validateKeySize(keySize);

    final keyLengthBytes = keySize ~/ 8;
    final hkdfDerivator = HKDFKeyDerivator(SHA256Digest());
    hkdfDerivator.init(
      HkdfParameters(sharedSecret, keyLengthBytes, salt, info),
    );

    final output = Uint8List(keyLengthBytes);
    hkdfDerivator.deriveKey(null, 0, output, 0);

    return output;
  }

  /// Derives a [FortisAesKey] from an arbitrary shared secret using HKDF.
  ///
  /// This is a static utility for when you already have a shared secret
  /// (e.g., from [deriveSharedSecret]) and want to derive an AES key.
  ///
  /// [keySize] must be 128, 192, or 256 bits. Defaults to 256.
  ///
  /// Throws [FortisConfigException] if [keySize] is not a valid AES key size.
  static FortisAesKey hkdfDeriveAesKey(
    Uint8List sharedSecret, {
    int keySize = 256,
    Uint8List? salt,
    Uint8List? info,
  }) {
    _validateAesKeySize(keySize);
    return FortisAesKey.fromTrustedBytes(
      hkdf(sharedSecret, keySize: keySize, salt: salt, info: info),
    );
  }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

void _validateKeySize(int size) {
  if (size <= 0 || size % 8 != 0) {
    throw FortisConfigException(
      'keySize must be a positive multiple of 8 bits, got $size.',
    );
  }
}

void _validateAesKeySize(int size) {
  if (size != 128 && size != 192 && size != 256) {
    throw FortisConfigException(
      'AES keySize must be 128, 192, or 256 bits, got $size.',
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
