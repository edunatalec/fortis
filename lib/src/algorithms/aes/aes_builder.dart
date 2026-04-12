import 'dart:isolate';
import 'dart:math';
import 'dart:typed_data';

import '../../exceptions/fortis_config_exception.dart';
import 'aes_decrypter.dart';
import 'aes_encrypter.dart';
import 'aes_key.dart';
import 'aes_mode.dart';
import 'aes_padding.dart';

/// Builder for AES key generation and cipher configuration.
///
/// Obtain an instance via [Fortis.aes].
class AesBuilder {
  final int _keySize;

  /// Creates an [AesBuilder] with the given key size in bits (default: 256).
  AesBuilder({int keySize = 256}) : _keySize = keySize;

  /// Sets the key size in bits. Must be 128, 192, or 256.
  AesBuilder keySize(int size) => AesBuilder(keySize: size);

  /// Generates a random AES key of the configured [keySize] in a Dart Isolate.
  ///
  /// Throws [FortisConfigException] if [keySize] is not 128, 192, or 256.
  Future<FortisAesKey> generateKey() async {
    _validateKeySize(_keySize);
    return Isolate.run(() => _generateSync(_keySize));
  }

  /// Selects the AES mode of operation.
  ///
  /// Returns a mode-specific builder:
  /// - [AesBlockModeBuilder] for [AesMode.ecb] and [AesMode.cbc], which
  ///   exposes [AesBlockModeBuilder.padding].
  /// - [AesStreamModeBuilder] for [AesMode.ctr], [AesMode.cfb], and
  ///   [AesMode.ofb] — no padding configuration available.
  /// - [AesAuthModeBuilder] for [AesMode.gcm] and [AesMode.ccm], which
  ///   exposes [AesAuthModeBuilder.aad] and [AesAuthModeBuilder.tagSize].
  ///
  /// Call `.encrypter(myKey)` or `.decrypter(myKey)` on the returned builder
  /// to build the cipher object.
  AesModeBuilder mode(AesMode mode) => switch (mode) {
    AesMode.ecb || AesMode.cbc => AesBlockModeBuilder._(mode: mode),
    AesMode.ctr ||
    AesMode.cfb ||
    AesMode.ofb => AesStreamModeBuilder._(mode: mode),
    AesMode.gcm || AesMode.ccm => AesAuthModeBuilder._(mode: mode),
  };
}

// ──────────────────────────────────────────────
// Sealed mode builder hierarchy
// ──────────────────────────────────────────────

/// Abstract base for mode-specific AES builders.
///
/// Call [encrypter] or [decrypter] with a [FortisAesKey] to build the
/// cipher object.
sealed class AesModeBuilder {
  final AesMode _mode;

  AesModeBuilder._({required AesMode mode}) : _mode = mode;

  /// Builds an [AesEncrypter] for this configuration using [key].
  AesEncrypter encrypter(FortisAesKey key);

  /// Builds an [AesDecrypter] for this configuration using [key].
  AesDecrypter decrypter(FortisAesKey key);
}

/// Builder for block modes (ECB, CBC). Exposes [padding].
///
/// Obtain via [AesBuilder.mode] with [AesMode.ecb] or [AesMode.cbc].
///
/// Example:
/// ```dart
/// final encrypter = Fortis.aes()
///     .mode(AesMode.cbc)
///     .padding(AesPadding.pkcs7)
///     .encrypter(myKey);
/// ```
final class AesBlockModeBuilder extends AesModeBuilder {
  final AesPadding _padding;

  AesBlockModeBuilder._({
    required super.mode,
    AesPadding padding = AesPadding.pkcs7,
  }) : _padding = padding,
       super._();

  /// Sets the padding scheme. Defaults to [AesPadding.pkcs7].
  AesBlockModeBuilder padding(AesPadding padding) =>
      AesBlockModeBuilder._(mode: _mode, padding: padding);

  @override
  AesEncrypter encrypter(FortisAesKey key) =>
      AesEncrypter.block(mode: _mode, key: key, padding: _padding);

  @override
  AesDecrypter decrypter(FortisAesKey key) =>
      AesDecrypter.block(mode: _mode, key: key, padding: _padding);
}

/// Builder for stream modes (CTR, CFB, OFB). No user-configurable padding.
///
/// Obtain via [AesBuilder.mode] with [AesMode.ctr], [AesMode.cfb], or
/// [AesMode.ofb].
///
/// Example:
/// ```dart
/// final encrypter = Fortis.aes()
///     .mode(AesMode.ctr)
///     .encrypter(myKey);
/// ```
final class AesStreamModeBuilder extends AesModeBuilder {
  AesStreamModeBuilder._({required super.mode}) : super._();

  @override
  AesEncrypter encrypter(FortisAesKey key) =>
      AesEncrypter.stream(mode: _mode, key: key);

  @override
  AesDecrypter decrypter(FortisAesKey key) =>
      AesDecrypter.stream(mode: _mode, key: key);
}

/// Builder for authenticated modes (GCM, CCM). Exposes [aad] and [tagSize].
///
/// Obtain via [AesBuilder.mode] with [AesMode.gcm] or [AesMode.ccm].
///
/// Example:
/// ```dart
/// final encrypter = Fortis.aes()
///     .mode(AesMode.gcm)
///     .aad(Uint8List.fromList(utf8.encode('user-id-123')))
///     .encrypter(myKey);
/// ```
final class AesAuthModeBuilder extends AesModeBuilder {
  final Uint8List? _aad;
  final int _tagSizeBits;

  AesAuthModeBuilder._({
    required super.mode,
    Uint8List? aad,
    int tagSizeBits = 128,
  }) : _aad = aad,
       _tagSizeBits = tagSizeBits,
       super._();

  /// Sets the Additional Authenticated Data (AAD).
  ///
  /// AAD is authenticated but not encrypted. If set on encryption,
  /// the **same** AAD must be provided on decryption, or
  /// [FortisEncryptionException] will be thrown.
  AesAuthModeBuilder aad(Uint8List aad) => AesAuthModeBuilder._(
    mode: _mode,
    aad: aad,
    tagSizeBits: _tagSizeBits,
  );

  /// Sets the authentication tag size in bits. Defaults to 128.
  AesAuthModeBuilder tagSize(int bits) => AesAuthModeBuilder._(
    mode: _mode,
    aad: _aad,
    tagSizeBits: bits,
  );

  @override
  AesEncrypter encrypter(FortisAesKey key) => AesEncrypter.auth(
    mode: _mode,
    key: key,
    aad: _aad,
    tagSizeBits: _tagSizeBits,
  );

  @override
  AesDecrypter decrypter(FortisAesKey key) => AesDecrypter.auth(
    mode: _mode,
    key: key,
    aad: _aad,
    tagSizeBits: _tagSizeBits,
  );
}

// ──────────────────────────────────────────────
// Internal helpers
// ──────────────────────────────────────────────

void _validateKeySize(int keySize) {
  if (keySize != 128 && keySize != 192 && keySize != 256) {
    throw FortisConfigException(
      'AES key size must be 128, 192, or 256 bits, got $keySize.',
    );
  }
}

FortisAesKey _generateSync(int keySize) {
  final rng = Random.secure();
  final bytes = Uint8List.fromList(
    List.generate(keySize ~/ 8, (_) => rng.nextInt(256)),
  );
  return FortisAesKey.fromTrustedBytes(bytes);
}
