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
  /// Call `.key(myKey)` on the returned builder to get a ready builder, then
  /// `.encrypter()` or `.decrypter()`.
  AesModeBuilder mode(AesMode mode) => switch (mode) {
    AesMode.ecb ||
    AesMode.cbc => AesBlockModeBuilder._(mode: mode, keySize: _keySize),
    AesMode.ctr ||
    AesMode.cfb ||
    AesMode.ofb => AesStreamModeBuilder._(mode: mode, keySize: _keySize),
    AesMode.gcm ||
    AesMode.ccm => AesAuthModeBuilder._(mode: mode, keySize: _keySize),
  };
}

// ──────────────────────────────────────────────
// Sealed mode builder hierarchy
// ──────────────────────────────────────────────

/// Abstract base for mode-specific AES builders.
///
/// Call [key] to advance to a ready builder, then call
/// [AesReadyBuilder.encrypter] or [AesReadyBuilder.decrypter].
sealed class AesModeBuilder {
  final AesMode _mode;
  final int _keySize;

  AesModeBuilder._({required AesMode mode, required int keySize})
    : _mode = mode,
      _keySize = keySize;

  /// Sets the AES key. Returns a [AesReadyBuilder] that can produce an
  /// [AesEncrypter] or [AesDecrypter].
  AesReadyBuilder key(FortisAesKey key);
}

/// Builder for block modes (ECB, CBC). Exposes [padding].
///
/// Obtain via [AesBuilder.mode] with [AesMode.ecb] or [AesMode.cbc].
final class AesBlockModeBuilder extends AesModeBuilder {
  final AesPadding _padding;

  AesBlockModeBuilder._({
    required super.mode,
    required super.keySize,
    AesPadding padding = AesPadding.pkcs7,
  }) : _padding = padding,
       super._();

  /// Sets the padding scheme. Defaults to [AesPadding.pkcs7].
  AesBlockModeBuilder padding(AesPadding padding) =>
      AesBlockModeBuilder._(mode: _mode, keySize: _keySize, padding: padding);

  @override
  AesBlockReadyBuilder key(FortisAesKey key) => AesBlockReadyBuilder._(
    mode: _mode,
    keySize: _keySize,
    padding: _padding,
    key: key,
  );
}

/// Builder for stream modes (CTR, CFB, OFB). No user-configurable padding.
///
/// Obtain via [AesBuilder.mode] with [AesMode.ctr], [AesMode.cfb], or
/// [AesMode.ofb].
final class AesStreamModeBuilder extends AesModeBuilder {
  AesStreamModeBuilder._({required super.mode, required super.keySize})
    : super._();

  @override
  AesStreamReadyBuilder key(FortisAesKey key) =>
      AesStreamReadyBuilder._(mode: _mode, keySize: _keySize, key: key);
}

/// Builder for authenticated modes (GCM, CCM). Exposes [aad] and [tagSize].
///
/// Obtain via [AesBuilder.mode] with [AesMode.gcm] or [AesMode.ccm].
final class AesAuthModeBuilder extends AesModeBuilder {
  final Uint8List? _aad;
  final int _tagSizeBits;

  AesAuthModeBuilder._({
    required super.mode,
    required super.keySize,
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
    keySize: _keySize,
    aad: aad,
    tagSizeBits: _tagSizeBits,
  );

  /// Sets the authentication tag size in bits. Defaults to 128.
  AesAuthModeBuilder tagSize(int bits) => AesAuthModeBuilder._(
    mode: _mode,
    keySize: _keySize,
    aad: _aad,
    tagSizeBits: bits,
  );

  @override
  AesAuthReadyBuilder key(FortisAesKey key) => AesAuthReadyBuilder._(
    mode: _mode,
    keySize: _keySize,
    aad: _aad,
    tagSizeBits: _tagSizeBits,
    key: key,
  );
}

// ──────────────────────────────────────────────
// Ready builder hierarchy (mode + key are both set)
// ──────────────────────────────────────────────

/// Abstract base for ready AES builders (mode + key configured).
///
/// Call [encrypter] or [decrypter] to build the cipher object.
sealed class AesReadyBuilder {
  final AesMode _mode;
  final FortisAesKey _key;

  AesReadyBuilder._({required AesMode mode, required FortisAesKey key})
    : _mode = mode,
      _key = key;

  /// Builds an [AesEncrypter] for this configuration.
  AesEncrypter encrypter();

  /// Builds an [AesDecrypter] for this configuration.
  AesDecrypter decrypter();
}

/// Ready builder for block modes (ECB, CBC).
final class AesBlockReadyBuilder extends AesReadyBuilder {
  final AesPadding _padding;
  // ignore: unused_field
  final int _keySize;

  AesBlockReadyBuilder._({
    required super.mode,
    required int keySize,
    required super.key,
    required AesPadding padding,
  }) : _padding = padding,
       _keySize = keySize,
       super._();

  @override
  AesEncrypter encrypter() =>
      AesEncrypter.block(mode: _mode, key: _key, padding: _padding);

  @override
  AesDecrypter decrypter() =>
      AesDecrypter.block(mode: _mode, key: _key, padding: _padding);
}

/// Ready builder for stream modes (CTR, CFB, OFB).
final class AesStreamReadyBuilder extends AesReadyBuilder {
  // ignore: unused_field
  final int _keySize;

  AesStreamReadyBuilder._({
    required super.mode,
    required int keySize,
    required super.key,
  }) : _keySize = keySize,
       super._();

  @override
  AesEncrypter encrypter() => AesEncrypter.stream(mode: _mode, key: _key);

  @override
  AesDecrypter decrypter() => AesDecrypter.stream(mode: _mode, key: _key);
}

/// Ready builder for authenticated modes (GCM, CCM).
final class AesAuthReadyBuilder extends AesReadyBuilder {
  final Uint8List? _aad;
  final int _tagSizeBits;
  // ignore: unused_field
  final int _keySize;

  AesAuthReadyBuilder._({
    required super.mode,
    required int keySize,
    required super.key,
    Uint8List? aad,
    int tagSizeBits = 128,
  }) : _aad = aad,
       _tagSizeBits = tagSizeBits,
       _keySize = keySize,
       super._();

  @override
  AesEncrypter encrypter() => AesEncrypter.auth(
    mode: _mode,
    key: _key,
    aad: _aad,
    tagSizeBits: _tagSizeBits,
  );

  @override
  AesDecrypter decrypter() => AesDecrypter.auth(
    mode: _mode,
    key: _key,
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
