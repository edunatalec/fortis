import 'dart:isolate';
import 'dart:math';
import 'dart:typed_data';

import '../../core/fortis_log.dart';
import '../../exceptions/fortis_config_exception.dart';
import 'aes_cipher.dart';
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
  /// Call `.cipher(myKey)` on the returned builder to build the cipher object.
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
/// Call [cipher] with a [FortisAesKey] to build the cipher object.
sealed class AesModeBuilder {
  final AesMode _mode;

  AesModeBuilder._({required AesMode mode}) : _mode = mode;

  /// Builds an [AesCipher] for this configuration using [key].
  AesCipher cipher(FortisAesKey key);
}

/// Builder for block modes (ECB, CBC). Exposes [padding].
///
/// Obtain via [AesBuilder.mode] with [AesMode.ecb] or [AesMode.cbc].
///
/// Example:
/// ```dart
/// final cipher = Fortis.aes()
///     .mode(AesMode.cbc)
///     .padding(AesPadding.pkcs7)
///     .cipher(myKey);
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
  AesCipher cipher(FortisAesKey key) =>
      AesCipher.block(mode: _mode, key: key, padding: _padding);
}

/// Builder for stream modes (CTR, CFB, OFB). No user-configurable padding.
///
/// Obtain via [AesBuilder.mode] with [AesMode.ctr], [AesMode.cfb], or
/// [AesMode.ofb].
///
/// Example:
/// ```dart
/// final cipher = Fortis.aes()
///     .mode(AesMode.ctr)
///     .cipher(myKey);
/// ```
final class AesStreamModeBuilder extends AesModeBuilder {
  AesStreamModeBuilder._({required super.mode}) : super._();

  @override
  AesCipher cipher(FortisAesKey key) =>
      AesCipher.stream(mode: _mode, key: key);
}

/// Builder for authenticated modes (GCM, CCM). Exposes [aad], [tagSize], and [nonceSize].
///
/// Obtain via [AesBuilder.mode] with [AesMode.gcm] or [AesMode.ccm].
///
/// Example:
/// ```dart
/// final cipher = Fortis.aes()
///     .mode(AesMode.gcm)
///     .nonceSize(16)
///     .aad(Uint8List.fromList(utf8.encode('user-id-123')))
///     .cipher(myKey);
/// ```
final class AesAuthModeBuilder extends AesModeBuilder {
  final Uint8List? _aad;
  final int _tagSizeBits;
  final int _nonceSize;

  AesAuthModeBuilder._({
    required super.mode,
    Uint8List? aad,
    int tagSizeBits = 128,
    int? nonceSize,
  }) : _aad = aad,
       _tagSizeBits = tagSizeBits,
       _nonceSize = nonceSize ?? (mode == AesMode.gcm ? 12 : 11),
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
    nonceSize: _nonceSize,
  );

  /// Sets the authentication tag size in bits. Defaults to 128.
  AesAuthModeBuilder tagSize(int bits) => AesAuthModeBuilder._(
    mode: _mode,
    aad: _aad,
    tagSizeBits: bits,
    nonceSize: _nonceSize,
  );

  /// Sets the IV or nonce size in bytes for GCM or CCM mode.
  ///
  /// **GCM** ([AesMode.gcm]): any size >= 1 is accepted. Per NIST SP 800-38D,
  /// 96 bits (12 bytes) is the recommended size for performance and security.
  /// A [FortisLog] warning is emitted if [size] exceeds 16 bytes.
  /// Defaults to 12 bytes.
  ///
  /// **CCM** ([AesMode.ccm]): size must be between 7 and 13 bytes per RFC 3610
  /// and NIST SP 800-38C. The nonce size and the message length field (L) are
  /// related by L + N = 15. Larger nonces allow fewer unique values but support
  /// larger messages. Defaults to 11 bytes (~4 GB max message size).
  ///
  /// | CCM nonce size | Max message size |
  /// |----------------|-----------------|
  /// | 7 bytes        | 2^64 bytes      |
  /// | 11 bytes       | ~4 GB (default) |
  /// | 13 bytes       | 65,535 bytes    |
  ///
  /// Throws [FortisConfigException] if [size] < 1 for GCM, or if [size] is
  /// outside [7, 13] for CCM.
  AesAuthModeBuilder nonceSize(int size) {
    if (_mode == AesMode.gcm) {
      if (size < 1) {
        throw FortisConfigException(
          'GCM IV size must be at least 1 byte, got $size.',
        );
      }
      if (size > 16) {
        FortisLog.warn(
          'GCM IV size of $size bytes is unusual. '
          'The NIST SP 800-38D recommended size is 12 bytes (96 bits). '
          'Values above 16 bytes may indicate a design issue.',
        );
      }
    } else {
      // CCM: RFC 3610 and NIST SP 800-38C require nonce size in [7, 13].
      if (size < 7 || size > 13) {
        throw FortisConfigException(
          'CCM nonce size must be between 7 and 13 bytes, got $size.',
        );
      }
    }
    return AesAuthModeBuilder._(
      mode: _mode,
      aad: _aad,
      tagSizeBits: _tagSizeBits,
      nonceSize: size,
    );
  }

  @override
  AesCipher cipher(FortisAesKey key) => AesCipher.auth(
    mode: _mode,
    key: key,
    aad: _aad,
    tagSizeBits: _tagSizeBits,
    nonceSize: _nonceSize,
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
