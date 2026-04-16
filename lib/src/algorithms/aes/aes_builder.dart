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
/// Obtain an instance via [Fortis.aes]. The only configurable parameter at
/// this stage is the key size — defaults to **256 bits**.
///
/// Two ways to continue the chain:
///
/// 1. **Typed shortcuts** — strongly typed by mode, so `.cipher()` returns the
///    correct subtype of [AesCipher] without any cast:
///    ```dart
///    final key = await Fortis.aes().generateKey();
///    final cipher = Fortis.aes().gcm().cipher(key); // AesAuthCipher
///    final payload = cipher.encryptToPayload('hi'); // AesAuthPayload
///    ```
///
/// 2. **Dynamic** — useful when the mode is only known at runtime. Returns
///    the sealed base type [AesModeBuilder]:
///    ```dart
///    final builder = Fortis.aes().mode(runtimeMode); // AesModeBuilder
///    ```
class AesBuilder {
  final int _keySize;

  /// Creates an [AesBuilder] with the given key size in bits.
  ///
  /// Defaults to 256. Must be 128, 192, or 256.
  AesBuilder({int keySize = 256}) : _keySize = keySize;

  /// Sets the key size in bits. Must be 128, 192, or 256. Defaults to 256.
  ///
  /// Example:
  /// ```dart
  /// final key = await Fortis.aes().keySize(128).generateKey();
  /// ```
  AesBuilder keySize(int size) => AesBuilder(keySize: size);

  /// Generates a random AES key of the configured key size in a Dart
  /// [Isolate], so the main thread is not blocked.
  ///
  /// Example:
  /// ```dart
  /// final key = await Fortis.aes().generateKey();     // 256-bit
  /// final key = await Fortis.aes().keySize(192).generateKey();
  /// ```
  ///
  /// Throws [FortisConfigException] if the key size is not 128, 192, or 256.
  Future<FortisAesKey> generateKey() async {
    _validateKeySize(_keySize);
    return Isolate.run(() => _generateSync(_keySize));
  }

  /// Selects [AesMode.ecb] and returns an [AesEcbModeBuilder].
  ///
  /// ⚠️ ECB is insecure for most use cases. Prefer [gcm]. Padding defaults
  /// to [AesPadding.pkcs7].
  ///
  /// Example:
  /// ```dart
  /// final cipher = Fortis.aes().ecb().cipher(key); // AesEcbCipher
  /// ```
  AesEcbModeBuilder ecb() => AesEcbModeBuilder._();

  /// Selects [AesMode.cbc] and returns an [AesCbcModeBuilder].
  ///
  /// Uses a 16-byte IV; padding defaults to [AesPadding.pkcs7]. Configure
  /// padding via [AesCbcModeBuilder.padding].
  ///
  /// Example:
  /// ```dart
  /// final cipher = Fortis.aes().cbc().cipher(key); // AesStandardCipher
  /// ```
  AesCbcModeBuilder cbc() => AesCbcModeBuilder._();

  /// Selects [AesMode.ctr] and returns an [AesStreamModeBuilder].
  ///
  /// Stream mode — no padding. Uses a 16-byte IV.
  ///
  /// Example:
  /// ```dart
  /// final cipher = Fortis.aes().ctr().cipher(key); // AesStandardCipher
  /// ```
  AesStreamModeBuilder ctr() => AesStreamModeBuilder._(mode: AesMode.ctr);

  /// Selects [AesMode.cfb] and returns an [AesStreamModeBuilder].
  ///
  /// Stream mode — no padding. Uses a 16-byte IV.
  AesStreamModeBuilder cfb() => AesStreamModeBuilder._(mode: AesMode.cfb);

  /// Selects [AesMode.ofb] and returns an [AesStreamModeBuilder].
  ///
  /// Stream mode — no padding. Uses a 16-byte IV.
  AesStreamModeBuilder ofb() => AesStreamModeBuilder._(mode: AesMode.ofb);

  /// Selects [AesMode.gcm] and returns an [AesAuthModeBuilder]. ✅ Recommended.
  ///
  /// Authenticated encryption (AEAD). IV defaults to 12 bytes, tag to 128
  /// bits. Configure via [AesAuthModeBuilder.aad], [AesAuthModeBuilder.tagSize],
  /// and [AesAuthModeBuilder.nonceSize].
  ///
  /// Example:
  /// ```dart
  /// final cipher = Fortis.aes().gcm().cipher(key); // AesAuthCipher
  /// final payload = cipher.encryptToPayload('hi'); // AesAuthPayload
  /// ```
  AesAuthModeBuilder gcm() => AesAuthModeBuilder._(mode: AesMode.gcm);

  /// Selects [AesMode.ccm] and returns an [AesAuthModeBuilder].
  ///
  /// Authenticated encryption (AEAD). Nonce defaults to 11 bytes (allowing
  /// ~4 GB messages), tag to 128 bits. Common in IoT / TLS contexts.
  ///
  /// Example:
  /// ```dart
  /// final cipher = Fortis.aes().ccm().cipher(key); // AesAuthCipher
  /// ```
  AesAuthModeBuilder ccm() => AesAuthModeBuilder._(mode: AesMode.ccm);

  /// Selects the AES mode of operation at runtime.
  ///
  /// Returns the sealed base type [AesModeBuilder] — static type does not
  /// know the concrete mode. Prefer the typed shortcuts ([ecb], [cbc],
  /// [ctr], [cfb], [ofb], [gcm], [ccm]) when the mode is known at compile
  /// time to get a statically typed [AesCipher] subtype.
  ///
  /// Returned concrete type by mode:
  /// - [AesMode.ecb] → [AesEcbModeBuilder] (exposes [AesEcbModeBuilder.padding]).
  /// - [AesMode.cbc] → [AesCbcModeBuilder] (exposes [AesCbcModeBuilder.padding]).
  /// - [AesMode.ctr] / [AesMode.cfb] / [AesMode.ofb] → [AesStreamModeBuilder].
  /// - [AesMode.gcm] / [AesMode.ccm] → [AesAuthModeBuilder] (exposes aad,
  ///   [AesAuthModeBuilder.tagSize], [AesAuthModeBuilder.nonceSize]).
  ///
  /// Example:
  /// ```dart
  /// final builder = Fortis.aes().mode(runtimeMode);
  /// final cipher = builder.cipher(key); // AesCipher (sealed base)
  /// ```
  AesModeBuilder mode(AesMode mode) => switch (mode) {
    AesMode.ecb => AesEcbModeBuilder._(),
    AesMode.cbc => AesCbcModeBuilder._(),
    AesMode.ctr ||
    AesMode.cfb ||
    AesMode.ofb => AesStreamModeBuilder._(mode: mode),
    AesMode.gcm || AesMode.ccm => AesAuthModeBuilder._(mode: mode),
  };
}

/// Sealed base for mode-specific AES builders.
///
/// You won't construct subtypes directly — they are returned by the typed
/// shortcuts on [AesBuilder]:
///
/// | Builder shortcut     | Concrete subtype       | Cipher returned       |
/// |----------------------|------------------------|-----------------------|
/// | `Fortis.aes().ecb()` | [AesEcbModeBuilder]    | [AesEcbCipher]        |
/// | `Fortis.aes().cbc()` | [AesCbcModeBuilder]    | [AesStandardCipher]   |
/// | `Fortis.aes().ctr()` | [AesStreamModeBuilder] | [AesStandardCipher]   |
/// | `Fortis.aes().cfb()` | [AesStreamModeBuilder] | [AesStandardCipher]   |
/// | `Fortis.aes().ofb()` | [AesStreamModeBuilder] | [AesStandardCipher]   |
/// | `Fortis.aes().gcm()` | [AesAuthModeBuilder]   | [AesAuthCipher]       |
/// | `Fortis.aes().ccm()` | [AesAuthModeBuilder]   | [AesAuthCipher]       |
///
/// Call [cipher] with a [FortisAesKey] to build the concrete cipher.
sealed class AesModeBuilder {
  final AesMode _mode;

  AesModeBuilder._({required AesMode mode}) : _mode = mode;

  /// Builds the AES cipher for this configuration using [key].
  ///
  /// Each subtype of [AesModeBuilder] overrides this with a covariant return
  /// type — so the concrete cipher type appears in your IDE:
  ///
  /// - [AesEcbModeBuilder.cipher] → [AesEcbCipher]
  /// - [AesCbcModeBuilder.cipher] → [AesStandardCipher]
  /// - [AesStreamModeBuilder.cipher] → [AesStandardCipher]
  /// - [AesAuthModeBuilder.cipher] → [AesAuthCipher]
  ///
  /// Example — typed shortcut keeps the concrete return type:
  /// ```dart
  /// final cipher = Fortis.aes().gcm().cipher(key); // AesAuthCipher
  /// final payload = cipher.encryptToPayload('hi'); // AesAuthPayload (no cast)
  /// ```
  ///
  /// Example — dynamic dispatch returns the sealed base:
  /// ```dart
  /// final AesCipher cipher = Fortis.aes().mode(runtimeMode).cipher(key);
  /// // Pattern-match or cast to the concrete subtype to call
  /// // encryptToPayload, which is not on the base.
  /// ```
  AesCipher cipher(FortisAesKey key);
}

/// Builder for [AesMode.ecb]. Exposes [padding].
///
/// ⚠️ ECB is insecure for most use cases — use [AesAuthModeBuilder] (GCM)
/// unless you must interoperate with an ECB-only legacy system.
///
/// Example:
/// ```dart
/// final cipher = Fortis.aes()
///     .ecb()
///     .padding(AesPadding.pkcs7)
///     .cipher(key); // AesEcbCipher
/// ```
final class AesEcbModeBuilder extends AesModeBuilder {
  final AesPadding _padding;

  AesEcbModeBuilder._({AesPadding padding = AesPadding.pkcs7})
    : _padding = padding,
      super._(mode: AesMode.ecb);

  /// Sets the padding scheme. Defaults to [AesPadding.pkcs7].
  ///
  /// Supported values:
  /// - [AesPadding.pkcs7] — standard and unambiguous. **Recommended.**
  /// - [AesPadding.iso7816] — `0x80` followed by zero bytes.
  /// - [AesPadding.zeroPadding] — zero bytes (ambiguous with trailing zeros).
  /// - [AesPadding.noPadding] — plaintext must be a multiple of 16 bytes.
  AesEcbModeBuilder padding(AesPadding padding) =>
      AesEcbModeBuilder._(padding: padding);

  /// Builds an [AesEcbCipher] with the configured padding.
  ///
  /// ECB has no IV and does not support [AesStandardCipher.encryptToPayload]
  /// — that method is intentionally absent from [AesEcbCipher].
  ///
  /// Example:
  /// ```dart
  /// final cipher = Fortis.aes().ecb().cipher(key); // AesEcbCipher
  /// final bytes = cipher.encrypt(alignedData);
  /// final plain = cipher.decrypt(bytes);
  /// ```
  @override
  AesEcbCipher cipher(FortisAesKey key) =>
      AesEcbCipher(key: key, padding: _padding);
}

/// Builder for [AesMode.cbc]. Exposes [padding].
///
/// Example:
/// ```dart
/// final cipher = Fortis.aes()
///     .cbc()
///     .padding(AesPadding.pkcs7)
///     .cipher(key); // AesStandardCipher
/// ```
final class AesCbcModeBuilder extends AesModeBuilder {
  final AesPadding _padding;

  AesCbcModeBuilder._({AesPadding padding = AesPadding.pkcs7})
    : _padding = padding,
      super._(mode: AesMode.cbc);

  /// Sets the padding scheme. Defaults to [AesPadding.pkcs7].
  ///
  /// See [AesPadding] for available values.
  AesCbcModeBuilder padding(AesPadding padding) =>
      AesCbcModeBuilder._(padding: padding);

  /// Builds an [AesStandardCipher] configured for CBC mode.
  ///
  /// Returns [AesStandardCipher], whose
  /// [AesStandardCipher.encryptToPayload] produces an [AesPayload] (iv +
  /// data) — statically typed, no cast required.
  ///
  /// Example:
  /// ```dart
  /// final cipher = Fortis.aes().cbc().cipher(key); // AesStandardCipher
  /// final payload = cipher.encryptToPayload('hi'); // AesPayload
  /// print('iv=${payload.iv} data=${payload.data}');
  /// ```
  @override
  AesStandardCipher cipher(FortisAesKey key) =>
      AesStandardCipher(mode: AesMode.cbc, key: key, padding: _padding);
}

/// Builder for stream modes ([AesMode.ctr], [AesMode.cfb], [AesMode.ofb]).
/// No user-configurable padding — stream modes don't use padding.
///
/// Example:
/// ```dart
/// final cipher = Fortis.aes().ctr().cipher(key); // AesStandardCipher
/// ```
final class AesStreamModeBuilder extends AesModeBuilder {
  AesStreamModeBuilder._({required super.mode}) : super._();

  /// Builds an [AesStandardCipher] configured for the stream mode selected
  /// on [AesBuilder] (CTR, CFB, or OFB).
  ///
  /// Returns [AesStandardCipher], whose
  /// [AesStandardCipher.encryptToPayload] produces an [AesPayload] (iv +
  /// data) — statically typed, no cast required.
  ///
  /// Example:
  /// ```dart
  /// final cipher = Fortis.aes().ctr().cipher(key); // AesStandardCipher
  /// final payload = cipher.encryptToPayload('hi'); // AesPayload
  /// ```
  @override
  AesStandardCipher cipher(FortisAesKey key) =>
      AesStandardCipher(mode: _mode, key: key);
}

/// Builder for authenticated modes ([AesMode.gcm], [AesMode.ccm]).
/// Exposes [aad], [tagSize], and [nonceSize].
///
/// Example:
/// ```dart
/// final cipher = Fortis.aes()
///     .gcm()
///     .nonceSize(12)
///     .aad(Uint8List.fromList(utf8.encode('user-id-123')))
///     .cipher(key); // AesAuthCipher
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
  /// AAD is authenticated but not encrypted. If set on encryption, the
  /// **same** AAD must be provided on decryption, or
  /// [FortisEncryptionException] is thrown.
  ///
  /// Example:
  /// ```dart
  /// final cipher = Fortis.aes()
  ///     .gcm()
  ///     .aad(Uint8List.fromList(utf8.encode('user-id-42')))
  ///     .cipher(key);
  /// ```
  AesAuthModeBuilder aad(Uint8List aad) => AesAuthModeBuilder._(
    mode: _mode,
    aad: aad,
    tagSizeBits: _tagSizeBits,
    nonceSize: _nonceSize,
  );

  /// Sets the authentication tag size in bits. Defaults to 128.
  ///
  /// Common values: 96, 104, 112, 120, 128. Smaller tags give weaker
  /// integrity guarantees. Prefer the default (128) unless required by
  /// an external protocol.
  ///
  /// Example:
  /// ```dart
  /// final cipher = Fortis.aes().gcm().tagSize(96).cipher(key);
  /// ```
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
  /// Example:
  /// ```dart
  /// final cipher = Fortis.aes().gcm().nonceSize(12).cipher(key);
  /// final cipher = Fortis.aes().ccm().nonceSize(13).cipher(key); // smaller messages
  /// ```
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

  /// Builds an [AesAuthCipher] configured for the authenticated mode
  /// selected on [AesBuilder] (GCM or CCM).
  ///
  /// Returns [AesAuthCipher], whose [AesAuthCipher.encryptToPayload]
  /// produces an [AesAuthPayload] (iv + data + tag) — statically typed,
  /// no cast required.
  ///
  /// Example:
  /// ```dart
  /// final cipher = Fortis.aes().gcm().cipher(key); // AesAuthCipher
  /// final payload = cipher.encryptToPayload('hi'); // AesAuthPayload
  /// print('tag=${payload.tag}'); // ✓ typed field, no cast
  /// ```
  @override
  AesAuthCipher cipher(FortisAesKey key) => AesAuthCipher(
    mode: _mode,
    key: key,
    aad: _aad,
    tagSizeBits: _tagSizeBits,
    nonceSize: _nonceSize,
  );
}

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
