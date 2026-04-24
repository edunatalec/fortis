import 'dart:math';
import 'dart:typed_data';

import '../../core/fortis_log.dart';
import '../../core/platform.dart';
import '../../exceptions/fortis_config_exception.dart';
import 'aes_constants.dart';
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

  /// Generates a random AES key of the configured key size.
  ///
  /// On VM / mobile / desktop the work runs on a background [Isolate] so
  /// the main thread is not blocked. On Flutter web — where
  /// `dart:isolate` is unavailable — the work runs synchronously on the
  /// main thread, wrapped in a [Future] to keep the signature uniform.
  /// AES key generation is trivially fast, so the web fallback is
  /// effectively instantaneous.
  ///
  /// Example:
  /// ```dart
  /// final key = await Fortis.aes().generateKey();     // 256-bit
  /// final key = await Fortis.aes().keySize(192).generateKey();
  /// ```
  ///
  /// Throws [FortisConfigException] if the key size is not 128, 192, or 256.
  Future<FortisAesKey> generateKey() async {
    _validateAesKeySize(_keySize);
    return runOffThread(() => _generateSync(_keySize));
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

  /// Selects [AesMode.gcm] and returns an [AesGcmModeBuilder]. ✅ Recommended.
  ///
  /// Authenticated encryption (AEAD). IV defaults to 12 bytes, tag is fixed
  /// at 128 bits (the only value PointyCastle supports for GCM). Configure
  /// via [AesGcmModeBuilder.aad] and [AesGcmModeBuilder.ivSize].
  ///
  /// Example:
  /// ```dart
  /// final cipher = Fortis.aes().gcm().cipher(key); // AesAuthCipher
  /// final payload = cipher.encryptToPayload('hi'); // AesAuthPayload
  /// ```
  AesGcmModeBuilder gcm() => AesGcmModeBuilder._();

  /// Selects [AesMode.ccm] and returns an [AesCcmModeBuilder].
  ///
  /// Authenticated encryption (AEAD). Nonce defaults to 11 bytes (allowing
  /// ~4 GB messages), tag to 128 bits. Common in IoT / TLS contexts.
  /// Configure via [AesCcmModeBuilder.aad], [AesCcmModeBuilder.ivSize], and
  /// [AesCcmModeBuilder.tagSize].
  ///
  /// Example:
  /// ```dart
  /// final cipher = Fortis.aes().ccm().cipher(key); // AesAuthCipher
  /// ```
  AesCcmModeBuilder ccm() => AesCcmModeBuilder._();

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
  /// - [AesMode.gcm] → [AesGcmModeBuilder] (exposes aad, ivSize).
  /// - [AesMode.ccm] → [AesCcmModeBuilder] (exposes aad, ivSize, tagSize).
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
    AesMode.gcm => AesGcmModeBuilder._(),
    AesMode.ccm => AesCcmModeBuilder._(),
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
/// | `Fortis.aes().gcm()` | [AesGcmModeBuilder]    | [AesAuthCipher]       |
/// | `Fortis.aes().ccm()` | [AesCcmModeBuilder]    | [AesAuthCipher]       |
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
  /// - [AesGcmModeBuilder.cipher] / [AesCcmModeBuilder.cipher] → [AesAuthCipher]
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

/// Sealed base for authenticated-mode builders ([AesMode.gcm], [AesMode.ccm]).
///
/// The concrete subtypes [AesGcmModeBuilder] and [AesCcmModeBuilder] differ
/// in what they expose:
///
/// - GCM has a fixed tag size of 128 bits (the only value PointyCastle
///   supports), so [AesGcmModeBuilder] does **not** expose a `tagSize` setter.
/// - CCM supports tags of 32/48/64/80/96/112/128 bits per NIST SP 800-38C,
///   so [AesCcmModeBuilder] exposes `tagSize` with validation against that set.
///
/// Both subtypes expose `aad` and `ivSize`. Use this sealed base only as a
/// type annotation when a function should accept either GCM or CCM.
sealed class AesAuthModeBuilder extends AesModeBuilder {
  final Uint8List? _aad;
  final int _tagSizeBits;
  final int _ivSize;

  AesAuthModeBuilder._({
    required super.mode,
    Uint8List? aad,
    required int tagSizeBits,
    required int ivSize,
  }) : _aad = aad,
       _tagSizeBits = tagSizeBits,
       _ivSize = ivSize,
       super._();

  /// Sets the Additional Authenticated Data (AAD). Subtypes override this
  /// with a covariant return type so the chain stays statically typed.
  AesAuthModeBuilder aad(Uint8List aad);

  /// Sets the IV size in bytes. Subtypes apply mode-specific validation
  /// and return their own type via covariance.
  AesAuthModeBuilder ivSize(int size);

  /// Builds an [AesAuthCipher] for this configuration.
  @override
  AesAuthCipher cipher(FortisAesKey key) => AesAuthCipher(
    mode: _mode,
    key: key,
    aad: _aad,
    tagSizeBits: _tagSizeBits,
    ivSize: _ivSize,
  );
}

/// Builder for [AesMode.gcm]. Exposes [aad] and [ivSize].
///
/// The authentication tag is fixed at **128 bits** — the only size
/// PointyCastle 4.x accepts for GCM. For variable tag sizes use
/// [AesCcmModeBuilder].
///
/// Example:
/// ```dart
/// final cipher = Fortis.aes()
///     .gcm()
///     .ivSize(12)
///     .aad(Uint8List.fromList(utf8.encode('user-id-123')))
///     .cipher(key); // AesAuthCipher
/// ```
final class AesGcmModeBuilder extends AesAuthModeBuilder {
  AesGcmModeBuilder._({super.aad, super.ivSize = gcmDefaultIvSize})
    : super._(mode: AesMode.gcm, tagSizeBits: 128);

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
  @override
  AesGcmModeBuilder aad(Uint8List aad) =>
      AesGcmModeBuilder._(aad: aad, ivSize: _ivSize);

  /// Sets the IV size in bytes. Defaults to 12.
  ///
  /// Per NIST SP 800-38D, 96 bits (12 bytes) is the recommended size for
  /// performance and security. Any size ≥ 1 is accepted; a [FortisLog]
  /// warning is emitted if [size] exceeds 16 bytes.
  ///
  /// Example:
  /// ```dart
  /// final cipher = Fortis.aes().gcm().ivSize(12).cipher(key);
  /// ```
  ///
  /// Throws [FortisConfigException] if [size] < 1.
  @override
  AesGcmModeBuilder ivSize(int size) {
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
    return AesGcmModeBuilder._(aad: _aad, ivSize: size);
  }
}

/// Builder for [AesMode.ccm]. Exposes [aad], [ivSize], and [tagSize].
///
/// Example:
/// ```dart
/// final cipher = Fortis.aes()
///     .ccm()
///     .ivSize(11)
///     .tagSize(96)
///     .cipher(key); // AesAuthCipher
/// ```
final class AesCcmModeBuilder extends AesAuthModeBuilder {
  AesCcmModeBuilder._({
    super.aad,
    super.ivSize = ccmDefaultIvSize,
    super.tagSizeBits = 128,
  }) : super._(mode: AesMode.ccm);

  /// Sets the Additional Authenticated Data (AAD). See [AesGcmModeBuilder.aad].
  @override
  AesCcmModeBuilder aad(Uint8List aad) =>
      AesCcmModeBuilder._(aad: aad, ivSize: _ivSize, tagSizeBits: _tagSizeBits);

  /// Sets the IV size in bytes. Defaults to 11.
  ///
  /// Per RFC 3610 and NIST SP 800-38C (where this value is called a *nonce*),
  /// the size must be between 7 and 13 bytes. Size and the message-length
  /// field (L) are related by L + N = 15 — larger IVs allow fewer unique
  /// values but support larger messages.
  ///
  /// | CCM IV size | Max message size |
  /// |-------------|------------------|
  /// | 7 bytes     | 2^64 bytes       |
  /// | 11 bytes    | ~4 GB (default)  |
  /// | 13 bytes    | 65,535 bytes     |
  ///
  /// Throws [FortisConfigException] if [size] is outside [7, 13].
  @override
  AesCcmModeBuilder ivSize(int size) {
    if (size < 7 || size > 13) {
      throw FortisConfigException(
        'CCM IV size must be between 7 and 13 bytes, got $size.',
      );
    }
    return AesCcmModeBuilder._(
      aad: _aad,
      ivSize: size,
      tagSizeBits: _tagSizeBits,
    );
  }

  /// Sets the authentication tag size in bits. Defaults to 128.
  ///
  /// Per NIST SP 800-38C, valid values are `{32, 48, 64, 80, 96, 112, 128}`.
  /// Smaller tags give weaker integrity guarantees; prefer 128 unless
  /// required by an external protocol.
  ///
  /// Example:
  /// ```dart
  /// final cipher = Fortis.aes().ccm().tagSize(96).cipher(key);
  /// ```
  ///
  /// Throws [FortisConfigException] if [bits] is not a valid CCM tag size.
  AesCcmModeBuilder tagSize(int bits) {
    const validTagSizes = {32, 48, 64, 80, 96, 112, 128};
    if (!validTagSizes.contains(bits)) {
      throw FortisConfigException(
        'CCM tag size must be one of 32/48/64/80/96/112/128 bits '
        '(per NIST SP 800-38C), got $bits.',
      );
    }
    return AesCcmModeBuilder._(aad: _aad, ivSize: _ivSize, tagSizeBits: bits);
  }
}

void _validateAesKeySize(int keySize) {
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
