import 'dart:math';
import 'dart:typed_data';

import 'package:pointycastle/export.dart';

import '../../core/fortis_log.dart';
import '../../core/platform.dart';
import '../../exceptions/fortis_config_exception.dart';
import 'rsa_decrypter.dart';
import 'rsa_encrypter.dart';
import 'rsa_hash.dart';
import 'rsa_key_pair.dart';
import 'rsa_padding.dart';
import 'rsa_private_key.dart';
import 'rsa_public_key.dart';

/// Marker base for the padding configuration state.
sealed class RsaBuilderPaddingState {}

/// Indicates that [RsaBuilder.padding] has not been called yet.
final class RsaBuilderPaddingUnset extends RsaBuilderPaddingState {}

/// Indicates that [RsaBuilder.padding] has been called.
final class RsaBuilderPaddingSet extends RsaBuilderPaddingState {}

/// Marker base for the hash configuration state.
sealed class RsaBuilderHashState {}

/// Indicates that [RsaBuilder.hash] has not been called yet.
final class RsaBuilderHashUnset extends RsaBuilderHashState {}

/// Indicates that [RsaBuilder.hash] has been called.
final class RsaBuilderHashSet extends RsaBuilderHashState {}

/// A fluent builder for RSA operations.
///
/// Obtain an instance via [Fortis.rsa].
///
/// **Defaults:**
/// - `keySize`: 2048 bits
/// - `padding`: *unset* — must be set before `.encrypter()`/`.decrypter()`
/// - `hash`: *unset* — must be set before `.encrypter()`/`.decrypter()`
///
/// The builder uses phantom types to guarantee at compile time that both
/// [padding] and [hash] have been configured before `.encrypter()` or
/// `.decrypter()` is available via the [RsaBuilderReady] extension.
///
/// Call [keySize] (optional), then either:
/// - [generateKeyPair] to generate a new key pair, or
/// - [padding] + [hash] to unlock [RsaBuilderReady.encrypter] /
///   [RsaBuilderReady.decrypter].
///
/// Example — recommended defaults (OAEP v2 + SHA-256):
///
/// ```dart
/// final pair = await Fortis.rsa().generateKeyPair(); // 2048-bit
///
/// final encrypter = Fortis.rsa()
///     .padding(RsaPadding.oaep_v2)
///     .hash(RsaHash.sha256)
///     .encrypter(pair.publicKey);
///
/// final ciphertext = encrypter.encrypt('hello fortis');
/// ```
///
/// Example — with label (OAEP v2.1 only):
///
/// ```dart
/// final encrypter = Fortis.rsa()
///     .padding(RsaPadding.oaep_v2_1)
///     .hash(RsaHash.sha256)
///     .encrypter(pair.publicKey, label: 'user:42');
/// ```
class RsaBuilder<
  P extends RsaBuilderPaddingState,
  H extends RsaBuilderHashState
> {
  final int _keySize;
  final RsaPadding? _padding;
  final RsaHash? _hash;

  /// Creates a builder with optional [keySizeParam], [paddingParam], and
  /// [hashParam]. Defaults: keySize = 2048, padding and hash unset.
  ///
  /// Users should call [Fortis.rsa] rather than constructing a builder
  /// directly — the unnamed constructor is public only because [Fortis.rsa]
  /// lives in a separate library.
  RsaBuilder({
    int keySizeParam = 2048,
    RsaPadding? paddingParam,
    RsaHash? hashParam,
  }) : _keySize = keySizeParam,
       _padding = paddingParam,
       _hash = hashParam;

  /// Sets the RSA key size in bits used by [generateKeyPair].
  ///
  /// Defaults to 2048. Must be a power of 2 and at least 2048. Common values:
  /// **2048** (default, fast), **3072** (NIST-recommended through 2030),
  /// **4096** (long-term, slower to generate).
  ///
  /// Example:
  /// ```dart
  /// final pair = await Fortis.rsa().keySize(3072).generateKeyPair();
  /// ```
  RsaBuilder<P, H> keySize(int size) =>
      RsaBuilder(keySizeParam: size, paddingParam: _padding, hashParam: _hash);

  /// Sets the padding scheme.
  ///
  /// Required before [RsaBuilderReady.encrypter] / [RsaBuilderReady.decrypter]
  /// become available (enforced at compile time via phantom types).
  ///
  /// Supported values — see [RsaPadding] for details and per-value examples:
  /// - [RsaPadding.oaep_v2_1] — OAEP with label support (new designs).
  /// - [RsaPadding.oaep_v2] — OAEP without label (new designs).
  /// - [RsaPadding.oaep_v1] — legacy SHA-1-only OAEP.
  /// - [RsaPadding.pkcs1_v1_5] — legacy PKCS#1 v1.5.
  ///
  /// Example:
  /// ```dart
  /// Fortis.rsa().padding(RsaPadding.oaep_v2).hash(RsaHash.sha256);
  /// ```
  RsaBuilder<RsaBuilderPaddingSet, H> padding(RsaPadding p) =>
      RsaBuilder(keySizeParam: _keySize, paddingParam: p, hashParam: _hash);

  /// Sets the hash algorithm used by the padding scheme (MGF1 for OAEP).
  ///
  /// Required before [RsaBuilderReady.encrypter] / [RsaBuilderReady.decrypter]
  /// become available (enforced at compile time via phantom types).
  ///
  /// See [RsaHash] for available values and a selection guide — the
  /// recommended default is [RsaHash.sha256].
  ///
  /// Note: ignored by [RsaPadding.pkcs1_v1_5] (no hash) and hard-wired to
  /// SHA-1 by [RsaPadding.oaep_v1]. The builder still requires a call, to
  /// keep the phantom-type API uniform.
  ///
  /// Example:
  /// ```dart
  /// Fortis.rsa().padding(RsaPadding.oaep_v2).hash(RsaHash.sha256);
  /// ```
  RsaBuilder<P, RsaBuilderHashSet> hash(RsaHash h) =>
      RsaBuilder(keySizeParam: _keySize, paddingParam: _padding, hashParam: h);

  /// Generates a new RSA key pair.
  ///
  /// On VM / mobile / desktop the work runs on a background [Isolate] so
  /// the main thread isn't blocked. On Flutter web — where
  /// `dart:isolate` is unavailable — the work runs synchronously on the
  /// main thread, wrapped in a [Future] to keep the signature uniform:
  /// RSA ≥ 2048 bits can freeze the UI for seconds, so a [FortisLog]
  /// warning is emitted to flag it. Consider pre-generating keys or
  /// offloading to a Web Worker in that case.
  ///
  /// Key size is controlled by [keySize] (default 2048). RSA-4096 may take
  /// several seconds to generate.
  ///
  /// Example:
  /// ```dart
  /// final pair = await Fortis.rsa().generateKeyPair();      // 2048-bit
  /// final big  = await Fortis.rsa().keySize(4096).generateKeyPair();
  /// ```
  ///
  /// Throws [FortisConfigException] if the key size is invalid.
  Future<FortisRsaKeyPair> generateKeyPair() async {
    _validateRsaKeySize(_keySize);

    if (_keySize == 4096) {
      FortisLog.info('RSA-4096 key generation may be slow.');
    }

    if (kFortisIsWeb && _keySize >= 2048) {
      FortisLog.warn(
        'RSA-$_keySize key generation on web blocks the main thread '
        '(dart:isolate is unavailable). Consider pre-generating keys '
        'or offloading to a Web Worker.',
      );
    }

    return runOffThread(() => _generateSync(_keySize));
  }
}

/// Unlocks [encrypter] and [decrypter] once both [RsaBuilder.padding] and
/// [RsaBuilder.hash] have been called.
extension RsaBuilderReady
    on RsaBuilder<RsaBuilderPaddingSet, RsaBuilderHashSet> {
  /// Builds an [RsaEncrypter] that encrypts with [key].
  ///
  /// [label] is only valid for [RsaPadding.oaep_v2_1]. Pass a [String] or a
  /// [Uint8List]; [String] is converted to UTF-8 bytes internally. The
  /// decrypter must use the same label or decryption will fail.
  ///
  /// Example — no label:
  /// ```dart
  /// final encrypter = Fortis.rsa()
  ///     .padding(RsaPadding.oaep_v2)
  ///     .hash(RsaHash.sha256)
  ///     .encrypter(pair.publicKey);
  /// ```
  ///
  /// Example — with label (binds ciphertext to a context):
  /// ```dart
  /// final encrypter = Fortis.rsa()
  ///     .padding(RsaPadding.oaep_v2_1)
  ///     .hash(RsaHash.sha256)
  ///     .encrypter(pair.publicKey, label: 'user:42');
  /// ```
  ///
  /// Throws [FortisConfigException] if [label] is provided with a non-v2.1
  /// padding, or is not a [String] / [Uint8List].
  RsaEncrypter encrypter(FortisRsaPublicKey key, {Object? label}) {
    // _padding and _hash are guaranteed non-null in this extension context
    // (only reachable after .padding() and .hash() have been called)
    final p = _padding!;
    final h = _hash!;

    _validateLabel(label, p);

    return RsaEncrypter(
      key: key,
      padding: p,
      hash: h,
      label: _normalizeLabel(label),
    );
  }

  /// Builds an [RsaDecrypter] that decrypts with [key].
  ///
  /// [label] is only valid for [RsaPadding.oaep_v2_1] and must match the
  /// label used when encrypting.
  ///
  /// Example:
  /// ```dart
  /// final decrypter = Fortis.rsa()
  ///     .padding(RsaPadding.oaep_v2_1)
  ///     .hash(RsaHash.sha256)
  ///     .decrypter(pair.privateKey, label: 'user:42');
  /// ```
  ///
  /// Throws [FortisConfigException] if [label] is provided with a non-v2.1
  /// padding, or is not a [String] / [Uint8List].
  RsaDecrypter decrypter(FortisRsaPrivateKey key, {Object? label}) {
    final p = _padding!;
    final h = _hash!;

    _validateLabel(label, p);

    return RsaDecrypter(
      key: key,
      padding: p,
      hash: h,
      label: _normalizeLabel(label),
    );
  }
}

void _validateRsaKeySize(int keySize) {
  if (keySize < 2048) {
    throw FortisConfigException(
      'keySize must be at least 2048 bits, got $keySize.',
    );
  }

  if (keySize & (keySize - 1) != 0) {
    throw FortisConfigException('keySize must be a power of 2, got $keySize.');
  }
}

void _validateLabel(Object? label, RsaPadding padding) {
  if (label == null) return;

  if (padding != RsaPadding.oaep_v2_1) {
    throw FortisConfigException(
      'label is only supported with RsaPadding.oaep_v2_1, '
      'but padding is $padding.',
    );
  }

  if (label is! String && label is! Uint8List) {
    throw FortisConfigException(
      'label must be a String or Uint8List, got ${label.runtimeType}.',
    );
  }
}

/// Converts a [String] label to UTF-8 bytes; passes [Uint8List] unchanged.
Uint8List? _normalizeLabel(Object? label) {
  if (label == null) return null;
  if (label is Uint8List) return label;

  return Uint8List.fromList((label as String).codeUnits);
}

FortisRsaKeyPair _generateSync(int keySize) {
  final secureRandom = FortunaRandom();
  final rng = Random.secure();
  final seed = Uint8List.fromList(List.generate(32, (_) => rng.nextInt(256)));

  secureRandom.seed(KeyParameter(seed));

  final keyGen = RSAKeyGenerator()
    ..init(
      ParametersWithRandom(
        RSAKeyGeneratorParameters(BigInt.parse('65537'), keySize, 64),
        secureRandom,
      ),
    );

  final pair = keyGen.generateKeyPair();

  return FortisRsaKeyPair(
    publicKey: FortisRsaPublicKey(pair.publicKey),
    privateKey: FortisRsaPrivateKey(pair.privateKey),
  );
}
