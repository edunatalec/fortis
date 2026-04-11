import 'dart:developer' as dev;
import 'dart:isolate';
import 'dart:math';
import 'dart:typed_data';

import 'package:pointycastle/export.dart';

import '../../exceptions/fortis_config_exception.dart';
import 'rsa_decrypter.dart';
import 'rsa_encrypter.dart';
import 'rsa_hash.dart';
import 'rsa_key_pair.dart';
import 'rsa_padding.dart';
import 'rsa_private_key.dart';
import 'rsa_public_key.dart';

// ---------------------------------------------------------------------------
// Phantom type markers
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Builder
// ---------------------------------------------------------------------------

/// A fluent builder for RSA operations.
///
/// Obtain an instance via [Fortis.rsa].
///
/// Call [keySize] (optional), then either:
/// - [generateKeyPair] to generate a new key pair, or
/// - [padding] + [hash] to unlock [RsaBuilderReady.encrypter] /
///   [RsaBuilderReady.decrypter].
///
/// ```dart
/// final pair = await Fortis.rsa().keySize(2048).generateKeyPair();
///
/// final encrypter = Fortis.rsa()
///     .padding(RsaPadding.oaep_v2)
///     .hash(RsaHash.sha256)
///     .encrypter(pair.publicKey);
/// ```
class RsaBuilder<P extends RsaBuilderPaddingState, H extends RsaBuilderHashState> {
  final int _keySize;
  final RsaPadding? _padding;
  final RsaHash? _hash;

  // The unnamed constructor is public so that [Fortis.rsa] (defined in a
  // separate library) can instantiate the initial unset state. Users should
  // call [Fortis.rsa] rather than constructing a builder directly.
  RsaBuilder({
    int keySizeParam = 2048,
    RsaPadding? paddingParam,
    RsaHash? hashParam,
  })  : _keySize = keySizeParam,
        _padding = paddingParam,
        _hash = hashParam;

  // ---------------------------------------------------------------------------
  // Configuration methods
  // ---------------------------------------------------------------------------

  /// Sets the RSA key size (in bits) used by [generateKeyPair].
  ///
  /// Defaults to 2048. Must be a power of 2 and at least 2048.
  RsaBuilder<P, H> keySize(int size) =>
      RsaBuilder(keySizeParam: size, paddingParam: _padding, hashParam: _hash);

  /// Sets the padding scheme for [RsaBuilderReady.encrypter] /
  /// [RsaBuilderReady.decrypter].
  RsaBuilder<RsaBuilderPaddingSet, H> padding(RsaPadding p) =>
      RsaBuilder(keySizeParam: _keySize, paddingParam: p, hashParam: _hash);

  /// Sets the hash algorithm for the padding scheme.
  RsaBuilder<P, RsaBuilderHashSet> hash(RsaHash h) =>
      RsaBuilder(keySizeParam: _keySize, paddingParam: _padding, hashParam: h);

  // ---------------------------------------------------------------------------
  // Key generation
  // ---------------------------------------------------------------------------

  /// Generates a new RSA key pair asynchronously in a separate [Isolate].
  ///
  /// Throws [FortisConfigException] if the key size is invalid.
  Future<FortisRsaKeyPair> generateKeyPair() async {
    _validateKeySize(_keySize);

    if (_keySize == 4096) {
      dev.log(
        'RSA-4096 key generation may be slow.',
        name: 'fortis',
        level: 500,
      );
    }

    return Isolate.run(() => _generateSync(_keySize));
  }
}

// ---------------------------------------------------------------------------
// Extension: encrypter / decrypter only available when fully configured
// ---------------------------------------------------------------------------

/// Unlocks [encrypter] and [decrypter] once both [RsaBuilder.padding] and
/// [RsaBuilder.hash] have been called.
extension RsaBuilderReady
    on RsaBuilder<RsaBuilderPaddingSet, RsaBuilderHashSet> {
  /// Builds an [RsaEncrypter] that encrypts with [key].
  ///
  /// [label] is only valid for [RsaPadding.oaep_v2_1]. Pass a [String] or a
  /// [Uint8List]; the library converts [String] to UTF-8 bytes internally.
  ///
  /// Throws [FortisConfigException] if [label] is provided with a non-v2.1 padding.
  RsaEncrypter encrypter(FortisRsaPublicKey key, {Object? label}) {
    // _padding and _hash are guaranteed non-null in this extension context
    // (only reachable after .padding() and .hash() have been called)
    final p = _padding!; // ignore: unnecessary_non_null_assertion
    final h = _hash!; // ignore: unnecessary_non_null_assertion
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
  /// [label] is only valid for [RsaPadding.oaep_v2_1]. Pass a [String] or a
  /// [Uint8List]; the library converts [String] to UTF-8 bytes internally.
  ///
  /// Throws [FortisConfigException] if [label] is provided with a non-v2.1 padding.
  RsaDecrypter decrypter(FortisRsaPrivateKey key, {Object? label}) {
    final p = _padding!; // ignore: unnecessary_non_null_assertion
    final h = _hash!; // ignore: unnecessary_non_null_assertion
    _validateLabel(label, p);
    return RsaDecrypter(
      key: key,
      padding: p,
      hash: h,
      label: _normalizeLabel(label),
    );
  }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

void _validateKeySize(int keySize) {
  if (keySize < 2048) {
    throw FortisConfigException(
      'keySize must be at least 2048 bits, got $keySize.',
    );
  }
  if (keySize & (keySize - 1) != 0) {
    throw FortisConfigException(
      'keySize must be a power of 2, got $keySize.',
    );
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
  final seed = Uint8List.fromList(
    List.generate(32, (_) => rng.nextInt(256)),
  );
  secureRandom.seed(KeyParameter(seed));

  final keyGen = RSAKeyGenerator()
    ..init(ParametersWithRandom(
      RSAKeyGeneratorParameters(BigInt.parse('65537'), keySize, 64),
      secureRandom,
    ));

  final pair = keyGen.generateKeyPair();
  return FortisRsaKeyPair(
    publicKey: FortisRsaPublicKey(pair.publicKey),
    privateKey: FortisRsaPrivateKey(pair.privateKey),
  );
}
