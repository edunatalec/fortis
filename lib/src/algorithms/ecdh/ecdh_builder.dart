import 'dart:isolate';
import 'dart:math';
import 'dart:typed_data';

import 'package:pointycastle/export.dart';

import '../../exceptions/fortis_config_exception.dart';
import 'ecdh_curve.dart';
import 'ecdh_key_derivation.dart';
import 'ecdh_key_pair.dart';
import 'ecdh_private_key.dart';
import 'ecdh_public_key.dart';

/// A fluent builder for ECDH key agreement operations.
///
/// Obtain an instance via [Fortis.ecdh].
///
/// **Defaults:**
/// - `curve`: [EcdhCurve.p256] (NIST P-256, 128-bit security level)
/// - `keySize`: 256 bits (used only by [keyDerivation])
///
/// Zero-config usage (everything at its default):
///
/// ```dart
/// // Generate a key pair with defaults (P-256):
/// final pair = await Fortis.ecdh().generateKeyPair();
///
/// // Derive a shared AES key (P-256 + HKDF-SHA256 → 256-bit AES key):
/// final aesKey = Fortis.ecdh()
///     .keyDerivation(myPrivateKey)
///     .deriveAesKey(theirPublicKey);
/// ```
///
/// With explicit configuration:
///
/// ```dart
/// final key = Fortis.ecdh()
///     .curve(EcdhCurve.p384)
///     .keySize(256)
///     .keyDerivation(myPrivateKey)
///     .deriveKey(theirPublicKey);
/// ```
class EcdhBuilder {
  final EcdhCurve _curve;
  final int _keySize;

  /// Creates an [EcdhBuilder] with the given defaults.
  ///
  /// Defaults: [curveParam] = [EcdhCurve.p256], [keySizeParam] = 256 bits.
  ///
  /// Users should call [Fortis.ecdh] rather than constructing a builder
  /// directly.
  EcdhBuilder({EcdhCurve curveParam = EcdhCurve.p256, int keySizeParam = 256})
    : _curve = curveParam,
      _keySize = keySizeParam;

  /// Sets the elliptic curve used for key agreement.
  ///
  /// Defaults to [EcdhCurve.p256] (128-bit security). See [EcdhCurve] for
  /// alternatives:
  /// - [EcdhCurve.p256] — 128-bit security, fastest. **Default**.
  /// - [EcdhCurve.p384] — 192-bit security.
  /// - [EcdhCurve.p521] — 256-bit security, slowest.
  ///
  /// Example:
  /// ```dart
  /// final pair = await Fortis.ecdh()
  ///     .curve(EcdhCurve.p384)
  ///     .generateKeyPair();
  /// ```
  EcdhBuilder curve(EcdhCurve curve) =>
      EcdhBuilder(curveParam: curve, keySizeParam: _keySize);

  /// Sets the derived key size in bits for [EcdhKeyDerivation.deriveKey].
  ///
  /// Defaults to 256. Must be a positive multiple of 8. For AES keys via
  /// [EcdhKeyDerivation.deriveAesKey], must be 128, 192, or 256.
  ///
  /// Example:
  /// ```dart
  /// final keyBytes = Fortis.ecdh()
  ///     .keySize(512) // 64 bytes of derived key material
  ///     .keyDerivation(myPrivateKey)
  ///     .deriveKey(theirPublicKey);
  /// ```
  EcdhBuilder keySize(int size) =>
      EcdhBuilder(curveParam: _curve, keySizeParam: size);

  /// Generates a new ECDH key pair asynchronously in a separate [Isolate]
  /// so the main thread isn't blocked.
  ///
  /// The curve is determined by the current [curve] setting (default:
  /// [EcdhCurve.p256]).
  ///
  /// Example:
  /// ```dart
  /// final pair = await Fortis.ecdh().generateKeyPair(); // P-256
  /// print(pair.publicKey.toPem());
  /// ```
  Future<FortisEcdhKeyPair> generateKeyPair() async {
    return Isolate.run(() => _generateSync(_curve));
  }

  /// Creates an [EcdhKeyDerivation] for key agreement with [privateKey].
  ///
  /// Use [EcdhKeyDerivation.deriveKey] (raw bytes), [EcdhKeyDerivation.deriveAesKey]
  /// (ready-to-use AES key), or [EcdhKeyDerivation.deriveSharedSecret] (raw
  /// shared secret without HKDF).
  ///
  /// Example:
  /// ```dart
  /// final aesKey = Fortis.ecdh()
  ///     .keyDerivation(myPrivateKey)
  ///     .deriveAesKey(theirPublicKey);
  /// ```
  ///
  /// Throws [FortisConfigException] if [keySize] is invalid (not a positive
  /// multiple of 8).
  EcdhKeyDerivation keyDerivation(FortisEcdhPrivateKey privateKey) {
    _validateKeySize(_keySize);
    return EcdhKeyDerivation(privateKey: privateKey, keySize: _keySize);
  }
}

void _validateKeySize(int size) {
  if (size <= 0 || size % 8 != 0) {
    throw FortisConfigException(
      'keySize must be a positive multiple of 8 bits, got $size.',
    );
  }
}

FortisEcdhKeyPair _generateSync(EcdhCurve curve) {
  final secureRandom = FortunaRandom();
  final rng = Random.secure();
  final seed = Uint8List.fromList(List.generate(32, (_) => rng.nextInt(256)));

  secureRandom.seed(KeyParameter(seed));

  final domainParams = ECDomainParameters(curve.domainName);
  final keyGen = ECKeyGenerator()
    ..init(
      ParametersWithRandom(
        ECKeyGeneratorParameters(domainParams),
        secureRandom,
      ),
    );

  final pair = keyGen.generateKeyPair();

  return FortisEcdhKeyPair(
    publicKey: FortisEcdhPublicKey(pair.publicKey, curve),
    privateKey: FortisEcdhPrivateKey(pair.privateKey, curve),
  );
}
