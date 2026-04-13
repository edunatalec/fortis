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
/// ```dart
/// // Generate a key pair
/// final pair = await Fortis.ecdh().curve(EcdhCurve.p256).generateKeyPair();
///
/// // Derive a key
/// final key = Fortis.ecdh()
///     .curve(EcdhCurve.p256)
///     .keySize(256)
///     .keyDerivation(myPrivateKey)
///     .deriveKey(theirPublicKey);
/// ```
class EcdhBuilder {
  final EcdhCurve _curve;
  final int _keySize;

  /// Creates an [EcdhBuilder] with optional [curveParam] and [keySizeParam].
  ///
  /// Users should call [Fortis.ecdh] rather than constructing a builder
  /// directly.
  EcdhBuilder({EcdhCurve curveParam = EcdhCurve.p256, int keySizeParam = 256})
    : _curve = curveParam,
      _keySize = keySizeParam;

  /// Sets the elliptic curve. Defaults to [EcdhCurve.p256].
  EcdhBuilder curve(EcdhCurve curve) =>
      EcdhBuilder(curveParam: curve, keySizeParam: _keySize);

  /// Sets the derived key size in bits for [EcdhKeyDerivation.deriveKey].
  ///
  /// Must be a positive multiple of 8. Defaults to 256.
  EcdhBuilder keySize(int size) =>
      EcdhBuilder(curveParam: _curve, keySizeParam: size);

  /// Generates a new ECDH key pair asynchronously in a separate [Isolate].
  Future<FortisEcdhKeyPair> generateKeyPair() async {
    return Isolate.run(() => _generateSync(_curve));
  }

  /// Creates an [EcdhKeyDerivation] for key agreement with [privateKey].
  ///
  /// Throws [FortisConfigException] if [keySize] is invalid.
  EcdhKeyDerivation keyDerivation(FortisEcdhPrivateKey privateKey) {
    _validateKeySize(_keySize);
    return EcdhKeyDerivation(privateKey: privateKey, keySize: _keySize);
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
