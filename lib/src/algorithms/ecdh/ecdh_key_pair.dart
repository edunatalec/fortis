import 'ecdh_private_key.dart';
import 'ecdh_public_key.dart';

/// A matching pair of ECDH [publicKey] and [privateKey].
///
/// Produced by [EcdhBuilder.generateKeyPair]. Share [publicKey] with the
/// other party and combine their public key with your [privateKey] via
/// [EcdhBuilder.keyDerivation] to derive a shared secret.
///
/// Example:
/// ```dart
/// final pair = await Fortis.ecdh().generateKeyPair();
/// final pubPem = pair.publicKey.toPem();   // share this
/// final aesKey = Fortis.ecdh()
///     .keyDerivation(pair.privateKey)
///     .deriveAesKey(remotePublicKey);
/// ```
class FortisEcdhKeyPair {
  /// The public key — share with the other party for key agreement.
  final FortisEcdhPublicKey publicKey;

  /// The private key — keep secret. Used as input to
  /// [EcdhBuilder.keyDerivation].
  final FortisEcdhPrivateKey privateKey;

  /// Creates a [FortisEcdhKeyPair] with the given [publicKey] and
  /// [privateKey]. Both keys must use the same curve; Fortis does not
  /// validate that here.
  const FortisEcdhKeyPair({required this.publicKey, required this.privateKey});
}
