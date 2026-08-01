/// @docImport 'package:fortis/fortis.dart';
library;

import 'ecdh_private_key.dart';
import 'ecdh_public_key.dart';

/// A matching pair of ECDH [publicKey] and [privateKey].
///
/// {@category ECDH}
///
/// Produced by [EcdhBuilder.generateKeyPair]. Share [publicKey] with the
/// other party and combine their public key with your [privateKey] via
/// [EcdhBuilder.keyDerivation] to derive a shared secret.
///
/// Example:
/// ```dart
/// final pair = await Fortis.ecdh().generateKeyPair();
/// final pubPem = pair.publicKey.toPem();   // share this
/// final remotePublicKey = (await Fortis.ecdh().generateKeyPair()).publicKey;
///
/// final aesKey = Fortis.ecdh()
///     .keyDerivation(pair.privateKey)
///     .deriveAesKey(remotePublicKey);
/// ```
///
/// See also:
///
///  * [EcdhBuilder.generateKeyPair], which produces this pair.
///  * [FortisEcdhPublicKey], the half you share with the other party.
///  * [FortisEcdhPrivateKey], the half you keep secret.
///  * [EcdhKeyDerivation], which turns the two halves into a shared key.
class FortisEcdhKeyPair {
  /// Creates a [FortisEcdhKeyPair] with the given [publicKey] and
  /// [privateKey]. Both keys must use the same curve; Fortis does not
  /// validate that here.
  const FortisEcdhKeyPair({required this.publicKey, required this.privateKey});

  /// The public key — share with the other party for key agreement.
  final FortisEcdhPublicKey publicKey;

  /// The private key — keep secret. Used as input to
  /// [EcdhBuilder.keyDerivation].
  final FortisEcdhPrivateKey privateKey;
}
