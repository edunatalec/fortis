import 'ecdh_private_key.dart';
import 'ecdh_public_key.dart';

/// A container holding a matching ECDH public and private key pair.
class FortisEcdhKeyPair {
  /// The public key, shared with the other party for key agreement.
  final FortisEcdhPublicKey publicKey;

  /// The private key, kept secret for key agreement.
  final FortisEcdhPrivateKey privateKey;

  /// Creates a [FortisEcdhKeyPair] from the given [publicKey] and
  /// [privateKey].
  const FortisEcdhKeyPair({required this.publicKey, required this.privateKey});
}
