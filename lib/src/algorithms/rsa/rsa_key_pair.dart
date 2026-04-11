import 'rsa_private_key.dart';
import 'rsa_public_key.dart';

/// A container holding a matching RSA public and private key pair.
///
/// Produced by [RsaBuilder.generateKeyPair]. Keys are pure data and hold no
/// encryption logic — use [RsaEncrypter] and [RsaDecrypter] for operations.
class FortisRsaKeyPair {
  /// The public key, used for encryption.
  final FortisRsaPublicKey publicKey;

  /// The private key, used for decryption.
  final FortisRsaPrivateKey privateKey;

  /// Creates an [FortisRsaKeyPair] from the given [publicKey] and [privateKey].
  const FortisRsaKeyPair({required this.publicKey, required this.privateKey});
}
