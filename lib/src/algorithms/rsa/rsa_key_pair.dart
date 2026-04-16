import 'rsa_private_key.dart';
import 'rsa_public_key.dart';

/// A matching pair of RSA [publicKey] and [privateKey].
///
/// Produced by [RsaBuilder.generateKeyPair]. Keys are pure data containers
/// — to encrypt or decrypt, build an [RsaEncrypter] / [RsaDecrypter] via
/// [RsaBuilder].
///
/// Example:
/// ```dart
/// final pair = await Fortis.rsa().generateKeyPair();
///
/// final encrypter = Fortis.rsa()
///     .padding(RsaPadding.oaep_v2)
///     .hash(RsaHash.sha256)
///     .encrypter(pair.publicKey);
///
/// final decrypter = Fortis.rsa()
///     .padding(RsaPadding.oaep_v2)
///     .hash(RsaHash.sha256)
///     .decrypter(pair.privateKey);
/// ```
class FortisRsaKeyPair {
  /// The public key — share with others to receive ciphertexts.
  final FortisRsaPublicKey publicKey;

  /// The private key — keep secret; used to decrypt.
  final FortisRsaPrivateKey privateKey;

  /// Creates a [FortisRsaKeyPair] with the given [publicKey] and
  /// [privateKey]. The keys must be a genuine RSA pair; Fortis does not
  /// validate that they match.
  const FortisRsaKeyPair({required this.publicKey, required this.privateKey});
}
