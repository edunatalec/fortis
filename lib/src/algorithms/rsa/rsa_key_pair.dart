/// @docImport 'package:fortis/fortis.dart';
library;

import 'rsa_private_key.dart';
import 'rsa_public_key.dart';

/// A matching pair of RSA [publicKey] and [privateKey].
///
/// {@category RSA}
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
///
/// See also:
///
///  * [RsaBuilder.generateKeyPair], which produces this pair.
///  * [FortisRsaPublicKey] and [FortisRsaPrivateKey], the two halves and
///    their PEM/DER serialization.
class FortisRsaKeyPair {
  /// Creates a [FortisRsaKeyPair] with the given [publicKey] and
  /// [privateKey]. The keys must be a genuine RSA pair; Fortis does not
  /// validate that they match.
  const FortisRsaKeyPair({required this.publicKey, required this.privateKey});

  /// The public key — share with others to receive ciphertexts.
  final FortisRsaPublicKey publicKey;

  /// The private key — keep secret; used to decrypt.
  final FortisRsaPrivateKey privateKey;
}
