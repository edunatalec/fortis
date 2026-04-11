import 'fortis_exception.dart';

/// Thrown when an encrypt or decrypt operation fails.
///
/// Examples: wrong key used for decryption, corrupted ciphertext,
/// or plaintext too large for the key size and padding combination.
class FortisEncryptionException extends FortisException {
  /// Creates a [FortisEncryptionException] with the given [message].
  const FortisEncryptionException(super.message);
}
