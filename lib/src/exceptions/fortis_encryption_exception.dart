import 'fortis_exception.dart';

/// Thrown when an encrypt or decrypt operation fails at runtime.
///
/// Typical triggers:
/// - Authentication failure on GCM/CCM decrypt (ciphertext or AAD tampered
///   with, or a different AAD than the one used during encryption).
/// - Wrong key used for decryption.
/// - Plaintext too large for the configured RSA key + hash combination.
/// - Ciphertext shorter than the expected IV/nonce prefix.
///
/// Example:
/// ```dart
/// try {
///   cipher.decrypt(tamperedCiphertext);
/// } on FortisEncryptionException catch (e) {
///   // Treat as a potential integrity failure — do NOT retry silently.
///   log('decrypt failed: ${e.message}');
/// }
/// ```
class FortisEncryptionException extends FortisException {
  /// Creates a [FortisEncryptionException] with the given [message].
  const FortisEncryptionException(super.message);
}
