/// @docImport 'package:fortis/fortis.dart';
library;

import 'fortis_exception.dart';

/// Thrown when an encrypt or decrypt operation fails at runtime.
///
/// {@category Errors}
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
/// final key = await Fortis.aes().generateKey();
/// final cipher = Fortis.aes().gcm().cipher(key);
/// final tamperedCiphertext = cipher.encrypt('hello fortis');
/// tamperedCiphertext[0] ^= 0xFF;
///
/// try {
///   cipher.decrypt(tamperedCiphertext);
/// } on FortisEncryptionException catch (e) {
///   // Treat as a potential integrity failure — do NOT retry silently.
///   log('decrypt failed: ${e.message}');
/// }
/// ```
///
/// See also:
///
///  * [FortisException], the base type to catch every Fortis error at once.
///  * [FortisConfigException], for caller-side misconfiguration.
///  * [FortisKeyException], for key import and export failures.
class FortisEncryptionException extends FortisException {
  /// Creates a [FortisEncryptionException] with the given [message].
  const FortisEncryptionException(super.message);
}
