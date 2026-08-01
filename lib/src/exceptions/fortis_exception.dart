/// @docImport 'package:fortis/fortis.dart';
library;

/// Base class for all exceptions thrown by the Fortis library.
///
/// {@category Errors}
///
/// Catch [FortisException] to handle any Fortis-originated error; catch one
/// of the concrete subtypes to react to a specific failure mode:
/// - [FortisConfigException] — caller-side misconfiguration.
/// - [FortisKeyException] — key import/export failures.
/// - [FortisEncryptionException] — encrypt/decrypt operation failures.
///
/// Example:
/// ```dart
/// final key = await Fortis.aes().generateKey();
/// final cipher = Fortis.aes().gcm().cipher(key);
/// final ciphertext = cipher.encryptToPayload('hello fortis');
///
/// try {
///   final plaintext = cipher.decryptToString(ciphertext);
/// } on FortisEncryptionException catch (e) {
///   // Likely tampering, wrong key, or bad ciphertext.
///   log('decryption failed: ${e.message}');
/// } on FortisException catch (e) {
///   // Any other Fortis error (config, key).
///   log('fortis error: ${e.message}');
/// }
/// ```
///
/// See also:
///
///  * [FortisConfigException], for caller-side misconfiguration.
///  * [FortisKeyException], for key import and export failures.
///  * [FortisEncryptionException], for encrypt and decrypt failures.
abstract class FortisException implements Exception {
  /// Creates a [FortisException] with the given [message].
  const FortisException(this.message);

  /// A human-readable description of what went wrong.
  final String message;

  @override
  String toString() => '$runtimeType: $message';
}
