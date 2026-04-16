/// Base class for all exceptions thrown by the Fortis library.
///
/// Catch `FortisException` to handle any Fortis-originated error; catch one
/// of the concrete subtypes to react to a specific failure mode:
/// - [FortisConfigException] — caller-side misconfiguration.
/// - [FortisKeyException] — key import/export failures.
/// - [FortisEncryptionException] — encrypt/decrypt operation failures.
///
/// Example:
/// ```dart
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
abstract class FortisException implements Exception {
  /// A human-readable description of what went wrong.
  final String message;

  /// Creates a [FortisException] with the given [message].
  const FortisException(this.message);

  @override
  String toString() => '$runtimeType: $message';
}
