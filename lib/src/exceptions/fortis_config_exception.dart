import 'fortis_exception.dart';

/// Thrown when the builder or caller input is misconfigured.
///
/// Typical triggers:
/// - Invalid key size (e.g. AES 123 bits, RSA 1024 bits).
/// - Unsupported padding/hash combination (e.g. label with non-OAEP-v2.1).
/// - Wrong IV/nonce length for the mode.
/// - Payload type that doesn't match the cipher's mode.
/// - Input of an unsupported type (e.g. passing an `int` to `encrypt`).
///
/// Example:
/// ```dart
/// try {
///   Fortis.aes().keySize(123); // invalid
///   await Fortis.aes().keySize(123).generateKey();
/// } on FortisConfigException catch (e) {
///   print(e.message); // 'AES key size must be 128, 192, or 256 bits...'
/// }
/// ```
class FortisConfigException extends FortisException {
  /// Creates a [FortisConfigException] with the given [message].
  const FortisConfigException(super.message);
}
