import 'fortis_exception.dart';

/// Thrown when a key cannot be imported or exported.
///
/// Typical triggers:
/// - Malformed PEM header or body.
/// - Invalid DER / ASN.1 structure.
/// - Base64 that fails to decode.
/// - ECDH keys on different curves supplied to the same agreement.
/// - Missing curve information when decoding an uncompressed EC point.
///
/// Example:
/// ```dart
/// try {
///   final key = FortisRsaPublicKey.fromPem(corruptedPem);
/// } on FortisKeyException catch (e) {
///   print(e.message); // 'Invalid PEM for RSA public key: ...'
/// }
/// ```
class FortisKeyException extends FortisException {
  /// Creates a [FortisKeyException] with the given [message].
  const FortisKeyException(super.message);
}
