/// @docImport 'package:fortis/fortis.dart';
library;

import 'fortis_exception.dart';

/// Thrown when a key cannot be imported or exported.
///
/// {@category Errors}
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
/// const corruptedPem = '-----BEGIN PUBLIC KEY-----\nnot base64\n';
///
/// try {
///   final key = FortisRsaPublicKey.fromPem(corruptedPem);
/// } on FortisKeyException catch (e) {
///   print(e.message); // 'Invalid PEM for RSA public key: ...'
/// }
/// ```
///
/// See also:
///
///  * [FortisException], the base type to catch every Fortis error at once.
///  * [FortisConfigException], for caller-side misconfiguration.
///  * [FortisEncryptionException], for encrypt and decrypt failures.
class FortisKeyException extends FortisException {
  /// Creates a [FortisKeyException] with the given [message].
  const FortisKeyException(super.message);
}
