import 'fortis_exception.dart';

/// Thrown when a key cannot be imported or exported.
///
/// Examples: malformed PEM header, invalid DER structure,
/// or ASN.1 parsing failure.
class FortisKeyException extends FortisException {
  /// Creates a [FortisKeyException] with the given [message].
  const FortisKeyException(super.message);
}
