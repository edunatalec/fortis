import 'fortis_exception.dart';

/// Thrown when the builder is misconfigured.
///
/// Examples: invalid key size, unsupported padding/hash combination,
/// or providing a label with a padding that does not support it.
class FortisConfigException extends FortisException {
  /// Creates a [FortisConfigException] with the given [message].
  const FortisConfigException(super.message);
}
