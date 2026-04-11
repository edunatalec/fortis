/// Base class for all exceptions thrown by the Fortis library.
abstract class FortisException implements Exception {
  /// A human-readable description of what went wrong.
  final String message;

  /// Creates a [FortisException] with the given [message].
  const FortisException(this.message);

  @override
  String toString() => '$runtimeType: $message';
}
