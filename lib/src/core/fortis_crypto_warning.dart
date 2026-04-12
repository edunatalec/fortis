import 'dart:developer' as developer;

/// Logs a non-fatal cryptographic configuration warning.
///
/// Warnings are emitted via [developer.log] with level 900 (WARNING).
/// They appear in Dart DevTools and any attached log listeners.
class FortisCryptoWarning {
  FortisCryptoWarning._();

  /// Logs [message] as a warning under the `fortis` log name.
  static void log(String message) {
    developer.log(message, name: 'fortis', level: 900);
  }
}
