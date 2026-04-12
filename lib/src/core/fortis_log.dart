import 'dart:developer' as developer;

/// Emits internal log messages for the Fortis library.
///
/// Messages appear in Dart DevTools and any attached log listeners
/// under the `fortis` log name.
sealed class FortisLog {
  /// Logs an informational [message] (level 500).
  static void info(String message) {
    developer.log(message, name: 'fortis', level: 500);
  }

  /// Logs a warning [message] for unusual cryptographic configurations (level 900).
  static void warn(String message) {
    developer.log(message, name: 'fortis', level: 900);
  }
}
