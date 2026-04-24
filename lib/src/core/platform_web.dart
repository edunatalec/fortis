/// Whether the code is running on Flutter web.
///
/// Always `true` on this implementation; resolved via conditional export
/// from `platform.dart`.
const bool kFortisIsWeb = true;

/// Runs [computation] synchronously on the main thread, wrapped in a
/// [Future] to match the async signature of the VM implementation.
///
/// On web, `dart:isolate` is unavailable — so this stub cannot move
/// work off the main thread. Heavy work (e.g. RSA key generation) will
/// block the UI. Callers that need to differentiate can gate on
/// [kFortisIsWeb].
Future<T> runOffThread<T>(T Function() computation) => Future.sync(computation);
