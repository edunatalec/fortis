import 'dart:isolate';

/// Whether the code is running on Flutter web.
///
/// Always `false` on this implementation; resolved via conditional export
/// from `platform.dart`.
const bool kFortisIsWeb = false;

/// Runs [computation] on a background [Isolate] so the main thread is
/// not blocked.
///
/// On web — where `dart:isolate` is unavailable — the sibling
/// `platform_web.dart` implementation runs [computation] synchronously
/// inside a [Future], keeping the async signature uniform across
/// platforms.
Future<T> runOffThread<T>(T Function() computation) => Isolate.run(computation);
