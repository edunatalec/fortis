/// Platform abstraction used internally by fortis to keep the public API
/// identical across VM/AOT and Flutter web.
///
/// Resolved at compile time via conditional exports:
///
/// - VM / mobile / desktop → [platform_vm.dart] — uses `dart:isolate`.
/// - Flutter web (dart2js / dart2wasm) → [platform_web.dart] — runs
///   synchronously since `dart:isolate` is unavailable there.
///
/// Exposes [runOffThread] and [kFortisIsWeb] to the rest of the package.
/// Not exported by the public `package:fortis/fortis.dart` barrel.
library;

export 'platform_vm.dart' if (dart.library.js_interop) 'platform_web.dart';
