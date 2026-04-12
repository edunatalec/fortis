/// Represents the output of an AES non-authenticated encryption operation
/// (CBC, CTR, CFB, OFB).
///
/// Contains:
/// - [iv]: the initialization vector, Base64-encoded. Always 16 bytes.
/// - [data]: the ciphertext, Base64-encoded.
///
/// Note: these modes do not produce an authentication tag. For authenticated
/// encryption with integrity guarantees, use GCM or CCM mode ([AesAuthPayload]).
class AesPayload {
  /// The initialization vector, Base64-encoded.
  final String iv;

  /// The ciphertext, Base64-encoded.
  final String data;

  /// Creates an [AesPayload] with the given [iv] and [data].
  const AesPayload({required this.iv, required this.data});

  /// Converts this payload to a [Map<String, String>].
  ///
  /// The [ivKey] parameter controls the key name used for [iv] in the map.
  /// Defaults to `'iv'`. Use `ivKey: 'nonce'` if the receiving system
  /// expects that key name.
  ///
  /// Example:
  /// ```dart
  /// payload.toMap()                // {'iv': '...', 'data': '...'}
  /// payload.toMap(ivKey: 'nonce')  // {'nonce': '...', 'data': '...'}
  /// ```
  Map<String, String> toMap({String ivKey = 'iv'}) => {ivKey: iv, 'data': data};
}
