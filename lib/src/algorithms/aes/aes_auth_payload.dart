/// The output of an AES authenticated encryption operation
/// ([AesMode.gcm], [AesMode.ccm]).
///
/// Contains the three components returned separately by many external
/// systems (.NET, Java, OpenSSL) when using authenticated encryption modes:
///
/// - [iv]: the initialization vector. In GCM and CCM this is technically a
///   "nonce" (number used once) — the terms are equivalent here (IETF RFC
///   5084). Default size 12 bytes (GCM) or 11 bytes (CCM), Base64-encoded.
/// - [data]: the ciphertext, Base64-encoded.
/// - [tag]: the authentication tag (16 bytes by default), Base64-encoded.
///   Used to verify integrity and authenticity on decryption.
///
/// Produced by [AesAuthCipher.encryptToPayload] — the return type is
/// statically inferred (no cast required):
///
/// ```dart
/// final cipher = Fortis.aes().gcm().cipher(key); // AesAuthCipher
/// final AesAuthPayload payload = cipher.encryptToPayload('hello');
/// print(payload.tag);                             // typed — no cast
///
/// // Serialize for a .NET/Java backend that expects 'nonce':
/// final json = jsonEncode(payload.toMap(ivKey: 'nonce'));
/// ```
class AesAuthPayload {
  /// The initialization vector (nonce), Base64-encoded.
  final String iv;

  /// The ciphertext, Base64-encoded.
  final String data;

  /// The authentication tag, Base64-encoded.
  final String tag;

  /// Creates an [AesAuthPayload] with the given [iv], [data], and [tag].
  const AesAuthPayload({
    required this.iv,
    required this.data,
    required this.tag,
  });

  /// Converts this payload to a `Map<String, String>`.
  ///
  /// The [ivKey] parameter controls the key name used for [iv] in the map.
  /// Defaults to `'iv'`. Use `ivKey: 'nonce'` when the receiving system
  /// expects the nonce under that key (common in .NET and Java backends).
  ///
  /// Example:
  /// ```dart
  /// payload.toMap()               // {'iv': '...', 'data': '...', 'tag': '...'}
  /// payload.toMap(ivKey: 'nonce') // {'nonce': '...', 'data': '...', 'tag': '...'}
  /// ```
  Map<String, String> toMap({String ivKey = 'iv'}) => {
    ivKey: iv,
    'data': data,
    'tag': tag,
  };
}
