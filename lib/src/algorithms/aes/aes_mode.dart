// ignore_for_file: constant_identifier_names

/// The AES cipher mode of operation.
///
/// Passed to [AesBuilder.mode] when the mode is only known at runtime. For
/// compile-time-known modes, prefer the typed shortcuts on [AesBuilder]
/// ([AesBuilder.gcm], [AesBuilder.cbc], etc.) — they return builders whose
/// `.cipher()` yields the specific [AesCipher] subtype.
///
/// Example:
/// ```dart
/// // Dynamic:
/// final builder = Fortis.aes().mode(AesMode.gcm);
///
/// // Typed (preferred):
/// final cipher = Fortis.aes().gcm().cipher(key); // AesAuthCipher
/// ```
enum AesMode {
  /// Electronic Code Book mode.
  ///
  /// ⚠️ **Insecure for most use cases.** Identical plaintext blocks produce
  /// identical ciphertext blocks, revealing patterns in the data. Only use
  /// for legacy interoperability. Prefer [gcm] in new designs.
  ///
  /// ECB does not use an IV or nonce.
  ///
  /// Example:
  /// ```dart
  /// final cipher = Fortis.aes().ecb().cipher(key);
  /// ```
  ///
  /// Reference: NIST SP 800-38A.
  ecb,

  /// Cipher Block Chaining mode.
  ///
  /// Requires a 16-byte initialization vector (IV). Uses configurable padding
  /// (defaults to [AesPadding.pkcs7]). The IV must be unpredictable (random)
  /// for each encryption operation.
  ///
  /// Example:
  /// ```dart
  /// final cipher = Fortis.aes()
  ///     .cbc()
  ///     .padding(AesPadding.pkcs7)
  ///     .cipher(key);
  /// ```
  ///
  /// Reference: NIST SP 800-38A.
  cbc,

  /// Counter mode.
  ///
  /// Requires a 16-byte initialization vector (IV). No padding required
  /// (stream mode). The IV must be unique for each encryption operation with
  /// the same key.
  ///
  /// Example:
  /// ```dart
  /// final cipher = Fortis.aes().ctr().cipher(key);
  /// ```
  ///
  /// Reference: NIST SP 800-38A.
  ctr,

  /// Galois/Counter Mode. Provides authenticated encryption (AEAD).
  ///
  /// ✅ **Recommended default** for most use cases.
  ///
  /// Per NIST SP 800-38D, the IV in GCM is essentially a nonce (must be
  /// unique per encryption under the same key). The recommended IV size is
  /// 96 bits (12 bytes). Configurable via [AesAuthModeBuilder.nonceSize].
  ///
  /// Example:
  /// ```dart
  /// final cipher = Fortis.aes().gcm().cipher(key);
  /// final payload = cipher.encryptToPayload('hi'); // AesAuthPayload
  /// ```
  ///
  /// Reference: NIST SP 800-38D.
  gcm,

  /// Cipher Feedback mode.
  ///
  /// Requires a 16-byte initialization vector (IV). No padding required
  /// (stream mode). The IV must be unpredictable (random) for each
  /// encryption operation.
  ///
  /// Example:
  /// ```dart
  /// final cipher = Fortis.aes().cfb().cipher(key);
  /// ```
  ///
  /// Reference: NIST SP 800-38A.
  cfb,

  /// Output Feedback mode.
  ///
  /// Requires a 16-byte initialization vector (IV). No padding required
  /// (stream mode). The IV must be unique for each encryption operation
  /// with the same key.
  ///
  /// Example:
  /// ```dart
  /// final cipher = Fortis.aes().ofb().cipher(key);
  /// ```
  ///
  /// Reference: NIST SP 800-38A.
  ofb,

  /// Counter with CBC-MAC mode. Provides authenticated encryption (AEAD).
  ///
  /// Commonly used in IoT and TLS contexts.
  ///
  /// Per NIST SP 800-38C and RFC 3610, the nonce size must be between 7 and
  /// 13 bytes (default: 11 bytes). There is a trade-off between nonce size
  /// and maximum message size: `L + N = 15`, where L is the message length
  /// field size and N is the nonce size. Configurable via
  /// [AesAuthModeBuilder.nonceSize].
  ///
  /// Example:
  /// ```dart
  /// final cipher = Fortis.aes().ccm().cipher(key);
  /// ```
  ///
  /// Reference: NIST SP 800-38C.
  ccm,
}
