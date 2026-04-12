// ignore_for_file: constant_identifier_names

/// The AES cipher mode of operation.
enum AesMode {
  /// Electronic Code Book mode.
  ///
  /// ⚠️ **Insecure for most use cases.** Identical plaintext blocks produce
  /// identical ciphertext blocks, revealing patterns in the data. Only use
  /// for legacy interoperability. Prefer [gcm] in new designs.
  ///
  /// ECB does not use an IV or nonce.
  ///
  /// Reference: NIST SP 800-38A.
  ecb,

  /// Cipher Block Chaining mode.
  ///
  /// Requires a 16-byte initialization vector (IV). Uses configurable padding.
  /// The IV must be unpredictable (random) for each encryption operation.
  ///
  /// Reference: NIST SP 800-38A.
  cbc,

  /// Counter mode.
  ///
  /// Requires a 16-byte initialization vector (IV). No padding required (stream mode).
  /// The IV must be unique for each encryption operation with the same key.
  ///
  /// Reference: NIST SP 800-38A.
  ctr,

  /// Galois/Counter Mode. Provides authenticated encryption (AEAD).
  ///
  /// ✅ **Recommended default** for most use cases.
  ///
  /// Requires an initialization vector (IV). Per NIST SP 800-38D, the IV in GCM
  /// is essentially a nonce (a value that must be unique per encryption under
  /// the same key). The recommended IV size is 96 bits (12 bytes).
  /// The IV size is configurable via [AesAuthModeBuilder.nonceSize].
  ///
  /// Reference: NIST SP 800-38D.
  gcm,

  /// Cipher Feedback mode.
  ///
  /// Requires a 16-byte initialization vector (IV). No padding required (stream mode).
  /// The IV must be unpredictable (random) for each encryption operation.
  ///
  /// Reference: NIST SP 800-38A.
  cfb,

  /// Output Feedback mode.
  ///
  /// Requires a 16-byte initialization vector (IV). No padding required (stream mode).
  /// The IV must be unique for each encryption operation with the same key.
  ///
  /// Reference: NIST SP 800-38A.
  ofb,

  /// Counter with CBC-MAC mode. Provides authenticated encryption (AEAD).
  ///
  /// Commonly used in IoT and TLS contexts.
  ///
  /// Requires a nonce. Per NIST SP 800-38C and RFC 3610, the nonce size must
  /// be between 7 and 13 bytes (default: 11 bytes). There is a trade-off
  /// between nonce size and maximum message size: L + N = 15, where L is
  /// the message length field size and N is the nonce size.
  /// The nonce size is configurable via [AesAuthModeBuilder.nonceSize].
  ///
  /// Reference: NIST SP 800-38C.
  ccm,
}
