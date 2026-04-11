// ignore_for_file: constant_identifier_names

/// The AES cipher mode of operation.
enum AesMode {
  /// Electronic Code Book mode.
  ///
  /// ⚠️ **Insecure for most use cases.** Identical plaintext blocks produce
  /// identical ciphertext blocks, revealing patterns in the data. Supported
  /// for interoperability only. Prefer [gcm] in new designs.
  ecb,

  /// Cipher Block Chaining mode. Requires an IV. Uses configurable padding.
  cbc,

  /// Counter mode. Requires an IV. No padding needed (stream mode).
  ctr,

  /// Galois/Counter Mode. Requires an IV. Provides authenticated encryption.
  ///
  /// **Recommended default** for most use cases.
  gcm,

  /// Cipher Feedback mode. Requires an IV. No user-configurable padding.
  cfb,

  /// Output Feedback mode. Requires an IV. No user-configurable padding.
  ofb,

  /// Counter with CBC-MAC. Requires a nonce. Provides authenticated encryption.
  ///
  /// Commonly used in IoT and TLS contexts.
  ccm,
}
