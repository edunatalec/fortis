/// The padding scheme for AES block modes (ECB, CBC).
///
/// Only applicable when using [AesMode.ecb] or [AesMode.cbc].
/// Stream modes and authenticated modes do not use padding.
enum AesPadding {
  /// PKCS#7 padding. Standard and unambiguous. **Recommended default.**
  pkcs7,

  /// ISO 7816-4 padding. Pads with `0x80` followed by zero bytes.
  iso7816,

  /// Zero byte padding. Pads with `0x00` bytes.
  ///
  /// ⚠️ **Ambiguous** if the plaintext legitimately ends with zero bytes.
  /// Prefer [pkcs7] unless interoperability with existing systems requires this.
  zeroPadding,

  /// No padding. Plaintext must be a multiple of 16 bytes.
  ///
  /// Throws [FortisEncryptionException] if the data length is not a multiple of 16.
  noPadding,
}
