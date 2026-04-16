/// The padding scheme for AES block modes ([AesMode.ecb], [AesMode.cbc]).
///
/// Stream modes ([AesMode.ctr], [AesMode.cfb], [AesMode.ofb]) and authenticated
/// modes ([AesMode.gcm], [AesMode.ccm]) do not use padding.
///
/// Configure via [AesCbcModeBuilder.padding] or [AesEcbModeBuilder.padding].
/// Defaults to [pkcs7] in both.
enum AesPadding {
  /// PKCS#7 padding. Standard and unambiguous. **Recommended default.**
  ///
  /// Pads with N bytes of value N, where N = `16 − (dataLength mod 16)`.
  /// When decrypting, the last byte tells the library how much to strip.
  ///
  /// Example:
  /// ```dart
  /// final cipher = Fortis.aes()
  ///     .cbc()
  ///     .padding(AesPadding.pkcs7)
  ///     .cipher(key);
  /// ```
  pkcs7,

  /// ISO 7816-4 padding. Pads with `0x80` followed by zero bytes.
  ///
  /// Useful for interop with smart-card and financial systems that follow
  /// the ISO/IEC 7816-4 standard.
  ///
  /// Example:
  /// ```dart
  /// final cipher = Fortis.aes()
  ///     .cbc()
  ///     .padding(AesPadding.iso7816)
  ///     .cipher(key);
  /// ```
  iso7816,

  /// Zero byte padding. Pads with `0x00` bytes.
  ///
  /// ⚠️ **Ambiguous** if the plaintext legitimately ends with zero bytes —
  /// the library can't tell whether trailing zeros are padding or data.
  /// Prefer [pkcs7] unless interoperability with existing systems demands
  /// this scheme.
  ///
  /// Example:
  /// ```dart
  /// final cipher = Fortis.aes()
  ///     .cbc()
  ///     .padding(AesPadding.zeroPadding)
  ///     .cipher(key);
  /// ```
  zeroPadding,

  /// No padding. Plaintext must be a multiple of 16 bytes.
  ///
  /// Throws [FortisConfigException] if the data length is not a multiple of 16.
  ///
  /// Example:
  /// ```dart
  /// final cipher = Fortis.aes()
  ///     .cbc()
  ///     .padding(AesPadding.noPadding)
  ///     .cipher(key);
  /// final ct = cipher.encrypt(Uint8List(32)); // length OK (multiple of 16)
  /// ```
  noPadding,
}
