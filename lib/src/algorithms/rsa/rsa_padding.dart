// ignore_for_file: constant_identifier_names

/// The RSA padding scheme to use for encryption and decryption.
enum RsaPadding {
  /// PKCS#1 v1.5 padding. Legacy; still widely supported.
  pkcs1_v1_5,

  /// OAEP v1 — SHA-1 based, MGF1. Deprecated in favor of OAEP v2+.
  oaep_v1,

  /// OAEP v2.0 — configurable hash and MGF1 (RFC 2437).
  oaep_v2,

  /// OAEP v2.1 — configurable hash, MGF1, and label support (RFC 3447 / RFC 8017).
  ///
  /// To provide a label, pass it to [RsaEncrypter.encrypt] or [RsaDecrypter.decrypt]
  /// as either a [String] or a [Uint8List].
  oaep_v2_1,
}
