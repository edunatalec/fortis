/// The elliptic curve used for ECDH key agreement.
///
/// Passed to [EcdhBuilder.curve]. Defaults to [p256].
///
/// Selection guide:
///
/// | Curve  | Security | Typical use                                |
/// |--------|----------|--------------------------------------------|
/// | [p256] | 128-bit  | **Default**. TLS, WebCrypto, mobile.       |
/// | [p384] | 192-bit  | Regulated or long-lived secrets.           |
/// | [p521] | 256-bit  | Maximum security; slower.                  |
enum EcdhCurve {
  /// NIST P-256 (secp256r1). 128-bit security level. **Default**.
  ///
  /// The most widely deployed curve — used by TLS, JWK, WebCrypto, and most
  /// cloud KMS systems.
  ///
  /// Example:
  /// ```dart
  /// final pair = await Fortis.ecdh().curve(EcdhCurve.p256).generateKeyPair();
  /// ```
  p256,

  /// NIST P-384 (secp384r1). 192-bit security level.
  ///
  /// Recommended for regulated environments (CNSA Suite, NSA Suite B) and
  /// long-lived secrets.
  ///
  /// Example:
  /// ```dart
  /// final pair = await Fortis.ecdh().curve(EcdhCurve.p384).generateKeyPair();
  /// ```
  p384,

  /// NIST P-521 (secp521r1). 256-bit security level.
  ///
  /// Highest security among the NIST curves; also the slowest. Field size
  /// is 521 bits (not 512) — the padding in encoded points reflects this.
  ///
  /// Example:
  /// ```dart
  /// final pair = await Fortis.ecdh().curve(EcdhCurve.p521).generateKeyPair();
  /// ```
  p521;

  /// The PointyCastle domain name for this curve.
  ///
  /// `secp256r1`, `secp384r1`, or `secp521r1`.
  String get domainName => switch (this) {
    p256 => 'secp256r1',
    p384 => 'secp384r1',
    p521 => 'secp521r1',
  };

  /// The field size in bytes for this curve.
  ///
  /// Used to left-pad the encoded shared secret. P-256 → 32, P-384 → 48,
  /// P-521 → 66.
  int get fieldSizeBytes => switch (this) {
    p256 => 32,
    p384 => 48,
    p521 => 66,
  };

  /// The ASN.1 OID that identifies this curve in X.509 / PKCS#8 structures.
  String get oid => switch (this) {
    p256 => '1.2.840.10045.3.1.7',
    p384 => '1.3.132.0.34',
    p521 => '1.3.132.0.35',
  };

  /// Resolves an OID string to an [EcdhCurve], or `null` if not recognized.
  ///
  /// Used internally when decoding X.509 / PKCS#8 keys.
  ///
  /// Example:
  /// ```dart
  /// final curve = EcdhCurve.fromOid('1.2.840.10045.3.1.7'); // EcdhCurve.p256
  /// ```
  static EcdhCurve? fromOid(String oid) => switch (oid) {
    '1.2.840.10045.3.1.7' => p256,
    '1.3.132.0.34' => p384,
    '1.3.132.0.35' => p521,
    _ => null,
  };
}
