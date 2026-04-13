/// The elliptic curve used for ECDH key agreement.
enum EcdhCurve {
  /// NIST P-256 (secp256r1). 128-bit security level.
  p256,

  /// NIST P-384 (secp384r1). 192-bit security level.
  p384,

  /// NIST P-521 (secp521r1). 256-bit security level.
  p521;

  /// Returns the PointyCastle domain name for this curve.
  String get domainName => switch (this) {
    p256 => 'secp256r1',
    p384 => 'secp384r1',
    p521 => 'secp521r1',
  };

  /// Returns the field size in bytes for this curve.
  int get fieldSizeBytes => switch (this) {
    p256 => 32,
    p384 => 48,
    p521 => 66,
  };

  /// Returns the ASN.1 OID for this curve.
  String get oid => switch (this) {
    p256 => '1.2.840.10045.3.1.7',
    p384 => '1.3.132.0.34',
    p521 => '1.3.132.0.35',
  };

  /// Resolves an OID string to an [EcdhCurve], or `null` if not recognized.
  static EcdhCurve? fromOid(String oid) => switch (oid) {
    '1.2.840.10045.3.1.7' => p256,
    '1.3.132.0.34' => p384,
    '1.3.132.0.35' => p521,
    _ => null,
  };
}
