/// The serialization format for an RSA private key.
///
/// Used by [FortisRsaPrivateKey.toPem] / [FortisRsaPrivateKey.toDer] /
/// [FortisRsaPrivateKey.fromPem] / [FortisRsaPrivateKey.fromDer]. Defaults
/// to [pkcs8] in all of them.
enum RsaPrivateKeyFormat {
  /// PKCS#8 / PrivateKeyInfo format. **Default**, most widely supported.
  ///
  /// PEM header: `-----BEGIN PRIVATE KEY-----`
  ///
  /// Matches Java `PKCS8EncodedKeySpec`, .NET `ImportFromPem`, modern
  /// OpenSSL (`openssl genpkey`), and cloud KMS systems.
  ///
  /// Example:
  /// ```dart
  /// final pem = pair.privateKey.toPem(); // PKCS#8 PEM
  /// final key = FortisRsaPrivateKey.fromPem(pem);
  /// ```
  pkcs8,

  /// PKCS#1 RSAPrivateKey format. Raw RSA parameters without an algorithm
  /// identifier wrapper.
  ///
  /// PEM header: `-----BEGIN RSA PRIVATE KEY-----`
  ///
  /// Common in older OpenSSL output (`openssl genrsa`). Use only when
  /// interoperating with systems that require PKCS#1.
  ///
  /// Example:
  /// ```dart
  /// final pem = pair.privateKey.toPem(format: RsaPrivateKeyFormat.pkcs1);
  /// final key = FortisRsaPrivateKey.fromPem(
  ///   pem,
  ///   format: RsaPrivateKeyFormat.pkcs1,
  /// );
  /// ```
  pkcs1,
}
