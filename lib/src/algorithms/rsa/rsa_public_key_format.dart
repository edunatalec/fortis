/// The serialization format for an RSA public key.
///
/// Used by [FortisRsaPublicKey.toPem] / [FortisRsaPublicKey.toDer] /
/// [FortisRsaPublicKey.fromPem] / [FortisRsaPublicKey.fromDer]. Defaults to
/// [x509] in all of them.
enum RsaPublicKeyFormat {
  /// X.509 / SubjectPublicKeyInfo format. **Default**, most widely supported.
  ///
  /// PEM header: `-----BEGIN PUBLIC KEY-----`
  ///
  /// This is the format used by OpenSSL (`openssl rsa -pubout`), Java
  /// `X509EncodedKeySpec`, .NET `ImportFromPem`, and most cloud KMS systems.
  ///
  /// Example:
  /// ```dart
  /// final pem = pair.publicKey.toPem(); // X.509 PEM
  /// final key = FortisRsaPublicKey.fromPem(pem);
  /// ```
  x509,

  /// PKCS#1 RSAPublicKey format. Raw RSA parameters without an algorithm
  /// identifier wrapper.
  ///
  /// PEM header: `-----BEGIN RSA PUBLIC KEY-----`
  ///
  /// Use only when interoperating with systems that insist on PKCS#1 (some
  /// older OpenSSL workflows, certain tools).
  ///
  /// Example:
  /// ```dart
  /// final pem = pair.publicKey.toPem(format: RsaPublicKeyFormat.pkcs1);
  /// final key = FortisRsaPublicKey.fromPem(
  ///   pem,
  ///   format: RsaPublicKeyFormat.pkcs1,
  /// );
  /// ```
  pkcs1,
}
