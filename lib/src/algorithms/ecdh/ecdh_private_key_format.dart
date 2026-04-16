/// The serialization format for an ECDH private key.
///
/// Used by [FortisEcdhPrivateKey.toPem] / [FortisEcdhPrivateKey.toDer] and
/// the matching `fromPem`/`fromDer` factories. Defaults to [pkcs8] in all
/// of them.
enum EcdhPrivateKeyFormat {
  /// PKCS#8 / PrivateKeyInfo format. **Default**, most widely supported.
  ///
  /// PEM header: `-----BEGIN PRIVATE KEY-----`
  ///
  /// Matches modern OpenSSL (`openssl genpkey -algorithm EC`), Java
  /// `PKCS8EncodedKeySpec`, .NET `ImportFromPem`, and cloud KMS systems.
  ///
  /// Example:
  /// ```dart
  /// final pem = pair.privateKey.toPem(); // PKCS#8 PEM
  /// final key = FortisEcdhPrivateKey.fromPem(pem);
  /// ```
  pkcs8,

  /// SEC1 / ECPrivateKey format (RFC 5915).
  ///
  /// PEM header: `-----BEGIN EC PRIVATE KEY-----`
  ///
  /// Produced by older OpenSSL (`openssl ecparam -genkey`). Use when
  /// interoperating with tools that emit SEC1.
  ///
  /// Example:
  /// ```dart
  /// final pem = pair.privateKey.toPem(
  ///   format: EcdhPrivateKeyFormat.sec1,
  /// );
  /// final key = FortisEcdhPrivateKey.fromPem(
  ///   pem,
  ///   format: EcdhPrivateKeyFormat.sec1,
  /// );
  /// ```
  sec1,
}
