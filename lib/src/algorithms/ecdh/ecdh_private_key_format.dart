/// The serialization format for an ECDH private key.
enum EcdhPrivateKeyFormat {
  /// PKCS#8 / PrivateKeyInfo format.
  ///
  /// PEM header: `-----BEGIN PRIVATE KEY-----`
  ///
  /// This is the most widely supported format and the default.
  pkcs8,

  /// SEC1 / ECPrivateKey format (RFC 5915).
  ///
  /// PEM header: `-----BEGIN EC PRIVATE KEY-----`
  sec1,
}
