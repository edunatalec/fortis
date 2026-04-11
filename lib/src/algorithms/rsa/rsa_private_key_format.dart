/// The serialization format for an RSA private key.
enum RsaPrivateKeyFormat {
  /// PKCS#8 / PrivateKeyInfo format.
  ///
  /// PEM header: `-----BEGIN PRIVATE KEY-----`
  ///
  /// This is the most widely supported format and the default.
  pkcs8,

  /// PKCS#1 RSAPrivateKey format.
  ///
  /// PEM header: `-----BEGIN RSA PRIVATE KEY-----`
  pkcs1,
}
