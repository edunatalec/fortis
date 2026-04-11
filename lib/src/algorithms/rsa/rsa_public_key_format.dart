/// The serialization format for an RSA public key.
enum RsaPublicKeyFormat {
  /// X.509 / SubjectPublicKeyInfo format.
  ///
  /// PEM header: `-----BEGIN PUBLIC KEY-----`
  ///
  /// This is the most widely supported format and the default.
  x509,

  /// PKCS#1 RSAPublicKey format.
  ///
  /// PEM header: `-----BEGIN RSA PUBLIC KEY-----`
  pkcs1,
}
