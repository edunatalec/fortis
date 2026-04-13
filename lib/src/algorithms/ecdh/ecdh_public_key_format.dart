/// The serialization format for an ECDH public key.
enum EcdhPublicKeyFormat {
  /// X.509 / SubjectPublicKeyInfo format.
  ///
  /// PEM header: `-----BEGIN PUBLIC KEY-----`
  ///
  /// This is the most widely supported format and the default.
  x509,

  /// Uncompressed EC point format (0x04 || x || y).
  ///
  /// Raw bytes only — no PEM or ASN.1 wrapper.
  uncompressedPoint,
}
