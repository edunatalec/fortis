/// @docImport 'package:fortis/fortis.dart';
library;

/// The serialization format for an ECDH private key.
///
/// Used by [FortisEcdhPrivateKey.toPem] / [FortisEcdhPrivateKey.toDer] and
/// the matching [FortisEcdhPrivateKey.fromPem] /
/// [FortisEcdhPrivateKey.fromDer] factories. Defaults to [pkcs8] in all
/// of them.
///
/// See also:
///
///  * [FortisEcdhPrivateKey], the key this format encodes and decodes.
///  * [EcdhPublicKeyFormat], the matching choice for the public half.
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
  /// final pair = await Fortis.ecdh().generateKeyPair();
  ///
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
  /// final pair = await Fortis.ecdh().generateKeyPair();
  ///
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
