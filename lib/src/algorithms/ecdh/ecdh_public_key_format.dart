/// @docImport 'package:fortis/fortis.dart';
library;

/// The serialization format for an ECDH public key.
///
/// {@category ECDH}
///
/// Used by [FortisEcdhPublicKey.toPem] / [FortisEcdhPublicKey.toDer] and
/// the matching [FortisEcdhPublicKey.fromPem] /
/// [FortisEcdhPublicKey.fromDer] factories. Defaults to [x509] in all
/// of them.
///
/// See also:
///
///  * [FortisEcdhPublicKey], the key this format encodes and decodes.
///  * [EcdhPrivateKeyFormat], the matching choice for the private half.
///  * [EcdhCurve], which must be supplied explicitly for
///    [uncompressedPoint].
enum EcdhPublicKeyFormat {
  /// X.509 / SubjectPublicKeyInfo format. **Default**, most widely supported.
  ///
  /// PEM header: `-----BEGIN PUBLIC KEY-----`
  ///
  /// Matches OpenSSL (`openssl ec -pubout`), Java `X509EncodedKeySpec`,
  /// .NET `ImportFromPem`, JWK libraries, and WebCrypto.
  ///
  /// Example:
  /// ```dart
  /// final pair = await Fortis.ecdh().generateKeyPair();
  ///
  /// final pem = pair.publicKey.toPem();
  /// final key = FortisEcdhPublicKey.fromPem(pem);
  /// ```
  x509,

  /// Uncompressed EC point format (`0x04 || x || y`).
  ///
  /// Raw bytes only — no PEM or ASN.1 wrapper. Useful for wire protocols
  /// that send just the point (e.g. TLS, WebPush). When importing this
  /// format, you must supply the curve explicitly — the point bytes alone
  /// don't identify the curve.
  ///
  /// Example:
  /// ```dart
  /// final pair = await Fortis.ecdh().generateKeyPair();
  ///
  /// final bytes = pair.publicKey.toDer(
  ///   format: EcdhPublicKeyFormat.uncompressedPoint,
  /// );
  ///
  /// final key = FortisEcdhPublicKey.fromDer(
  ///   bytes,
  ///   format: EcdhPublicKeyFormat.uncompressedPoint,
  ///   curve: EcdhCurve.p256,
  /// );
  /// ```
  uncompressedPoint,
}
