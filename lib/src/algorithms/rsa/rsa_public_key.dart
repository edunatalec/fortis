import 'dart:convert';
import 'dart:typed_data';

import 'package:pointycastle/asn1.dart';
import 'package:pointycastle/asymmetric/api.dart';

import '../../exceptions/fortis_key_exception.dart';
import 'rsa_public_key_format.dart';

const _x509Header = '-----BEGIN PUBLIC KEY-----';
const _x509Footer = '-----END PUBLIC KEY-----';
const _pkcs1Header = '-----BEGIN RSA PUBLIC KEY-----';
const _pkcs1Footer = '-----END RSA PUBLIC KEY-----';

/// An RSA public key used for encryption.
///
/// Pure data container wrapping PointyCastle's [RSAPublicKey]. Serialization
/// is available via [toPem], [toDer], and [toDerBase64]; import via
/// [fromPem], [fromDer], and [fromDerBase64]. To encrypt data, build an
/// [RsaEncrypter] via [RsaBuilder].
///
/// Example:
/// ```dart
/// final pair = await Fortis.rsa().generateKeyPair();
/// final pem = pair.publicKey.toPem();
/// final restored = FortisRsaPublicKey.fromPem(pem);
/// ```
class FortisRsaPublicKey {
  /// The underlying PointyCastle key.
  final RSAPublicKey key;

  /// Creates a [FortisRsaPublicKey] from a raw PointyCastle [RSAPublicKey].
  ///
  /// You usually don't call this directly — prefer [FortisRsaPublicKey.fromPem],
  /// [FortisRsaPublicKey.fromDer], [FortisRsaPublicKey.fromDerBase64], or
  /// [RsaBuilder.generateKeyPair].
  const FortisRsaPublicKey(this.key);

  /// Encodes this key as a PEM string.
  ///
  /// [format] defaults to [RsaPublicKeyFormat.x509] (SubjectPublicKeyInfo) —
  /// the widely-supported default. Use [RsaPublicKeyFormat.pkcs1] for raw
  /// PKCS#1 interop.
  ///
  /// Example:
  /// ```dart
  /// final pem = pair.publicKey.toPem(); // -----BEGIN PUBLIC KEY-----
  /// final pem1 = pair.publicKey.toPem(format: RsaPublicKeyFormat.pkcs1);
  /// ```
  String toPem({RsaPublicKeyFormat format = RsaPublicKeyFormat.x509}) {
    final der = toDer(format: format);
    final b64 = base64.encode(der);
    final wrapped = _wrapBase64(b64);
    final (header, footer) = _headers(format);
    return '$header\n$wrapped\n$footer';
  }

  /// Encodes this key as DER bytes (binary ASN.1).
  ///
  /// [format] defaults to [RsaPublicKeyFormat.x509] (SubjectPublicKeyInfo).
  ///
  /// Example:
  /// ```dart
  /// final bytes = pair.publicKey.toDer(); // Uint8List, X.509 DER
  /// File('pub.der').writeAsBytesSync(bytes);
  /// ```
  Uint8List toDer({RsaPublicKeyFormat format = RsaPublicKeyFormat.x509}) {
    return switch (format) {
      RsaPublicKeyFormat.x509 => _encodeX509(),
      RsaPublicKeyFormat.pkcs1 => _encodePkcs1(),
    };
  }

  /// Exports the public key as a Base64-encoded DER string.
  ///
  /// Convenience wrapper over [toDer] — handy for JSON/HTTP transport
  /// without the PEM header/footer lines.
  ///
  /// [format] defaults to [RsaPublicKeyFormat.x509] (SubjectPublicKeyInfo).
  ///
  /// Example:
  /// ```dart
  /// final b64 = pair.publicKey.toDerBase64();
  /// sendJson({'rsa_pub_b64': b64});
  /// ```
  String toDerBase64({RsaPublicKeyFormat format = RsaPublicKeyFormat.x509}) =>
      base64Encode(toDer(format: format));

  /// Imports a public key from a PEM string.
  ///
  /// [format] must match the PEM header inside [pem]:
  /// - `-----BEGIN PUBLIC KEY-----` → [RsaPublicKeyFormat.x509] (default)
  /// - `-----BEGIN RSA PUBLIC KEY-----` → [RsaPublicKeyFormat.pkcs1]
  ///
  /// Example:
  /// ```dart
  /// final pem = File('public.pem').readAsStringSync();
  /// final key = FortisRsaPublicKey.fromPem(pem);
  /// ```
  ///
  /// Throws [FortisKeyException] if the PEM is malformed.
  factory FortisRsaPublicKey.fromPem(
    String pem, {
    RsaPublicKeyFormat format = RsaPublicKeyFormat.x509,
  }) {
    try {
      final der = ASN1Utils.getBytesFromPEMString(pem);

      return FortisRsaPublicKey.fromDer(der, format: format);
    } catch (e) {
      if (e is FortisKeyException) rethrow;

      throw FortisKeyException('Invalid PEM for RSA public key: $e');
    }
  }

  /// Imports a public key from a Base64-encoded DER string.
  ///
  /// Convenience wrapper over [fromDer]. The input must be a plain Base64
  /// string (no PEM header/footer). [format] defaults to
  /// [RsaPublicKeyFormat.x509].
  ///
  /// Example:
  /// ```dart
  /// final b64 = json['rsa_pub_b64'] as String;
  /// final key = FortisRsaPublicKey.fromDerBase64(b64);
  /// ```
  ///
  /// Throws [FortisKeyException] if the string is not valid Base64 or DER.
  factory FortisRsaPublicKey.fromDerBase64(
    String base64, {
    RsaPublicKeyFormat format = RsaPublicKeyFormat.x509,
  }) {
    try {
      return FortisRsaPublicKey.fromDer(base64Decode(base64), format: format);
    } catch (e) {
      if (e is FortisKeyException) rethrow;

      throw FortisKeyException(
        'Invalid Base64-encoded DER for RSA public key: $e',
      );
    }
  }

  /// Imports a public key from DER bytes (binary ASN.1).
  ///
  /// [format] must match the DER structure. Defaults to
  /// [RsaPublicKeyFormat.x509].
  ///
  /// Example:
  /// ```dart
  /// final bytes = File('pub.der').readAsBytesSync();
  /// final key = FortisRsaPublicKey.fromDer(bytes);
  /// ```
  ///
  /// Throws [FortisKeyException] if the DER is malformed.
  factory FortisRsaPublicKey.fromDer(
    Uint8List der, {
    RsaPublicKeyFormat format = RsaPublicKeyFormat.x509,
  }) {
    try {
      return switch (format) {
        RsaPublicKeyFormat.x509 => _decodeX509(der),
        RsaPublicKeyFormat.pkcs1 => _decodePkcs1(der),
      };
    } catch (e) {
      if (e is FortisKeyException) rethrow;
      throw FortisKeyException('Invalid DER for RSA public key ($format): $e');
    }
  }

  Uint8List _encodeX509() {
    final rsaSeq = ASN1Sequence(
      elements: [ASN1Integer(key.modulus), ASN1Integer(key.publicExponent)],
    );

    final algorithmId = ASN1AlgorithmIdentifier.fromIdentifier(
      '1.2.840.113549.1.1.1',
      parameters: ASN1Null(),
    );

    final spki = ASN1SubjectPublicKeyInfo(
      algorithmId,
      ASN1BitString(stringValues: rsaSeq.encode()),
    );

    return spki.encode();
  }

  Uint8List _encodePkcs1() {
    return ASN1Sequence(
      elements: [ASN1Integer(key.modulus), ASN1Integer(key.publicExponent)],
    ).encode();
  }

  static FortisRsaPublicKey _decodeX509(Uint8List der) {
    final parser = ASN1Parser(der);
    final seq = parser.nextObject() as ASN1Sequence;
    final spki = ASN1SubjectPublicKeyInfo.fromSequence(seq);

    final bitStringBytes = Uint8List.fromList(
      spki.subjectPublicKey.stringValues!,
    );

    return _decodePkcs1(bitStringBytes);
  }

  static FortisRsaPublicKey _decodePkcs1(Uint8List der) {
    final parser = ASN1Parser(der);
    final seq = parser.nextObject() as ASN1Sequence;
    final n = (seq.elements![0] as ASN1Integer).integer!;
    final e = (seq.elements![1] as ASN1Integer).integer!;

    return FortisRsaPublicKey(RSAPublicKey(n, e));
  }

  static (String, String) _headers(RsaPublicKeyFormat format) =>
      switch (format) {
        RsaPublicKeyFormat.x509 => (_x509Header, _x509Footer),
        RsaPublicKeyFormat.pkcs1 => (_pkcs1Header, _pkcs1Footer),
      };
}

/// Wraps a base64 string with line breaks every 64 characters.
String _wrapBase64(String b64) {
  final buf = StringBuffer();

  for (var i = 0; i < b64.length; i += 64) {
    buf.writeln(b64.substring(i, i + 64 > b64.length ? b64.length : i + 64));
  }

  return buf.toString().trimRight();
}
