import 'dart:convert';
import 'dart:typed_data';

import 'package:pointycastle/asn1.dart';
import 'package:pointycastle/asymmetric/api.dart';

import '../../exceptions/fortis_key_exception.dart';
import 'rsa_private_key_format.dart';

const _pkcs8Header = '-----BEGIN PRIVATE KEY-----';
const _pkcs8Footer = '-----END PRIVATE KEY-----';
const _pkcs1Header = '-----BEGIN RSA PRIVATE KEY-----';
const _pkcs1Footer = '-----END RSA PRIVATE KEY-----';

/// An RSA private key used for decryption.
///
/// Pure data container wrapping PointyCastle's [RSAPrivateKey]. Serialization
/// is available via [toPem], [toDer], and [toDerBase64]; import via
/// [fromPem], [fromDer], and [fromDerBase64]. To decrypt data, build an
/// [RsaDecrypter] via [RsaBuilder].
///
/// ⚠️ Handle with care — treat the output of [toPem] / [toDer] /
/// [toDerBase64] as a secret.
///
/// Example:
/// ```dart
/// final pair = await Fortis.rsa().generateKeyPair();
/// final pem = pair.privateKey.toPem();
/// final restored = FortisRsaPrivateKey.fromPem(pem);
/// ```
class FortisRsaPrivateKey {
  /// The underlying PointyCastle key.
  final RSAPrivateKey key;

  /// Creates a [FortisRsaPrivateKey] from a raw PointyCastle [RSAPrivateKey].
  ///
  /// You usually don't call this directly — prefer the `from*` factories or
  /// [RsaBuilder.generateKeyPair].
  const FortisRsaPrivateKey(this.key);

  /// Encodes this key as a PEM string.
  ///
  /// [format] defaults to [RsaPrivateKeyFormat.pkcs8] (PrivateKeyInfo) —
  /// the widely-supported modern default. Use [RsaPrivateKeyFormat.pkcs1]
  /// for legacy interop.
  ///
  /// Example:
  /// ```dart
  /// final pem = pair.privateKey.toPem(); // -----BEGIN PRIVATE KEY-----
  /// final pem1 = pair.privateKey.toPem(format: RsaPrivateKeyFormat.pkcs1);
  /// ```
  String toPem({RsaPrivateKeyFormat format = RsaPrivateKeyFormat.pkcs8}) {
    final der = toDer(format: format);
    final b64 = base64.encode(der);
    final wrapped = _wrapBase64(b64);
    final (header, footer) = _headers(format);
    return '$header\n$wrapped\n$footer';
  }

  /// Encodes this key as DER bytes (binary ASN.1).
  ///
  /// [format] defaults to [RsaPrivateKeyFormat.pkcs8] (PrivateKeyInfo).
  ///
  /// Example:
  /// ```dart
  /// final bytes = pair.privateKey.toDer();
  /// File('priv.der').writeAsBytesSync(bytes);
  /// ```
  Uint8List toDer({RsaPrivateKeyFormat format = RsaPrivateKeyFormat.pkcs8}) {
    return switch (format) {
      RsaPrivateKeyFormat.pkcs8 => _encodePkcs8(),
      RsaPrivateKeyFormat.pkcs1 => _encodePkcs1(),
    };
  }

  /// Exports the private key as a Base64-encoded DER string.
  ///
  /// Convenience wrapper over [toDer]. Handy for sealed storage in secret
  /// managers that accept strings. [format] defaults to
  /// [RsaPrivateKeyFormat.pkcs8].
  ///
  /// Example:
  /// ```dart
  /// final b64 = pair.privateKey.toDerBase64();
  /// secretStore.write('rsa_priv_b64', b64);
  /// ```
  String toDerBase64({
    RsaPrivateKeyFormat format = RsaPrivateKeyFormat.pkcs8,
  }) => base64Encode(toDer(format: format));

  /// Imports a private key from a PEM string.
  ///
  /// [format] must match the PEM header inside [pem]:
  /// - `-----BEGIN PRIVATE KEY-----` → [RsaPrivateKeyFormat.pkcs8] (default)
  /// - `-----BEGIN RSA PRIVATE KEY-----` → [RsaPrivateKeyFormat.pkcs1]
  ///
  /// Example:
  /// ```dart
  /// final pem = File('private.pem').readAsStringSync();
  /// final key = FortisRsaPrivateKey.fromPem(pem);
  /// ```
  ///
  /// Throws [FortisKeyException] if the PEM is malformed.
  factory FortisRsaPrivateKey.fromPem(
    String pem, {
    RsaPrivateKeyFormat format = RsaPrivateKeyFormat.pkcs8,
  }) {
    try {
      final der = ASN1Utils.getBytesFromPEMString(pem);
      return FortisRsaPrivateKey.fromDer(der, format: format);
    } catch (e) {
      if (e is FortisKeyException) rethrow;
      throw FortisKeyException('Invalid PEM for RSA private key: $e');
    }
  }

  /// Imports a private key from a Base64-encoded DER string.
  ///
  /// Convenience wrapper over [fromDer]. Input must be plain Base64 (no PEM
  /// header/footer). [format] defaults to [RsaPrivateKeyFormat.pkcs8].
  ///
  /// Example:
  /// ```dart
  /// final b64 = secretStore.read('rsa_priv_b64');
  /// final key = FortisRsaPrivateKey.fromDerBase64(b64);
  /// ```
  ///
  /// Throws [FortisKeyException] if the string is not valid Base64 or DER.
  factory FortisRsaPrivateKey.fromDerBase64(
    String base64, {
    RsaPrivateKeyFormat format = RsaPrivateKeyFormat.pkcs8,
  }) {
    try {
      return FortisRsaPrivateKey.fromDer(base64Decode(base64), format: format);
    } catch (e) {
      if (e is FortisKeyException) rethrow;
      throw FortisKeyException(
        'Invalid Base64-encoded DER for RSA private key: $e',
      );
    }
  }

  /// Imports a private key from DER bytes (binary ASN.1).
  ///
  /// [format] must match the DER structure. Defaults to
  /// [RsaPrivateKeyFormat.pkcs8].
  ///
  /// Example:
  /// ```dart
  /// final bytes = File('priv.der').readAsBytesSync();
  /// final key = FortisRsaPrivateKey.fromDer(bytes);
  /// ```
  ///
  /// Throws [FortisKeyException] if the DER is malformed.
  factory FortisRsaPrivateKey.fromDer(
    Uint8List der, {
    RsaPrivateKeyFormat format = RsaPrivateKeyFormat.pkcs8,
  }) {
    try {
      return switch (format) {
        RsaPrivateKeyFormat.pkcs8 => _decodePkcs8(der),
        RsaPrivateKeyFormat.pkcs1 => _decodePkcs1(der),
      };
    } catch (e) {
      if (e is FortisKeyException) rethrow;
      throw FortisKeyException('Invalid DER for RSA private key ($format): $e');
    }
  }

  Uint8List _encodePkcs1() {
    final n = key.modulus!;
    final e = key.publicExponent!;
    final d = key.privateExponent!;
    final p = key.p!;
    final q = key.q!;
    final dp = d.remainder(p - BigInt.one);
    final dq = d.remainder(q - BigInt.one);
    final qp = q.modInverse(p);

    return ASN1Sequence(
      elements: [
        ASN1Integer.fromtInt(0), // version
        ASN1Integer(n),
        ASN1Integer(e),
        ASN1Integer(d),
        ASN1Integer(p),
        ASN1Integer(q),
        ASN1Integer(dp),
        ASN1Integer(dq),
        ASN1Integer(qp),
      ],
    ).encode();
  }

  Uint8List _encodePkcs8() {
    final pkcs1Der = _encodePkcs1();
    final algorithmId = ASN1AlgorithmIdentifier.fromIdentifier(
      '1.2.840.113549.1.1.1',
      parameters: ASN1Null(),
    );
    final privateKeyInfo = ASN1PrivateKeyInfo(
      ASN1Integer.fromtInt(0),
      algorithmId,
      ASN1OctetString(octets: pkcs1Der),
    );
    return privateKeyInfo.encode();
  }

  static FortisRsaPrivateKey _decodePkcs1(Uint8List der) {
    final parser = ASN1Parser(der);
    final seq = parser.nextObject() as ASN1Sequence;
    // version is seq.elements![0], skip it
    final n = (seq.elements![1] as ASN1Integer).integer!;
    // e is seq.elements![2], not needed for RSAPrivateKey construction
    final d = (seq.elements![3] as ASN1Integer).integer!;
    final p = (seq.elements![4] as ASN1Integer).integer!;
    final q = (seq.elements![5] as ASN1Integer).integer!;
    return FortisRsaPrivateKey(RSAPrivateKey(n, d, p, q));
  }

  static FortisRsaPrivateKey _decodePkcs8(Uint8List der) {
    final parser = ASN1Parser(der);
    final seq = parser.nextObject() as ASN1Sequence;
    // PKCS#8: SEQUENCE { version, AlgorithmIdentifier, OCTET STRING { pkcs1 } }
    final octetString = seq.elements![2] as ASN1OctetString;
    final pkcs1Der = octetString.octets!;
    return _decodePkcs1(pkcs1Der);
  }

  static (String, String) _headers(RsaPrivateKeyFormat format) =>
      switch (format) {
        RsaPrivateKeyFormat.pkcs8 => (_pkcs8Header, _pkcs8Footer),
        RsaPrivateKeyFormat.pkcs1 => (_pkcs1Header, _pkcs1Footer),
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
