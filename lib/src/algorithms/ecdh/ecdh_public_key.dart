import 'dart:convert';
import 'dart:typed_data';

import 'package:pointycastle/asn1.dart';
import 'package:pointycastle/ecc/api.dart';

import '../../exceptions/fortis_key_exception.dart';
import 'ecdh_curve.dart';
import 'ecdh_public_key_format.dart';

const _x509Header = '-----BEGIN PUBLIC KEY-----';
const _x509Footer = '-----END PUBLIC KEY-----';

/// OID for id-ecPublicKey (1.2.840.10045.2.1).
const _ecPublicKeyOid = '1.2.840.10045.2.1';

/// An ECDH public key used for key agreement.
///
/// Pure data container wrapping PointyCastle's [ECPublicKey]. Serialization
/// is available via [toPem], [toDer], and [toDerBase64]. To derive a shared
/// key, build an [EcdhKeyDerivation] via [EcdhBuilder].
///
/// Example:
/// ```dart
/// final pair = await Fortis.ecdh().generateKeyPair();
/// final pem = pair.publicKey.toPem();
/// final restored = FortisEcdhPublicKey.fromPem(pem);
/// ```
class FortisEcdhPublicKey {
  /// The underlying PointyCastle key.
  final ECPublicKey key;

  /// The curve this key belongs to.
  final EcdhCurve curve;

  /// Creates a [FortisEcdhPublicKey] from a raw PointyCastle [ECPublicKey]
  /// plus the [curve] it belongs to.
  ///
  /// You usually don't call this directly — prefer the `from*` factories or
  /// [EcdhBuilder.generateKeyPair].
  const FortisEcdhPublicKey(this.key, this.curve);

  /// Encodes this key as a PEM string.
  ///
  /// Only [EcdhPublicKeyFormat.x509] supports PEM encoding — raw
  /// uncompressed points have no PEM representation.
  ///
  /// Example:
  /// ```dart
  /// final pem = pair.publicKey.toPem(); // -----BEGIN PUBLIC KEY-----
  /// ```
  ///
  /// Throws [FortisKeyException] if [format] is
  /// [EcdhPublicKeyFormat.uncompressedPoint].
  String toPem({EcdhPublicKeyFormat format = EcdhPublicKeyFormat.x509}) {
    if (format == EcdhPublicKeyFormat.uncompressedPoint) {
      throw FortisKeyException(
        'Uncompressed point format does not support PEM encoding.',
      );
    }

    final der = toDer(format: format);
    final b64 = base64.encode(der);
    final wrapped = _wrapBase64(b64);
    return '$_x509Header\n$wrapped\n$_x509Footer';
  }

  /// Encodes this key as DER bytes (binary).
  ///
  /// [format] defaults to [EcdhPublicKeyFormat.x509] (SubjectPublicKeyInfo).
  /// Use [EcdhPublicKeyFormat.uncompressedPoint] to get just the raw
  /// `0x04 || x || y` bytes — common in wire protocols like WebPush.
  ///
  /// Example:
  /// ```dart
  /// final der = pair.publicKey.toDer(); // X.509 DER
  /// final raw = pair.publicKey.toDer(
  ///   format: EcdhPublicKeyFormat.uncompressedPoint,
  /// );
  /// ```
  Uint8List toDer({EcdhPublicKeyFormat format = EcdhPublicKeyFormat.x509}) {
    return switch (format) {
      EcdhPublicKeyFormat.x509 => _encodeX509(),
      EcdhPublicKeyFormat.uncompressedPoint => _encodeUncompressedPoint(),
    };
  }

  /// Exports the public key as a Base64-encoded DER string.
  ///
  /// Convenience wrapper over [toDer]. [format] defaults to
  /// [EcdhPublicKeyFormat.x509].
  ///
  /// Example:
  /// ```dart
  /// final b64 = pair.publicKey.toDerBase64();
  /// sendJson({'ecdh_pub_b64': b64});
  /// ```
  String toDerBase64({EcdhPublicKeyFormat format = EcdhPublicKeyFormat.x509}) =>
      base64Encode(toDer(format: format));

  /// Imports a public key from a PEM string.
  ///
  /// Only [EcdhPublicKeyFormat.x509] supports PEM (header:
  /// `-----BEGIN PUBLIC KEY-----`).
  ///
  /// Example:
  /// ```dart
  /// final pem = File('ecdh_pub.pem').readAsStringSync();
  /// final key = FortisEcdhPublicKey.fromPem(pem);
  /// ```
  ///
  /// Throws [FortisKeyException] if the PEM is malformed.
  factory FortisEcdhPublicKey.fromPem(
    String pem, {
    EcdhPublicKeyFormat format = EcdhPublicKeyFormat.x509,
  }) {
    try {
      final der = ASN1Utils.getBytesFromPEMString(pem);
      return FortisEcdhPublicKey.fromDer(der, format: format);
    } catch (e) {
      if (e is FortisKeyException) rethrow;
      throw FortisKeyException('Invalid PEM for ECDH public key: $e');
    }
  }

  /// Imports a public key from a Base64-encoded DER string.
  ///
  /// [format] defaults to [EcdhPublicKeyFormat.x509]. [curve] is required
  /// when [format] is [EcdhPublicKeyFormat.uncompressedPoint] (raw points
  /// carry no curve information).
  ///
  /// Example:
  /// ```dart
  /// final key = FortisEcdhPublicKey.fromDerBase64(b64); // X.509
  ///
  /// final key2 = FortisEcdhPublicKey.fromDerBase64(
  ///   rawB64,
  ///   format: EcdhPublicKeyFormat.uncompressedPoint,
  ///   curve: EcdhCurve.p256,
  /// );
  /// ```
  ///
  /// Throws [FortisKeyException] if the string is not valid Base64 or DER.
  factory FortisEcdhPublicKey.fromDerBase64(
    String base64String, {
    EcdhPublicKeyFormat format = EcdhPublicKeyFormat.x509,
    EcdhCurve? curve,
  }) {
    try {
      return FortisEcdhPublicKey.fromDer(
        base64Decode(base64String),
        format: format,
        curve: curve,
      );
    } catch (e) {
      if (e is FortisKeyException) rethrow;
      throw FortisKeyException(
        'Invalid Base64-encoded DER for ECDH public key: $e',
      );
    }
  }

  /// Imports a public key from DER bytes (binary).
  ///
  /// [format] defaults to [EcdhPublicKeyFormat.x509]. [curve] is required
  /// when [format] is [EcdhPublicKeyFormat.uncompressedPoint] — the raw
  /// `0x04 || x || y` bytes don't identify the curve on their own.
  ///
  /// Example:
  /// ```dart
  /// final key = FortisEcdhPublicKey.fromDer(der); // X.509
  ///
  /// final key2 = FortisEcdhPublicKey.fromDer(
  ///   rawBytes,
  ///   format: EcdhPublicKeyFormat.uncompressedPoint,
  ///   curve: EcdhCurve.p256,
  /// );
  /// ```
  ///
  /// Throws [FortisKeyException] if the DER is malformed or [curve] is
  /// missing for uncompressed point format.
  factory FortisEcdhPublicKey.fromDer(
    Uint8List der, {
    EcdhPublicKeyFormat format = EcdhPublicKeyFormat.x509,
    EcdhCurve? curve,
  }) {
    try {
      return switch (format) {
        EcdhPublicKeyFormat.x509 => _decodeX509(der),
        EcdhPublicKeyFormat.uncompressedPoint => _decodeUncompressedPoint(
          der,
          curve,
        ),
      };
    } catch (e) {
      if (e is FortisKeyException) rethrow;
      throw FortisKeyException('Invalid DER for ECDH public key ($format): $e');
    }
  }

  Uint8List _encodeX509() {
    final algorithmId = ASN1Sequence(
      elements: [
        ASN1ObjectIdentifier.fromIdentifierString(_ecPublicKeyOid),
        ASN1ObjectIdentifier.fromIdentifierString(curve.oid),
      ],
    );

    final uncompressedPoint = key.Q!.getEncoded(false);

    final spki = ASN1Sequence(
      elements: [
        algorithmId,
        ASN1BitString(stringValues: uncompressedPoint),
      ],
    );

    return spki.encode();
  }

  Uint8List _encodeUncompressedPoint() {
    return Uint8List.fromList(key.Q!.getEncoded(false));
  }

  static FortisEcdhPublicKey _decodeX509(Uint8List der) {
    final parser = ASN1Parser(der);
    final seq = parser.nextObject() as ASN1Sequence;

    final algorithmSeq = seq.elements![0] as ASN1Sequence;
    final curveOid = (algorithmSeq.elements![1] as ASN1ObjectIdentifier)
        .objectIdentifierAsString!;

    final curve = EcdhCurve.fromOid(curveOid);
    if (curve == null) {
      throw FortisKeyException('Unsupported EC curve OID: $curveOid');
    }

    final bitString = seq.elements![1] as ASN1BitString;
    final pointBytes = Uint8List.fromList(bitString.stringValues!);

    final domainParams = ECDomainParameters(curve.domainName);
    final point = domainParams.curve.decodePoint(pointBytes);
    if (point == null) {
      throw FortisKeyException('Failed to decode EC point from X.509 key.');
    }

    return FortisEcdhPublicKey(ECPublicKey(point, domainParams), curve);
  }

  static FortisEcdhPublicKey _decodeUncompressedPoint(
    Uint8List bytes,
    EcdhCurve? curve,
  ) {
    if (curve == null) {
      throw FortisKeyException(
        'curve is required when importing from uncompressed point format.',
      );
    }

    final domainParams = ECDomainParameters(curve.domainName);
    final point = domainParams.curve.decodePoint(bytes);
    if (point == null) {
      throw FortisKeyException('Failed to decode EC point from raw bytes.');
    }

    return FortisEcdhPublicKey(ECPublicKey(point, domainParams), curve);
  }
}

/// Wraps a base64 string with line breaks every 64 characters.
String _wrapBase64(String b64) {
  final buf = StringBuffer();

  for (var i = 0; i < b64.length; i += 64) {
    buf.writeln(b64.substring(i, i + 64 > b64.length ? b64.length : i + 64));
  }

  return buf.toString().trimRight();
}
