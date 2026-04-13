import 'dart:convert';
import 'dart:typed_data';

import 'package:pointycastle/asn1.dart';
import 'package:pointycastle/ecc/api.dart';

import '../../exceptions/fortis_key_exception.dart';
import 'ecdh_curve.dart';
import 'ecdh_private_key_format.dart';

const _pkcs8Header = '-----BEGIN PRIVATE KEY-----';
const _pkcs8Footer = '-----END PRIVATE KEY-----';
const _sec1Header = '-----BEGIN EC PRIVATE KEY-----';
const _sec1Footer = '-----END EC PRIVATE KEY-----';

/// OID for id-ecPublicKey (1.2.840.10045.2.1).
const _ecPublicKeyOid = '1.2.840.10045.2.1';

/// An ECDH private key used for key agreement.
///
/// This is a pure data container wrapping PointyCastle's [ECPrivateKey].
/// Serialization is available via [toPem] / [toDer].
/// To perform key agreement, build an [EcdhKeyDerivation] via [EcdhBuilder].
class FortisEcdhPrivateKey {
  /// The underlying PointyCastle key.
  final ECPrivateKey key;

  /// The curve this key belongs to.
  final EcdhCurve curve;

  /// Creates a [FortisEcdhPrivateKey] from the given PointyCastle [key]
  /// and [curve].
  const FortisEcdhPrivateKey(this.key, this.curve);

  // ---------------------------------------------------------------------------
  // Serialization
  // ---------------------------------------------------------------------------

  /// Encodes this key as a PEM string.
  ///
  /// [format] defaults to [EcdhPrivateKeyFormat.pkcs8] (PrivateKeyInfo).
  String toPem({EcdhPrivateKeyFormat format = EcdhPrivateKeyFormat.pkcs8}) {
    final der = toDer(format: format);
    final b64 = base64.encode(der);
    final wrapped = _wrapBase64(b64);
    final (header, footer) = _headers(format);
    return '$header\n$wrapped\n$footer';
  }

  /// Encodes this key as DER bytes.
  ///
  /// [format] defaults to [EcdhPrivateKeyFormat.pkcs8] (PrivateKeyInfo).
  Uint8List toDer({EcdhPrivateKeyFormat format = EcdhPrivateKeyFormat.pkcs8}) {
    return switch (format) {
      EcdhPrivateKeyFormat.pkcs8 => _encodePkcs8(),
      EcdhPrivateKeyFormat.sec1 => _encodeSec1(),
    };
  }

  /// Exports the private key as a Base64-encoded DER string.
  ///
  /// [format] defaults to [EcdhPrivateKeyFormat.pkcs8] (PrivateKeyInfo).
  String toDerBase64({
    EcdhPrivateKeyFormat format = EcdhPrivateKeyFormat.pkcs8,
  }) => base64Encode(toDer(format: format));

  // ---------------------------------------------------------------------------
  // Deserialization
  // ---------------------------------------------------------------------------

  /// Imports a private key from a PEM string.
  ///
  /// [format] must match the PEM header present in [pem].
  /// Defaults to [EcdhPrivateKeyFormat.pkcs8].
  ///
  /// Throws [FortisKeyException] if the PEM is malformed.
  factory FortisEcdhPrivateKey.fromPem(
    String pem, {
    EcdhPrivateKeyFormat format = EcdhPrivateKeyFormat.pkcs8,
  }) {
    try {
      final der = ASN1Utils.getBytesFromPEMString(pem);
      return FortisEcdhPrivateKey.fromDer(der, format: format);
    } catch (e) {
      if (e is FortisKeyException) rethrow;
      throw FortisKeyException('Invalid PEM for ECDH private key: $e');
    }
  }

  /// Imports a private key from a Base64-encoded DER string.
  ///
  /// [format] defaults to [EcdhPrivateKeyFormat.pkcs8].
  ///
  /// Throws [FortisKeyException] if the string is not valid Base64 or DER.
  factory FortisEcdhPrivateKey.fromDerBase64(
    String base64String, {
    EcdhPrivateKeyFormat format = EcdhPrivateKeyFormat.pkcs8,
  }) {
    try {
      return FortisEcdhPrivateKey.fromDer(
        base64Decode(base64String),
        format: format,
      );
    } catch (e) {
      if (e is FortisKeyException) rethrow;
      throw FortisKeyException(
        'Invalid Base64-encoded DER for ECDH private key: $e',
      );
    }
  }

  /// Imports a private key from DER bytes.
  ///
  /// [format] must match the DER structure provided.
  /// Defaults to [EcdhPrivateKeyFormat.pkcs8].
  ///
  /// Throws [FortisKeyException] if the DER is malformed.
  factory FortisEcdhPrivateKey.fromDer(
    Uint8List der, {
    EcdhPrivateKeyFormat format = EcdhPrivateKeyFormat.pkcs8,
  }) {
    try {
      return switch (format) {
        EcdhPrivateKeyFormat.pkcs8 => _decodePkcs8(der),
        EcdhPrivateKeyFormat.sec1 => _decodeSec1(der),
      };
    } catch (e) {
      if (e is FortisKeyException) rethrow;
      throw FortisKeyException(
        'Invalid DER for ECDH private key ($format): $e',
      );
    }
  }

  // ---------------------------------------------------------------------------
  // Internal encoding
  // ---------------------------------------------------------------------------

  Uint8List _encodeSec1() {
    final dBytes = _padToFieldSize(
      _encodeBigIntAsUnsigned(key.d!),
      curve.fieldSizeBytes,
    );

    final curveOidEncoded = ASN1ObjectIdentifier.fromIdentifierString(
      curve.oid,
    ).encode();

    // [0] EXPLICIT context tag for curve OID
    final tag0 = _buildExplicitContextTag(0, curveOidEncoded);

    // [1] EXPLICIT context tag for public key
    final domainParams = key.parameters!;
    final publicPoint = (domainParams.G * key.d!)!.getEncoded(false);
    final publicKeyBitString = ASN1BitString(
      stringValues: publicPoint,
    ).encode();
    final tag1 = _buildExplicitContextTag(1, publicKeyBitString);

    final sec1 = ASN1Sequence(
      elements: [
        ASN1Integer.fromtInt(1), // version
        ASN1OctetString(octets: dBytes),
        ASN1Object.fromBytes(tag0),
        ASN1Object.fromBytes(tag1),
      ],
    );

    return sec1.encode();
  }

  Uint8List _encodePkcs8() {
    // Inner SEC1 without [0] parameters (curve is in AlgorithmIdentifier)
    final dBytes = _padToFieldSize(
      _encodeBigIntAsUnsigned(key.d!),
      curve.fieldSizeBytes,
    );

    final innerSec1 = ASN1Sequence(
      elements: [
        ASN1Integer.fromtInt(1),
        ASN1OctetString(octets: dBytes),
      ],
    );

    final algorithmId = ASN1Sequence(
      elements: [
        ASN1ObjectIdentifier.fromIdentifierString(_ecPublicKeyOid),
        ASN1ObjectIdentifier.fromIdentifierString(curve.oid),
      ],
    );

    final pkcs8 = ASN1Sequence(
      elements: [
        ASN1Integer.fromtInt(0), // version
        algorithmId,
        ASN1OctetString(octets: innerSec1.encode()),
      ],
    );

    return pkcs8.encode();
  }

  // ---------------------------------------------------------------------------
  // Internal decoding
  // ---------------------------------------------------------------------------

  static FortisEcdhPrivateKey _decodeSec1(Uint8List der) {
    final parser = ASN1Parser(der);
    final seq = parser.nextObject() as ASN1Sequence;

    final dOctetString = seq.elements![1] as ASN1OctetString;
    final dBytes = dOctetString.octets!;
    final d = _decodeBigIntAsUnsigned(dBytes);

    // Extract curve from [0] context tag
    EcdhCurve? curve;
    for (var i = 2; i < seq.elements!.length; i++) {
      final element = seq.elements![i];
      if (element.tag == 0xA0) {
        final innerParser = ASN1Parser(element.valueBytes);
        final oid = innerParser.nextObject() as ASN1ObjectIdentifier;
        curve = EcdhCurve.fromOid(oid.objectIdentifierAsString!);
        break;
      }
    }

    if (curve == null) {
      throw FortisKeyException('SEC1 key is missing the curve OID ([0] tag).');
    }

    final domainParams = ECDomainParameters(curve.domainName);
    return FortisEcdhPrivateKey(ECPrivateKey(d, domainParams), curve);
  }

  static FortisEcdhPrivateKey _decodePkcs8(Uint8List der) {
    final parser = ASN1Parser(der);
    final seq = parser.nextObject() as ASN1Sequence;

    // Extract curve from AlgorithmIdentifier
    final algorithmSeq = seq.elements![1] as ASN1Sequence;
    final curveOid = (algorithmSeq.elements![1] as ASN1ObjectIdentifier)
        .objectIdentifierAsString!;

    final curve = EcdhCurve.fromOid(curveOid);
    if (curve == null) {
      throw FortisKeyException('Unsupported EC curve OID: $curveOid');
    }

    // Extract private key from inner OCTET STRING
    final octetString = seq.elements![2] as ASN1OctetString;
    final innerParser = ASN1Parser(octetString.octets!);
    final innerSeq = innerParser.nextObject() as ASN1Sequence;
    final dOctetString = innerSeq.elements![1] as ASN1OctetString;
    final d = _decodeBigIntAsUnsigned(dOctetString.octets!);

    final domainParams = ECDomainParameters(curve.domainName);
    return FortisEcdhPrivateKey(ECPrivateKey(d, domainParams), curve);
  }

  // ---------------------------------------------------------------------------
  // Helpers
  // ---------------------------------------------------------------------------

  static (String, String) _headers(EcdhPrivateKeyFormat format) =>
      switch (format) {
        EcdhPrivateKeyFormat.pkcs8 => (_pkcs8Header, _pkcs8Footer),
        EcdhPrivateKeyFormat.sec1 => (_sec1Header, _sec1Footer),
      };
}

/// Builds an explicit context-specific tag (constructed).
///
/// Tag byte: `0xA0 | tagNumber` (constructed context-specific).
Uint8List _buildExplicitContextTag(int tagNumber, Uint8List content) {
  final tagByte = 0xA0 | tagNumber;
  final lengthBytes = ASN1Utils.encodeLength(content.length);
  final result = Uint8List(1 + lengthBytes.length + content.length);
  result[0] = tagByte;
  result.setRange(1, 1 + lengthBytes.length, lengthBytes);
  result.setRange(1 + lengthBytes.length, result.length, content);
  return result;
}

/// Left-pads [bytes] with zeros to exactly [fieldSize] bytes.
Uint8List _padToFieldSize(Uint8List bytes, int fieldSize) {
  if (bytes.length >= fieldSize) return bytes;
  final padded = Uint8List(fieldSize);
  padded.setRange(fieldSize - bytes.length, fieldSize, bytes);
  return padded;
}

/// Encodes a non-negative [BigInt] as an unsigned big-endian byte array.
Uint8List _encodeBigIntAsUnsigned(BigInt value) {
  final hexStr = value.toRadixString(16);
  final padded = hexStr.length.isOdd ? '0$hexStr' : hexStr;
  final bytes = Uint8List(padded.length ~/ 2);
  for (var i = 0; i < bytes.length; i++) {
    bytes[i] = int.parse(padded.substring(i * 2, i * 2 + 2), radix: 16);
  }
  return bytes;
}

/// Decodes an unsigned big-endian byte array to a non-negative [BigInt].
BigInt _decodeBigIntAsUnsigned(Uint8List bytes) {
  var result = BigInt.zero;
  for (var i = 0; i < bytes.length; i++) {
    result = (result << 8) | BigInt.from(bytes[i]);
  }
  return result;
}

/// Wraps a base64 string with line breaks every 64 characters.
String _wrapBase64(String b64) {
  final buf = StringBuffer();

  for (var i = 0; i < b64.length; i += 64) {
    buf.writeln(b64.substring(i, i + 64 > b64.length ? b64.length : i + 64));
  }

  return buf.toString().trimRight();
}
