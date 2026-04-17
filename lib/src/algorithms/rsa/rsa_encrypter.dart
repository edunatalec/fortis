import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:pointycastle/export.dart';

import '../../core/fortis_log.dart';
import '../../exceptions/fortis_config_exception.dart';
import '../../exceptions/fortis_encryption_exception.dart';
import 'rsa_hash.dart';
import 'rsa_oaep_v21.dart';
import 'rsa_padding.dart';
import 'rsa_public_key.dart';
import 'rsa_validators.dart';

// ignore_for_file: constant_identifier_names

/// Encrypts data using an RSA public key.
///
/// Build via [RsaBuilder]:
/// ```dart
/// final encrypter = Fortis.rsa()
///     .padding(RsaPadding.oaep_v2)
///     .hash(RsaHash.sha256)
///     .encrypter(pair.publicKey);
///
/// final ciphertext = encrypter.encrypt('hello fortis');       // Uint8List
/// final base64     = encrypter.encryptToString('hello fortis'); // Base64
/// ```
///
/// ## Maximum plaintext size
///
/// RSA is a **small-payload cipher** — it can only encrypt as many bytes as
/// the key size minus padding overhead. Encrypting a longer message throws
/// [FortisEncryptionException].
///
/// | Padding        | Max plaintext bytes                                  |
/// |----------------|------------------------------------------------------|
/// | OAEP (any)     | `keyBytes − 2·hashBytes − 2`                         |
/// | PKCS#1 v1.5    | `keyBytes − 11`                                      |
///
/// Examples: RSA-2048 (256 bytes) + SHA-256 → **190 bytes**. RSA-2048 +
/// SHA-512 → **62 bytes**. RSA-4096 + SHA-256 → **446 bytes**.
///
/// For larger payloads, use hybrid encryption: generate an AES key, encrypt
/// the payload with AES, then wrap the AES key with RSA.
class RsaEncrypter {
  /// The public key used to encrypt.
  final FortisRsaPublicKey key;

  /// The padding scheme.
  final RsaPadding padding;

  /// The hash algorithm used by the padding scheme.
  final RsaHash hash;

  /// The label for OAEP v2.1 (null for other paddings).
  final Uint8List? label;

  /// Creates an [RsaEncrypter] directly. Prefer [RsaBuilder] — this
  /// constructor is public only for advanced scenarios where you already
  /// have the padding/hash/label in hand.
  ///
  /// Example:
  /// ```dart
  /// final encrypter = Fortis.rsa()
  ///     .padding(RsaPadding.oaep_v2)
  ///     .hash(RsaHash.sha256)
  ///     .encrypter(pair.publicKey);
  /// ```
  ///
  /// Throws [FortisConfigException] if [label] is provided with a padding
  /// other than [RsaPadding.oaep_v2_1] (label is silently ignored by the
  /// other paddings, so the combination is rejected up front).
  factory RsaEncrypter({
    required FortisRsaPublicKey key,
    required RsaPadding padding,
    required RsaHash hash,
    Uint8List? label,
  }) {
    validateLabelPadding(label, padding);
    return RsaEncrypter._internal(
      key: key,
      padding: padding,
      hash: hash,
      label: label,
    );
  }

  const RsaEncrypter._internal({
    required this.key,
    required this.padding,
    required this.hash,
    this.label,
  });

  /// Encrypts [plaintext] and returns the ciphertext as raw bytes.
  ///
  /// [plaintext] accepts:
  /// - [Uint8List]: raw bytes, encrypted as-is.
  /// - [String]: UTF-8 encoded before encryption.
  ///
  /// See the class-level "Maximum plaintext size" table for length limits.
  ///
  /// Example:
  /// ```dart
  /// final ct = encrypter.encrypt('hello fortis');
  /// ```
  ///
  /// Throws [FortisConfigException] if [plaintext] is not a [String] or
  /// [Uint8List]. Throws [FortisEncryptionException] if encryption fails
  /// (e.g. plaintext exceeds the max size for the configured key/hash).
  Uint8List encrypt(Object plaintext) {
    _warnIfNeeded();

    final bytes = _toBytes(plaintext);

    try {
      return switch (padding) {
        RsaPadding.pkcs1_v1_5 => _encryptPkcs1v15(bytes),
        RsaPadding.oaep_v1 => _encryptOaepV1(bytes),
        RsaPadding.oaep_v2 => _encryptOaepV2(bytes),
        RsaPadding.oaep_v2_1 => _encryptOaepV21(bytes),
      };
    } on FortisEncryptionException {
      rethrow;
    } on FortisConfigException {
      rethrow;
    } catch (e) {
      throw FortisEncryptionException('Encryption failed: $e');
    }
  }

  /// Encrypts [plaintext] and returns the ciphertext as a Base64 string.
  ///
  /// See [encrypt] for accepted [plaintext] types and limits.
  ///
  /// Example:
  /// ```dart
  /// final b64 = encrypter.encryptToString('hello fortis');
  /// ```
  String encryptToString(Object plaintext) => base64Encode(encrypt(plaintext));

  /// Converts [plaintext] to [Uint8List].
  ///
  /// Accepts [Uint8List] or [String] (UTF-8 encoded).
  /// Throws [FortisConfigException] for any other type.
  Uint8List _toBytes(Object plaintext) {
    if (plaintext is Uint8List) return plaintext;
    if (plaintext is String) return Uint8List.fromList(utf8.encode(plaintext));

    throw FortisConfigException(
      'Unsupported plaintext type: ${plaintext.runtimeType}. '
      'Expected String or Uint8List.',
    );
  }

  Uint8List _encryptPkcs1v15(Uint8List plaintext) {
    final cipher = PKCS1Encoding(RSAEngine())
      ..init(true, PublicKeyParameter<RSAPublicKey>(key.key));

    return cipher.process(plaintext);
  }

  Uint8List _encryptOaepV1(Uint8List plaintext) {
    final cipher = OAEPEncoding.withSHA1(RSAEngine())
      ..init(true, PublicKeyParameter<RSAPublicKey>(key.key));

    return cipher.process(plaintext);
  }

  Uint8List _encryptOaepV2(Uint8List plaintext) {
    final cipher = OAEPEncoding.withCustomDigest(hash.toDigest, RSAEngine())
      ..init(true, PublicKeyParameter<RSAPublicKey>(key.key));

    return cipher.process(plaintext);
  }

  Uint8List _encryptOaepV21(Uint8List plaintext) {
    return oaepV21Encrypt(
      key: key.key,
      message: plaintext,
      digest: hash.toDigest(),
      label: label ?? Uint8List(0),
      rng: Random.secure(),
    );
  }

  void _warnIfNeeded() {
    final bitLength = key.key.modulus?.bitLength ?? 0;
    if (bitLength <= 2048 && hash == RsaHash.sha512) {
      FortisLog.info(
        'RSA-2048 with SHA-512 is uncommon and may fail for large plaintexts.',
      );
    }
  }
}
