import 'dart:convert';
import 'dart:typed_data';

import 'package:pointycastle/export.dart';

import '../../exceptions/fortis_config_exception.dart';
import '../../exceptions/fortis_encryption_exception.dart';
import 'rsa_hash.dart';
import 'rsa_oaep_v21.dart';
import 'rsa_padding.dart';
import 'rsa_private_key.dart';

// ignore_for_file: constant_identifier_names

/// Decrypts data using an RSA private key.
///
/// Build via [RsaBuilder]:
/// ```dart
/// final decrypter = Fortis.rsa()
///     .padding(RsaPadding.oaep_v2)
///     .hash(RsaHash.sha256)
///     .decrypter(pair.privateKey);
///
/// final plaintext = decrypter.decrypt(ciphertext);         // Uint8List
/// final text      = decrypter.decryptToString(ciphertext); // UTF-8 String
/// ```
///
/// The [padding], [hash], and `label` (for OAEP v2.1) must match those used
/// by the encrypter; otherwise [FortisEncryptionException] is thrown.
class RsaDecrypter {
  /// The private key used to decrypt.
  final FortisRsaPrivateKey key;

  /// The padding scheme.
  final RsaPadding padding;

  /// The hash algorithm used by the padding scheme.
  final RsaHash hash;

  /// The label for OAEP v2.1 (null for other paddings).
  final Uint8List? label;

  /// Creates an [RsaDecrypter] directly. Prefer [RsaBuilder] — this
  /// constructor is public only for advanced scenarios.
  ///
  /// Example:
  /// ```dart
  /// final decrypter = Fortis.rsa()
  ///     .padding(RsaPadding.oaep_v2)
  ///     .hash(RsaHash.sha256)
  ///     .decrypter(pair.privateKey);
  /// ```
  const RsaDecrypter({
    required this.key,
    required this.padding,
    required this.hash,
    this.label,
  });

  /// Decrypts [input] and returns the plaintext as raw bytes.
  ///
  /// [input] accepts:
  /// - [Uint8List]: raw ciphertext bytes.
  /// - [String]: a Base64-encoded ciphertext string.
  ///
  /// Example:
  /// ```dart
  /// final plaintext = decrypter.decrypt(ciphertext);
  /// ```
  ///
  /// Throws [FortisConfigException] if [input] is not a [String] or
  /// [Uint8List]. Throws [FortisEncryptionException] if decryption fails
  /// (wrong key, corrupted data, mismatched padding/hash/label, etc.).
  Uint8List decrypt(Object input) {
    if (input is Uint8List) return _decryptBytes(input);
    if (input is String) {
      final Uint8List bytes;
      try {
        bytes = base64Decode(input);
      } on FormatException catch (e) {
        throw FortisConfigException(
          'Invalid Base64 in ciphertext: ${e.message}',
        );
      }
      return _decryptBytes(bytes);
    }

    throw FortisConfigException(
      'Unsupported input type: ${input.runtimeType}. '
      'Expected String or Uint8List.',
    );
  }

  /// Decrypts [input] and returns the plaintext as a UTF-8 decoded [String].
  ///
  /// See [decrypt] for accepted [input] types.
  ///
  /// Example:
  /// ```dart
  /// final text = decrypter.decryptToString(ciphertext);
  /// ```
  String decryptToString(Object input) => utf8.decode(decrypt(input));

  /// Decrypts raw [ciphertext] bytes and returns the plaintext.
  ///
  /// Throws [FortisEncryptionException] if decryption fails.
  Uint8List _decryptBytes(Uint8List ciphertext) {
    try {
      return switch (padding) {
        RsaPadding.pkcs1_v1_5 => _decryptPkcs1v15(ciphertext),
        RsaPadding.oaep_v1 => _decryptOaepV1(ciphertext),
        RsaPadding.oaep_v2 => _decryptOaepV2(ciphertext),
        RsaPadding.oaep_v2_1 => _decryptOaepV21(ciphertext),
      };
    } on FortisEncryptionException {
      rethrow;
    } catch (e) {
      throw FortisEncryptionException('Decryption failed: $e');
    }
  }

  Uint8List _decryptPkcs1v15(Uint8List ciphertext) {
    final cipher = PKCS1Encoding(RSAEngine())
      ..init(false, PrivateKeyParameter<RSAPrivateKey>(key.key));

    return cipher.process(ciphertext);
  }

  Uint8List _decryptOaepV1(Uint8List ciphertext) {
    final cipher = OAEPEncoding.withSHA1(RSAEngine())
      ..init(false, PrivateKeyParameter<RSAPrivateKey>(key.key));

    return cipher.process(ciphertext);
  }

  Uint8List _decryptOaepV2(Uint8List ciphertext) {
    final cipher = OAEPEncoding.withCustomDigest(hash.toDigest, RSAEngine())
      ..init(false, PrivateKeyParameter<RSAPrivateKey>(key.key));

    return cipher.process(ciphertext);
  }

  Uint8List _decryptOaepV21(Uint8List ciphertext) {
    return oaepV21Decrypt(
      key: key.key,
      ciphertext: ciphertext,
      digest: hash.toDigest(),
      label: label ?? Uint8List(0),
    );
  }
}
