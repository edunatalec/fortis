import 'dart:convert';
import 'dart:typed_data';

import 'package:pointycastle/export.dart';

import '../../exceptions/fortis_encryption_exception.dart';
import 'rsa_hash.dart';
import 'rsa_oaep_v21.dart';
import 'rsa_padding.dart';
import 'rsa_private_key.dart';

// ignore_for_file: constant_identifier_names

/// Decrypts data using an RSA private key.
///
/// Build an instance via [RsaBuilder]:
/// ```dart
/// final decrypter = Fortis.rsa()
///     .padding(RsaPadding.oaep_v2)
///     .hash(RsaHash.sha256)
///     .decrypter(pair.privateKey);
///
/// final plaintext = decrypter.decrypt(ciphertext);
/// ```
class RsaDecrypter {
  /// The private key used to decrypt.
  final FortisRsaPrivateKey key;

  /// The padding scheme.
  final RsaPadding padding;

  /// The hash algorithm used by the padding scheme.
  final RsaHash hash;

  /// The label for OAEP v2.1 (null for other paddings).
  final Uint8List? label;

  /// Creates an [RsaDecrypter].
  ///
  /// Use [RsaBuilder] to obtain an instance.
  const RsaDecrypter({
    required this.key,
    required this.padding,
    required this.hash,
    this.label,
  });

  /// Decrypts [ciphertext] and returns the original plaintext.
  ///
  /// Throws [FortisEncryptionException] on failure.
  Uint8List decrypt(Uint8List ciphertext) {
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

  /// Decrypts raw ciphertext bytes and returns a UTF-8 string.
  String decryptToString(Uint8List ciphertext) =>
      utf8.decode(decrypt(ciphertext));

  /// Decrypts a Base64-encoded ciphertext string and returns raw bytes.
  Uint8List decryptFromBase64(String base64Ciphertext) =>
      decrypt(base64Decode(base64Ciphertext));

  /// Decrypts a Base64-encoded ciphertext string and returns a UTF-8 string.
  String decryptFromBase64ToString(String base64Ciphertext) =>
      utf8.decode(decryptFromBase64(base64Ciphertext));

  // ---------------------------------------------------------------------------
  // Padding implementations
  // ---------------------------------------------------------------------------

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
