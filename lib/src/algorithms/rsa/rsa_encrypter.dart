import 'dart:developer' as dev;
import 'dart:math';
import 'dart:typed_data';

import 'package:pointycastle/export.dart';

import '../../exceptions/fortis_encryption_exception.dart';
import 'rsa_hash.dart';
import 'rsa_oaep_v21.dart';
import 'rsa_padding.dart';
import 'rsa_public_key.dart';

// ignore_for_file: constant_identifier_names

/// Encrypts data using an RSA public key.
///
/// Build an instance via [RsaBuilder]:
/// ```dart
/// final encrypter = Fortis.rsa()
///     .padding(RsaPadding.oaep_v2)
///     .hash(RsaHash.sha256)
///     .encrypter(pair.publicKey);
///
/// final ciphertext = encrypter.encrypt(plaintext);
/// ```
class RsaEncrypter {
  /// The public key used to encrypt.
  final FortisRsaPublicKey key;

  /// The padding scheme.
  final RsaPadding padding;

  /// The hash algorithm used by the padding scheme.
  final RsaHash hash;

  /// The label for OAEP v2.1 (null for other paddings).
  final Uint8List? label;

  /// Creates an [RsaEncrypter].
  ///
  /// Use [RsaBuilder] to obtain an instance.
  const RsaEncrypter({
    required this.key,
    required this.padding,
    required this.hash,
    this.label,
  });

  /// Encrypts [plaintext] and returns the ciphertext.
  ///
  /// Throws [FortisEncryptionException] on failure.
  Uint8List encrypt(Uint8List plaintext) {
    _warnIfNeeded();
    try {
      return switch (padding) {
        RsaPadding.pkcs1_v1_5 => _encryptPkcs1v15(plaintext),
        RsaPadding.oaep_v1 => _encryptOaepV1(plaintext),
        RsaPadding.oaep_v2 => _encryptOaepV2(plaintext),
        RsaPadding.oaep_v2_1 => _encryptOaepV21(plaintext),
      };
    } on FortisEncryptionException {
      rethrow;
    } catch (e) {
      throw FortisEncryptionException('Encryption failed: $e');
    }
  }

  // ---------------------------------------------------------------------------
  // Padding implementations
  // ---------------------------------------------------------------------------

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

  // ---------------------------------------------------------------------------
  // Warnings
  // ---------------------------------------------------------------------------

  void _warnIfNeeded() {
    final bitLength = key.key.modulus?.bitLength ?? 0;
    if (bitLength <= 2048 && hash == RsaHash.sha512) {
      dev.log(
        'RSA-2048 with SHA-512 is uncommon and may fail for large plaintexts.',
        name: 'fortis',
        level: 500,
      );
    }
  }
}
