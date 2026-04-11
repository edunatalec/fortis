import 'dart:convert';
import 'dart:typed_data';

import 'package:pointycastle/export.dart';

import '../../exceptions/fortis_config_exception.dart';
import '../../exceptions/fortis_encryption_exception.dart';
import 'aes_key.dart';
import 'aes_mode.dart';
import 'aes_padding.dart';

/// Decrypts AES ciphertext produced by [AesEncrypter].
///
/// Obtain via the builder:
/// ```dart
/// final decrypter = Fortis.aes()
///     .mode(AesMode.gcm)
///     .key(myKey)
///     .decrypter();
/// ```
///
/// The IV/nonce is extracted automatically from the ciphertext prefix.
/// For authenticated modes (GCM, CCM), the auth tag is verified automatically.
/// Developers never manage IVs or auth tags manually.
class AesDecrypter {
  final AesMode _mode;
  final FortisAesKey _key;
  final AesPadding? _padding;
  final Uint8List? _aad;
  final int _tagSizeBits;

  /// Creates a decrypter for block modes (ECB, CBC).
  AesDecrypter.block({
    required AesMode mode,
    required FortisAesKey key,
    required AesPadding padding,
  }) : _mode = mode,
       _key = key,
       _padding = padding,
       _aad = null,
       _tagSizeBits = 128;

  /// Creates a decrypter for stream modes (CTR, CFB, OFB).
  AesDecrypter.stream({required AesMode mode, required FortisAesKey key})
    : _mode = mode,
      _key = key,
      _padding = null,
      _aad = null,
      _tagSizeBits = 128;

  /// Creates a decrypter for authenticated modes (GCM, CCM).
  AesDecrypter.auth({
    required AesMode mode,
    required FortisAesKey key,
    Uint8List? aad,
    int tagSizeBits = 128,
  }) : _mode = mode,
       _key = key,
       _padding = null,
       _aad = aad,
       _tagSizeBits = tagSizeBits;

  /// Decrypts [ciphertext] and returns the original plaintext.
  ///
  /// Throws [FortisEncryptionException] if decryption fails, the auth tag
  /// is invalid, or the AAD does not match what was used during encryption.
  Uint8List decrypt(Uint8List ciphertext) {
    try {
      return switch (_mode) {
        AesMode.ecb => _decryptEcb(ciphertext),
        AesMode.cbc => _decryptCbc(ciphertext),
        AesMode.ctr => _decryptCtr(ciphertext),
        AesMode.cfb => _decryptCfb(ciphertext),
        AesMode.ofb => _decryptOfb(ciphertext),
        AesMode.gcm => _decryptGcm(ciphertext),
        AesMode.ccm => _decryptCcm(ciphertext),
      };
    } on FortisEncryptionException {
      rethrow;
    } on FortisConfigException {
      rethrow;
    } catch (e) {
      throw FortisEncryptionException('AES decryption failed: $e');
    }
  }

  /// Decrypts [ciphertext] and returns the result as a UTF-8 string.
  String decryptToString(Uint8List ciphertext) =>
      utf8.decode(decrypt(ciphertext));

  /// Decrypts a Base64-encoded [base64Ciphertext] and returns bytes.
  Uint8List decryptFromBase64(String base64Ciphertext) =>
      decrypt(base64Decode(base64Ciphertext));

  /// Decrypts a Base64-encoded [base64Ciphertext] and returns a UTF-8 string.
  String decryptFromBase64ToString(String base64Ciphertext) =>
      utf8.decode(decryptFromBase64(base64Ciphertext));

  // ──────────────────────────────────────────────
  // Block modes
  // ──────────────────────────────────────────────

  Uint8List _decryptEcb(Uint8List ciphertext) {
    final padding = _padding!;
    final cipher = _paddedBlockCipher(padding, ECBBlockCipher(AESEngine()));
    cipher.init(
      false,
      PaddedBlockCipherParameters(KeyParameter(_key.toBytes()), null),
    );
    return cipher.process(ciphertext);
  }

  Uint8List _decryptCbc(Uint8List ciphertext) {
    if (ciphertext.length < 16) {
      throw FortisEncryptionException(
        'Ciphertext too short for CBC mode '
        '(expected at least 16 bytes for IV, got ${ciphertext.length}).',
      );
    }
    final iv = ciphertext.sublist(0, 16);
    final body = ciphertext.sublist(16);
    final padding = _padding!;
    final cipher = _paddedBlockCipher(padding, CBCBlockCipher(AESEngine()));
    cipher.init(
      false,
      PaddedBlockCipherParameters(
        ParametersWithIV(KeyParameter(_key.toBytes()), iv),
        null,
      ),
    );
    return cipher.process(body);
  }

  // ──────────────────────────────────────────────
  // Stream modes
  // ──────────────────────────────────────────────

  Uint8List _decryptCtr(Uint8List ciphertext) {
    if (ciphertext.length < 16) {
      throw FortisEncryptionException(
        'Ciphertext too short for CTR mode '
        '(expected at least 16 bytes for IV, got ${ciphertext.length}).',
      );
    }
    final iv = ciphertext.sublist(0, 16);
    final body = ciphertext.sublist(16);
    final cipher = CTRStreamCipher(AESEngine());
    cipher.init(false, ParametersWithIV(KeyParameter(_key.toBytes()), iv));
    final output = Uint8List(body.length);
    cipher.processBytes(body, 0, body.length, output, 0);
    return output;
  }

  Uint8List _decryptCfb(Uint8List ciphertext) {
    if (ciphertext.length < 16) {
      throw FortisEncryptionException(
        'Ciphertext too short for CFB mode '
        '(expected at least 16 bytes for IV, got ${ciphertext.length}).',
      );
    }
    final iv = ciphertext.sublist(0, 16);
    final body = ciphertext.sublist(16);
    // Mirror the internal PKCS7 padding used during encryption.
    final cipher = _paddedBlockCipher(
      AesPadding.pkcs7,
      CFBBlockCipher(AESEngine(), 16),
    );
    cipher.init(
      false,
      PaddedBlockCipherParameters(
        ParametersWithIV(KeyParameter(_key.toBytes()), iv),
        null,
      ),
    );
    return cipher.process(body);
  }

  Uint8List _decryptOfb(Uint8List ciphertext) {
    if (ciphertext.length < 16) {
      throw FortisEncryptionException(
        'Ciphertext too short for OFB mode '
        '(expected at least 16 bytes for IV, got ${ciphertext.length}).',
      );
    }
    final iv = ciphertext.sublist(0, 16);
    final body = ciphertext.sublist(16);
    final cipher = _paddedBlockCipher(
      AesPadding.pkcs7,
      OFBBlockCipher(AESEngine(), 16),
    );
    cipher.init(
      false,
      PaddedBlockCipherParameters(
        ParametersWithIV(KeyParameter(_key.toBytes()), iv),
        null,
      ),
    );
    return cipher.process(body);
  }

  // ──────────────────────────────────────────────
  // Authenticated modes
  // ──────────────────────────────────────────────

  Uint8List _decryptGcm(Uint8List ciphertext) {
    if (ciphertext.length < 16) {
      throw FortisEncryptionException(
        'Ciphertext too short for GCM mode '
        '(expected at least 16 bytes for IV, got ${ciphertext.length}).',
      );
    }
    final iv = ciphertext.sublist(0, 16);
    final body = ciphertext.sublist(16); // ciphertext + auth tag
    final cipher = GCMBlockCipher(AESEngine());
    cipher.init(
      false,
      AEADParameters(
        KeyParameter(_key.toBytes()),
        _tagSizeBits,
        iv,
        _aad ?? Uint8List(0),
      ),
    );
    try {
      return cipher.process(body);
    } catch (e) {
      throw FortisEncryptionException(
        'GCM authentication failed. The ciphertext may have been tampered with, '
        'or the AAD does not match what was used during encryption. ($e)',
      );
    }
  }

  Uint8List _decryptCcm(Uint8List ciphertext) {
    if (ciphertext.length < 12) {
      throw FortisEncryptionException(
        'Ciphertext too short for CCM mode '
        '(expected at least 12 bytes for nonce, got ${ciphertext.length}).',
      );
    }
    final nonce = ciphertext.sublist(0, 12); // 12-byte nonce per RFC 3610
    final body = ciphertext.sublist(12);
    final cipher = CCMBlockCipher(AESEngine());
    cipher.init(
      false,
      AEADParameters(
        KeyParameter(_key.toBytes()),
        _tagSizeBits,
        nonce,
        _aad ?? Uint8List(0),
      ),
    );
    try {
      return cipher.process(body);
    } catch (e) {
      throw FortisEncryptionException(
        'CCM authentication failed. The ciphertext may have been tampered with, '
        'or the AAD does not match what was used during encryption. ($e)',
      );
    }
  }

  // ──────────────────────────────────────────────
  // Helpers
  // ──────────────────────────────────────────────

  PaddedBlockCipherImpl _paddedBlockCipher(
    AesPadding padding,
    BlockCipher cipher,
  ) => PaddedBlockCipherImpl(_toPadding(padding), cipher);

  Padding _toPadding(AesPadding padding) => switch (padding) {
    AesPadding.pkcs7 => PKCS7Padding(),
    AesPadding.iso7816 => ISO7816d4Padding(),
    AesPadding.zeroPadding => _ZeroBytePadding(),
    AesPadding.noPadding => PKCS7Padding(),
  };
}

/// Custom zero-byte padding implementation.
///
/// ⚠️ Ambiguous if data legitimately ends with `0x00` bytes. Prefer [PKCS7Padding].
class _ZeroBytePadding implements Padding {
  @override
  String get algorithmName => 'ZeroBytePadding';

  @override
  void init([CipherParameters? params]) {}

  @override
  int addPadding(Uint8List data, int offset) {
    final count = data.length - offset;
    for (var i = offset; i < data.length; i++) {
      data[i] = 0;
    }
    return count;
  }

  @override
  int padCount(Uint8List data) {
    var i = data.length - 1;
    while (i >= 0 && data[i] == 0) {
      i--;
    }
    return data.length - 1 - i;
  }

  @override
  Uint8List process(bool pad, Uint8List data) {
    if (pad) {
      const blockSize = 16;
      final padLen = blockSize - (data.length % blockSize);
      final out = Uint8List(data.length + padLen);
      out.setAll(0, data);
      return out;
    } else {
      final padLen = padCount(data);
      return data.sublist(0, data.length - padLen);
    }
  }
}
