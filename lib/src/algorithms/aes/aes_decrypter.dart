import 'dart:convert';
import 'dart:typed_data';

import 'package:pointycastle/export.dart';

import '../../exceptions/fortis_config_exception.dart';
import '../../exceptions/fortis_encryption_exception.dart';
import 'aes_auth_payload.dart';
import 'aes_key.dart';
import 'aes_mode.dart';
import 'aes_padding.dart';
import 'aes_payload.dart';

/// Decrypts AES ciphertext produced by [AesEncrypter].
///
/// Obtain via the builder:
/// ```dart
/// final decrypter = Fortis.aes()
///     .mode(AesMode.gcm)
///     .decrypter(myKey);
/// ```
///
/// ## IV / nonce management
///
/// The IV or nonce is extracted automatically from the ciphertext prefix.
/// For authenticated modes (GCM, CCM), the auth tag is verified automatically.
/// Developers never manage IVs or auth tags manually in the default flow.
///
/// ## Buffer layouts expected by [decrypt] when passed a [Uint8List]
///
/// - ECB: `[ciphertext]`
/// - CBC / CTR / CFB / OFB: `[iv (16 bytes) | ciphertext]`
/// - GCM: `[nonce (12 bytes) | ciphertext | tag (16 bytes)]`
/// - CCM: `[nonce (11 bytes) | ciphertext | tag (16 bytes)]`
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

  /// Decrypts [input] and returns the plaintext as raw bytes.
  ///
  /// [input] accepts the following types:
  ///
  /// - [Uint8List]: the combined buffer in Fortis internal format.
  ///   Layout: `[ iv | ciphertext ]` or `[ iv | ciphertext | tag ]` depending on mode.
  ///
  /// - [String]: a Base64-encoded string of the combined buffer.
  ///
  /// - [Map<String, String>]: a map with separate fields, all Base64-encoded.
  ///   Must contain either `'iv'` or `'nonce'` (not both) and `'data'`.
  ///   Authenticated modes (GCM, CCM) must also contain `'tag'`.
  ///   Throws [FortisConfigException] if:
  ///   - Both `'iv'` and `'nonce'` are present
  ///   - Neither `'iv'` nor `'nonce'` is present
  ///   - `'data'` is missing
  ///   - `'tag'` is missing for authenticated modes
  ///
  /// - [AesAuthPayload]: only valid for authenticated modes (GCM, CCM).
  ///   Throws [FortisConfigException] if used with non-authenticated modes.
  ///
  /// - [AesPayload]: only valid for non-authenticated modes (CBC, CTR, CFB, OFB).
  ///   Throws [FortisConfigException] if used with authenticated modes.
  ///
  /// Throws [FortisConfigException] if [input] is not one of the accepted types.
  Uint8List decrypt(Object input) {
    if (input is Uint8List) {
      return _decryptBytes(input);
    }

    if (input is String) {
      return _decryptBytes(base64Decode(input));
    }

    if (input is Map<String, String>) {
      return _decryptBytes(_fromMap(input));
    }

    if (input is AesAuthPayload) {
      final isAuth = _mode == AesMode.gcm || _mode == AesMode.ccm;
      if (!isAuth) {
        throw FortisConfigException(
          'AesAuthPayload is only valid for authenticated modes (GCM, CCM). '
          'Current mode: ${_mode.name.toUpperCase()}.',
        );
      }
      return _decryptBytes(_fromMap(input.toMap()));
    }

    if (input is AesPayload) {
      final isAuth = _mode == AesMode.gcm || _mode == AesMode.ccm;
      if (isAuth) {
        throw FortisConfigException(
          'AesPayload is not valid for authenticated modes (GCM, CCM). '
          'Current mode: ${_mode.name.toUpperCase()}. '
          'Use AesAuthPayload instead.',
        );
      }
      return _decryptBytes(_fromMap(input.toMap()));
    }

    throw FortisConfigException(
      'Unsupported input type: ${input.runtimeType}. '
      'Expected Uint8List, String, Map<String, String>, AesAuthPayload, or AesPayload.',
    );
  }

  /// Decrypts [input] and returns the plaintext as a UTF-8 decoded [String].
  ///
  /// See [decrypt] for accepted [input] types and validation rules.
  String decryptToString(Object input) {
    return utf8.decode(decrypt(input));
  }

  // ──────────────────────────────────────────────
  // Internal core
  // ──────────────────────────────────────────────

  /// Decrypts a combined [ciphertext] buffer and returns the original plaintext.
  ///
  /// Throws [FortisEncryptionException] if decryption fails, the auth tag
  /// is invalid, or the AAD does not match what was used during encryption.
  Uint8List _decryptBytes(Uint8List ciphertext) {
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

  /// Parses [map] and assembles it into the combined buffer expected by [_decryptBytes].
  ///
  /// Validates:
  /// - Exactly one of `'iv'` or `'nonce'` is present (not both, not neither)
  /// - `'data'` is present
  /// - `'tag'` is present for authenticated modes (GCM, CCM)
  Uint8List _fromMap(Map<String, String> map) {
    final hasIv = map.containsKey('iv');
    final hasNonce = map.containsKey('nonce');

    if (hasIv && hasNonce) {
      throw const FortisConfigException(
        "Map must contain either 'iv' or 'nonce', not both.",
      );
    }
    if (!hasIv && !hasNonce) {
      throw const FortisConfigException(
        "Map must contain either 'iv' or 'nonce'.",
      );
    }
    if (!map.containsKey('data')) {
      throw const FortisConfigException(
        "Map is missing required field 'data'.",
      );
    }

    final isAuth = _mode == AesMode.gcm || _mode == AesMode.ccm;

    if (isAuth && !map.containsKey('tag')) {
      throw FortisConfigException(
        "Map is missing required field 'tag' for ${_mode.name.toUpperCase()} mode.",
      );
    }

    final ivBytes = base64Decode(hasIv ? map['iv']! : map['nonce']!);
    final dataBytes = base64Decode(map['data']!);

    if (isAuth) {
      final tagBytes = base64Decode(map['tag']!);
      return Uint8List.fromList([...ivBytes, ...dataBytes, ...tagBytes]);
    }

    return Uint8List.fromList([...ivBytes, ...dataBytes]);
  }

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
    final cipher = CFBBlockCipher(AESEngine(), 16);
    cipher.init(false, ParametersWithIV(KeyParameter(_key.toBytes()), iv));
    return _processStreamBlockCipher(cipher, body);
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
    final cipher = OFBBlockCipher(AESEngine(), 16);
    cipher.init(false, ParametersWithIV(KeyParameter(_key.toBytes()), iv));
    return _processStreamBlockCipher(cipher, body);
  }

  // ──────────────────────────────────────────────
  // Authenticated modes
  // ──────────────────────────────────────────────

  Uint8List _decryptGcm(Uint8List ciphertext) {
    if (ciphertext.length < 12) {
      throw FortisEncryptionException(
        'Ciphertext too short for GCM mode '
        '(expected at least 12 bytes for nonce, got ${ciphertext.length}).',
      );
    }
    final iv = ciphertext.sublist(0, 12); // NIST SP 800-38D: 96 bits (12 bytes)
    final body = ciphertext.sublist(12); // ciphertext + auth tag
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
    if (ciphertext.length < 11) {
      throw FortisEncryptionException(
        'Ciphertext too short for CCM mode '
        '(expected at least 11 bytes for nonce, got ${ciphertext.length}).',
      );
    }
    final nonce = ciphertext.sublist(0, 11); // RFC 3610: 11-byte nonce
    final body = ciphertext.sublist(11);
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

  /// Processes [input] with [cipher] block by block, without padding.
  ///
  /// Full blocks are processed directly. The last partial block is
  /// zero-padded, processed, and only the necessary bytes are copied —
  /// ensuring the output has the same size as the input.
  Uint8List _processStreamBlockCipher(BlockCipher cipher, Uint8List input) {
    const blockSize = 16;
    final output = Uint8List(input.length);
    var offset = 0;

    while (offset + blockSize <= input.length) {
      cipher.processBlock(input, offset, output, offset);
      offset += blockSize;
    }

    if (offset < input.length) {
      final remaining = input.length - offset;
      final tmp = Uint8List(blockSize)..setRange(0, remaining, input, offset);
      final tmpOut = Uint8List(blockSize);
      cipher.processBlock(tmp, 0, tmpOut, 0);
      output.setRange(offset, output.length, tmpOut);
    }

    return output;
  }

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
