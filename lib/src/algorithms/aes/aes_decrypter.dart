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
///     .decrypter(myKey);
/// ```
///
/// ## IV / nonce management
///
/// The IV or nonce is extracted automatically from the ciphertext prefix.
/// For authenticated modes (GCM, CCM), the auth tag is verified automatically.
/// Developers never manage IVs or auth tags manually in the default flow.
///
/// Modes CBC, CTR, CFB, and OFB use the term **IV** internally and in
/// documentation. Modes GCM and CCM use the term **nonce**. They are
/// equivalent concepts; the `iv` parameter in [decryptFields] and [decryptMap]
/// accepts both.
///
/// ## Buffer layouts expected by [decrypt]
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
  // Interoperability methods
  // ──────────────────────────────────────────────

  /// Decrypts using separate Base64-encoded fields.
  ///
  /// Use when receiving ciphertext from external systems (e.g. .NET, Java,
  /// OpenSSL) that return the IV/nonce, ciphertext, and auth tag as
  /// separate fields rather than a combined buffer.
  ///
  /// The [iv] parameter accepts both IV values (used by CBC/CTR/CFB/OFB) and
  /// nonce values (used by GCM/CCM) — they are equivalent. See class-level
  /// documentation for mode-specific naming conventions.
  ///
  /// For non-authenticated modes (ECB, CBC, CTR, CFB, OFB), the [tag]
  /// parameter is accepted but not included in the decryption buffer.
  ///
  /// Throws [FortisConfigException] if any parameter contains invalid Base64.
  /// Throws [FortisEncryptionException] if decryption or authentication fails.
  Uint8List decryptFields({
    required String iv,
    required String data,
    required String tag,
  }) {
    try {
      final ivBytes = base64Decode(iv);
      final dataBytes = base64Decode(data);
      final tagBytes = base64Decode(tag);
      return decrypt(_assembleBuffer(iv: ivBytes, data: dataBytes, tag: tagBytes));
    } on FortisEncryptionException {
      rethrow;
    } on FortisConfigException {
      rethrow;
    } catch (e) {
      throw FortisConfigException('Invalid Base64 in decryptFields: $e');
    }
  }

  /// Decrypts using separate Base64-encoded fields and returns a UTF-8 string.
  ///
  /// Equivalent to calling [decryptFields] and then UTF-8 decoding the result.
  ///
  /// See [decryptFields] for parameter documentation.
  String decryptFieldsToString({
    required String iv,
    required String data,
    required String tag,
  }) => utf8.decode(decryptFields(iv: iv, data: data, tag: tag));

  /// Decrypts using a [Map] with separate Base64-encoded fields.
  ///
  /// Accepted keys:
  /// - `'iv'` **or** `'nonce'` (exactly one must be present, not both)
  /// - `'data'` (required)
  /// - `'tag'` (required)
  ///
  /// All values must be Base64-encoded strings.
  ///
  /// Example — accepted:
  /// ```dart
  /// {'iv':    '...', 'data': '...', 'tag': '...'}
  /// {'nonce': '...', 'data': '...', 'tag': '...'}
  /// ```
  ///
  /// Example — rejected with [FortisConfigException]:
  /// ```dart
  /// {'iv': '...', 'nonce': '...', 'data': '...', 'tag': '...'}  // both present
  /// {'data': '...', 'tag': '...'}                                 // no iv/nonce
  /// {'iv': '...', 'tag': '...'}                                   // missing data
  /// {'iv': '...', 'data': '...'}                                  // missing tag
  /// ```
  ///
  /// Throws [FortisConfigException] if the map structure is invalid or any
  /// value contains invalid Base64.
  /// Throws [FortisEncryptionException] if decryption or authentication fails.
  Uint8List decryptMap(Map<String, String> payload) {
    final hasIv = payload.containsKey('iv');
    final hasNonce = payload.containsKey('nonce');

    if (hasIv && hasNonce) {
      throw FortisConfigException(
        "decryptMap: payload must not contain both 'iv' and 'nonce'.",
      );
    }
    if (!hasIv && !hasNonce) {
      throw FortisConfigException(
        "decryptMap: payload must contain 'iv' or 'nonce'.",
      );
    }

    final data = payload['data'];
    if (data == null) {
      throw FortisConfigException("decryptMap: payload must contain 'data'.");
    }

    final tag = payload['tag'];
    if (tag == null) {
      throw FortisConfigException("decryptMap: payload must contain 'tag'.");
    }

    final ivStr = hasIv ? payload['iv']! : payload['nonce']!;
    return decryptFields(iv: ivStr, data: data, tag: tag);
  }

  /// Decrypts using a [Map] with separate Base64-encoded fields and returns
  /// a UTF-8 string.
  ///
  /// Equivalent to calling [decryptMap] and then UTF-8 decoding the result.
  ///
  /// See [decryptMap] for parameter documentation.
  String decryptMapToString(Map<String, String> payload) =>
      utf8.decode(decryptMap(payload));

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

  /// Reassembles the canonical buffer format from separate fields.
  ///
  /// Mode-specific layouts:
  /// - ECB: `[data]` — iv and tag are ignored
  /// - CBC / CTR / CFB / OFB: `[iv | data]` — tag is ignored
  /// - GCM / CCM: `[iv | data | tag]`
  Uint8List _assembleBuffer({
    required Uint8List iv,
    required Uint8List data,
    required Uint8List tag,
  }) => switch (_mode) {
    AesMode.ecb => data,
    AesMode.cbc ||
    AesMode.ctr ||
    AesMode.cfb ||
    AesMode.ofb => Uint8List(iv.length + data.length)
        ..setAll(0, iv)
        ..setAll(iv.length, data),
    AesMode.gcm ||
    AesMode.ccm => Uint8List(iv.length + data.length + tag.length)
        ..setAll(0, iv)
        ..setAll(iv.length, data)
        ..setAll(iv.length + data.length, tag),
  };

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
