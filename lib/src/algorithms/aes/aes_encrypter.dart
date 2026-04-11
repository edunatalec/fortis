import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:pointycastle/export.dart';

import '../../exceptions/fortis_config_exception.dart';
import '../../exceptions/fortis_encryption_exception.dart';
import 'aes_key.dart';
import 'aes_mode.dart';
import 'aes_padding.dart';

/// Encrypts data using AES.
///
/// Obtain via the builder:
/// ```dart
/// final encrypter = Fortis.aes()
///     .mode(AesMode.gcm)
///     .key(myKey)
///     .encrypter();
/// ```
///
/// The IV is generated automatically and prepended to the ciphertext.
/// For authenticated modes (GCM, CCM), the auth tag is appended automatically
/// by PointyCastle. Developers never manage IVs or auth tags manually.
class AesEncrypter {
  final AesMode _mode;
  final FortisAesKey _key;
  final AesPadding? _padding;
  final Uint8List? _aad;
  final int _tagSizeBits;

  /// Creates an encrypter for block modes (ECB, CBC).
  AesEncrypter.block({
    required AesMode mode,
    required FortisAesKey key,
    required AesPadding padding,
  }) : _mode = mode,
       _key = key,
       _padding = padding,
       _aad = null,
       _tagSizeBits = 128;

  /// Creates an encrypter for stream modes (CTR, CFB, OFB).
  AesEncrypter.stream({required AesMode mode, required FortisAesKey key})
    : _mode = mode,
      _key = key,
      _padding = null,
      _aad = null,
      _tagSizeBits = 128;

  /// Creates an encrypter for authenticated modes (GCM, CCM).
  AesEncrypter.auth({
    required AesMode mode,
    required FortisAesKey key,
    Uint8List? aad,
    int tagSizeBits = 128,
  }) : _mode = mode,
       _key = key,
       _padding = null,
       _aad = aad,
       _tagSizeBits = tagSizeBits;

  /// Encrypts [plaintext] and returns ciphertext with the IV/nonce prepended.
  ///
  /// Throws [FortisConfigException] if [AesPadding.noPadding] is used with
  /// data that is not a multiple of 16 bytes.
  /// Throws [FortisEncryptionException] if encryption fails.
  Uint8List encrypt(Uint8List plaintext) {
    try {
      return switch (_mode) {
        AesMode.ecb => _encryptEcb(plaintext),
        AesMode.cbc => _encryptCbc(plaintext),
        AesMode.ctr => _encryptCtr(plaintext),
        AesMode.cfb => _encryptCfb(plaintext),
        AesMode.ofb => _encryptOfb(plaintext),
        AesMode.gcm => _encryptGcm(plaintext),
        AesMode.ccm => _encryptCcm(plaintext),
      };
    } on FortisEncryptionException {
      rethrow;
    } on FortisConfigException {
      rethrow;
    } catch (e) {
      throw FortisEncryptionException('AES encryption failed: $e');
    }
  }

  /// Encrypts a UTF-8 [plaintext] string and returns ciphertext bytes.
  Uint8List encryptString(String plaintext) =>
      encrypt(Uint8List.fromList(utf8.encode(plaintext)));

  /// Encrypts [data] and returns the ciphertext as a Base64 string.
  String encryptToBase64(Uint8List data) => base64Encode(encrypt(data));

  /// Encrypts a UTF-8 [plaintext] string and returns a Base64 string.
  String encryptStringToBase64(String plaintext) =>
      base64Encode(encryptString(plaintext));

  // ──────────────────────────────────────────────
  // Block modes
  // ──────────────────────────────────────────────

  Uint8List _encryptEcb(Uint8List plaintext) {
    final padding = _padding!;
    if (padding == AesPadding.noPadding && plaintext.length % 16 != 0) {
      throw FortisConfigException(
        'AesPadding.noPadding requires data length to be a multiple of 16 bytes, '
        'got ${plaintext.length}.',
      );
    }
    final cipher = _paddedBlockCipher(padding, ECBBlockCipher(AESEngine()));
    cipher.init(
      true,
      PaddedBlockCipherParameters(KeyParameter(_key.toBytes()), null),
    );
    return cipher.process(plaintext);
  }

  Uint8List _encryptCbc(Uint8List plaintext) {
    final padding = _padding!;
    if (padding == AesPadding.noPadding && plaintext.length % 16 != 0) {
      throw FortisConfigException(
        'AesPadding.noPadding requires data length to be a multiple of 16 bytes, '
        'got ${plaintext.length}.',
      );
    }
    final iv = _randomBytes(16);
    final cipher = _paddedBlockCipher(padding, CBCBlockCipher(AESEngine()));
    cipher.init(
      true,
      PaddedBlockCipherParameters(
        ParametersWithIV(KeyParameter(_key.toBytes()), iv),
        null,
      ),
    );
    return _prepend(iv, cipher.process(plaintext));
  }

  // ──────────────────────────────────────────────
  // Stream modes
  // ──────────────────────────────────────────────

  Uint8List _encryptCtr(Uint8List plaintext) {
    final iv = _randomBytes(16);
    final cipher = CTRStreamCipher(AESEngine());
    cipher.init(true, ParametersWithIV(KeyParameter(_key.toBytes()), iv));
    final ciphertext = Uint8List(plaintext.length);
    cipher.processBytes(plaintext, 0, plaintext.length, ciphertext, 0);
    return _prepend(iv, ciphertext);
  }

  Uint8List _encryptCfb(Uint8List plaintext) {
    final iv = _randomBytes(16);
    final cipher = CFBBlockCipher(AESEngine(), 16);
    cipher.init(true, ParametersWithIV(KeyParameter(_key.toBytes()), iv));
    return _prepend(iv, _processStreamBlockCipher(cipher, plaintext));
  }

  Uint8List _encryptOfb(Uint8List plaintext) {
    final iv = _randomBytes(16);
    final cipher = OFBBlockCipher(AESEngine(), 16);
    cipher.init(true, ParametersWithIV(KeyParameter(_key.toBytes()), iv));
    return _prepend(iv, _processStreamBlockCipher(cipher, plaintext));
  }

  // ──────────────────────────────────────────────
  // Authenticated modes
  // ──────────────────────────────────────────────

  Uint8List _encryptGcm(Uint8List plaintext) {
    final iv = _randomBytes(12); // NIST SP 800-38D: 96 bits (12 bytes) recomendado
    final cipher = GCMBlockCipher(AESEngine());
    cipher.init(
      true,
      AEADParameters(
        KeyParameter(_key.toBytes()),
        _tagSizeBits,
        iv,
        _aad ?? Uint8List(0),
      ),
    );
    // process() returns ciphertext || auth_tag (PointyCastle appends the tag)
    return _prepend(iv, cipher.process(plaintext));
  }

  Uint8List _encryptCcm(Uint8List plaintext) {
    final nonce = _randomBytes(12); // CCM uses 12-byte nonce per RFC 3610
    final cipher = CCMBlockCipher(AESEngine());
    cipher.init(
      true,
      AEADParameters(
        KeyParameter(_key.toBytes()),
        _tagSizeBits,
        nonce,
        _aad ?? Uint8List(0),
      ),
    );
    return _prepend(nonce, cipher.process(plaintext));
  }

  // ──────────────────────────────────────────────
  // Helpers
  // ──────────────────────────────────────────────

  /// Processa [input] com [cipher] bloco a bloco, sem padding.
  ///
  /// Blocos completos são processados diretamente. O último bloco parcial
  /// é preenchido com zeros, processado, e apenas os bytes necessários são
  /// copiados — garantindo que a saída tenha o mesmo tamanho da entrada.
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
    // noPadding: data is pre-validated; use PKCS7 which adds 0 effective padding
    // when the data is already block-aligned (won't be reached for misaligned data).
    AesPadding.noPadding => PKCS7Padding(),
  };

  Uint8List _randomBytes(int length) {
    final rng = Random.secure();
    return Uint8List.fromList(List.generate(length, (_) => rng.nextInt(256)));
  }

  Uint8List _prepend(Uint8List prefix, Uint8List data) =>
      Uint8List(prefix.length + data.length)
        ..setAll(0, prefix)
        ..setAll(prefix.length, data);
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
      final blockSize = 16;
      final padLen = blockSize - (data.length % blockSize);
      final out = Uint8List(data.length + padLen);
      out.setAll(0, data);
      return out; // zero bytes are already the default
    } else {
      final padLen = padCount(data);
      return data.sublist(0, data.length - padLen);
    }
  }
}
