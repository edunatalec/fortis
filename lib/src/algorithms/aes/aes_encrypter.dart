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
///     .encrypter(myKey);
/// ```
///
/// ## IV / nonce management
///
/// The IV or nonce is generated automatically on each call to [encrypt] and
/// prepended to the ciphertext. For authenticated modes (GCM, CCM), the auth
/// tag is appended automatically. Developers never manage IVs or auth tags
/// manually in the default flow.
///
/// Modes CBC, CTR, CFB, and OFB use the term **IV** internally and in
/// documentation. Modes GCM and CCM use the term **nonce**. They are
/// equivalent concepts; the `nonce` parameter in [encrypt] accepts both.
///
/// ## Buffer layouts
///
/// - ECB: `[ciphertext]`
/// - CBC / CTR / CFB / OFB: `[iv (16 bytes) | ciphertext]`
/// - GCM: `[nonce (12 bytes) | ciphertext | tag (16 bytes)]`
/// - CCM: `[nonce (11 bytes) | ciphertext | tag (16 bytes)]`
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
  /// The optional [nonce] parameter allows callers to supply a specific
  /// IV or nonce — useful for interoperability with external systems that
  /// require a deterministic nonce. When omitted, a cryptographically random
  /// value is generated automatically.
  ///
  /// - For GCM the nonce must be exactly 12 bytes.
  /// - For CCM the nonce must be exactly 11 bytes.
  /// - For CBC, CTR, CFB, and OFB the IV must be exactly 16 bytes.
  /// - ECB does not use a nonce; passing one throws [FortisConfigException].
  ///
  /// Throws [FortisConfigException] if:
  /// - [AesPadding.noPadding] is used with data that is not a multiple of 16.
  /// - [nonce] is provided with the wrong size for the mode.
  /// - [nonce] is provided for ECB mode.
  ///
  /// Throws [FortisEncryptionException] if encryption fails.
  Uint8List encrypt(Uint8List plaintext, {Uint8List? nonce}) {
    try {
      return switch (_mode) {
        AesMode.ecb => _encryptEcb(plaintext, nonce),
        AesMode.cbc => _encryptCbc(plaintext, nonce),
        AesMode.ctr => _encryptCtr(plaintext, nonce),
        AesMode.cfb => _encryptCfb(plaintext, nonce),
        AesMode.ofb => _encryptOfb(plaintext, nonce),
        AesMode.gcm => _encryptGcm(plaintext, nonce),
        AesMode.ccm => _encryptCcm(plaintext, nonce),
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
  Uint8List encryptString(String plaintext, {Uint8List? nonce}) =>
      encrypt(Uint8List.fromList(utf8.encode(plaintext)), nonce: nonce);

  /// Encrypts [data] and returns the ciphertext as a Base64 string.
  String encryptToBase64(Uint8List data, {Uint8List? nonce}) =>
      base64Encode(encrypt(data, nonce: nonce));

  /// Encrypts a UTF-8 [plaintext] string and returns a Base64 string.
  String encryptStringToBase64(String plaintext, {Uint8List? nonce}) =>
      base64Encode(encryptString(plaintext, nonce: nonce));

  // ──────────────────────────────────────────────
  // Block modes
  // ──────────────────────────────────────────────

  Uint8List _encryptEcb(Uint8List plaintext, Uint8List? nonce) {
    if (nonce != null) {
      throw FortisConfigException('ECB mode does not use a nonce/IV.');
    }
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

  Uint8List _encryptCbc(Uint8List plaintext, Uint8List? nonce) {
    final padding = _padding!;
    if (padding == AesPadding.noPadding && plaintext.length % 16 != 0) {
      throw FortisConfigException(
        'AesPadding.noPadding requires data length to be a multiple of 16 bytes, '
        'got ${plaintext.length}.',
      );
    }
    final iv = _resolveNonce(16, nonce, 'CBC');
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

  Uint8List _encryptCtr(Uint8List plaintext, Uint8List? nonce) {
    final iv = _resolveNonce(16, nonce, 'CTR');
    final cipher = CTRStreamCipher(AESEngine());
    cipher.init(true, ParametersWithIV(KeyParameter(_key.toBytes()), iv));
    final ciphertext = Uint8List(plaintext.length);
    cipher.processBytes(plaintext, 0, plaintext.length, ciphertext, 0);
    return _prepend(iv, ciphertext);
  }

  Uint8List _encryptCfb(Uint8List plaintext, Uint8List? nonce) {
    final iv = _resolveNonce(16, nonce, 'CFB');
    final cipher = CFBBlockCipher(AESEngine(), 16);
    cipher.init(true, ParametersWithIV(KeyParameter(_key.toBytes()), iv));
    return _prepend(iv, _processStreamBlockCipher(cipher, plaintext));
  }

  Uint8List _encryptOfb(Uint8List plaintext, Uint8List? nonce) {
    final iv = _resolveNonce(16, nonce, 'OFB');
    final cipher = OFBBlockCipher(AESEngine(), 16);
    cipher.init(true, ParametersWithIV(KeyParameter(_key.toBytes()), iv));
    return _prepend(iv, _processStreamBlockCipher(cipher, plaintext));
  }

  // ──────────────────────────────────────────────
  // Authenticated modes
  // ──────────────────────────────────────────────

  Uint8List _encryptGcm(Uint8List plaintext, Uint8List? nonce) {
    final iv = _resolveNonce(12, nonce, 'GCM'); // NIST SP 800-38D: 96 bits
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

  Uint8List _encryptCcm(Uint8List plaintext, Uint8List? nonce) {
    final iv = _resolveNonce(11, nonce, 'CCM'); // RFC 3610: 11-byte nonce
    final cipher = CCMBlockCipher(AESEngine());
    cipher.init(
      true,
      AEADParameters(
        KeyParameter(_key.toBytes()),
        _tagSizeBits,
        iv,
        _aad ?? Uint8List(0),
      ),
    );
    return _prepend(iv, cipher.process(plaintext));
  }

  // ──────────────────────────────────────────────
  // Helpers
  // ──────────────────────────────────────────────

  /// Resolves the IV/nonce to use.
  ///
  /// If [provided] is non-null, validates its size against [expectedSize].
  /// If null, generates a random byte array of [expectedSize].
  Uint8List _resolveNonce(int expectedSize, Uint8List? provided, String mode) {
    if (provided != null && provided.length != expectedSize) {
      throw FortisConfigException(
        '$mode nonce must be $expectedSize bytes, got ${provided.length}.',
      );
    }
    return provided ?? _randomBytes(expectedSize);
  }

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
      const blockSize = 16;
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
