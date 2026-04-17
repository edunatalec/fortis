import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:pointycastle/export.dart';

import '../../exceptions/fortis_config_exception.dart';
import '../../exceptions/fortis_encryption_exception.dart';
import 'aes_constants.dart';
import 'aes_auth_payload.dart';
import 'aes_key.dart';
import 'aes_mode.dart';
import 'aes_padding.dart';
import 'aes_payload.dart';
import 'aes_paddings_impl.dart';

/// A symmetric AES cipher that encrypts and decrypts with the same key.
///
/// `AesCipher` is a `sealed` hierarchy with three concrete variants — each one
/// exposed by a different mode builder so hover and autocomplete surface only
/// the methods that make sense for the chosen mode:
///
/// - [AesEcbCipher] — [AesMode.ecb] only. No IV, no authentication.
///   Built via `Fortis.aes().ecb().cipher(key)`.
/// - [AesStandardCipher] — [AesMode.cbc], [AesMode.ctr], [AesMode.cfb],
///   [AesMode.ofb]. Uses a 16-byte IV and returns an [AesPayload] from
///   [AesStandardCipher.encryptToPayload].
/// - [AesAuthCipher] — [AesMode.gcm], [AesMode.ccm]. Authenticated encryption
///   (AEAD) that returns an [AesAuthPayload] (with `tag`) from
///   [AesAuthCipher.encryptToPayload].
///
/// Example (GCM — recommended default):
///
/// ```dart
/// final key = await Fortis.aes().generateKey();              // 256-bit
/// final cipher = Fortis.aes().gcm().cipher(key);             // AesAuthCipher
/// final payload = cipher.encryptToPayload('hello fortis');    // AesAuthPayload
/// final plaintext = cipher.decryptToString(payload);          // 'hello fortis'
/// ```
///
/// ## IV management
///
/// The IV is generated automatically on each call to [encrypt] and prepended
/// to the ciphertext. For authenticated modes (GCM, CCM), the auth tag is
/// appended automatically. On [decrypt], the IV is extracted automatically
/// from the ciphertext prefix, and the auth tag is verified automatically for
/// authenticated modes.
///
/// Fortis uses **IV** uniformly across the public API. NIST SP 800-38C calls
/// the same value a *nonce* for CCM — same concept, same wire bytes, just a
/// different spec label.
///
/// ## Buffer layouts
///
/// - ECB: `[ciphertext]`
/// - CBC / CTR / CFB / OFB: `[iv (16 bytes) | ciphertext]`
/// - GCM: `[iv (default 12 bytes) | ciphertext | tag (16 bytes)]`
/// - CCM: `[iv (default 11 bytes) | ciphertext | tag (16 bytes)]`
sealed class AesCipher {
  final AesMode _mode;
  final FortisAesKey _key;
  final AesPadding? _padding;
  final Uint8List? _aad;
  final int _tagSizeBits;
  final int _ivSize;

  AesCipher._({
    required AesMode mode,
    required FortisAesKey key,
    AesPadding? padding,
    Uint8List? aad,
    int tagSizeBits = 128,
    int ivSize = 0,
  }) : _mode = mode,
       _key = key,
       _padding = padding,
       _aad = aad,
       _tagSizeBits = tagSizeBits,
       _ivSize = ivSize;

  /// Encrypts [plaintext] and returns the combined buffer as raw bytes.
  ///
  /// [plaintext] accepts:
  /// - [Uint8List]: raw bytes, encrypted as-is.
  /// - [String]: UTF-8 encoded before encryption.
  ///
  /// The optional [iv] provides the initialization vector. When omitted, a
  /// cryptographically secure random value of the correct size is generated
  /// automatically — this is the recommended behavior.
  ///
  /// Required [iv] sizes by mode:
  /// - ECB: must be `null` (ECB has no IV).
  /// - CBC / CFB / OFB / CTR: exactly 16 bytes.
  /// - GCM: size configured via [AesGcmModeBuilder.ivSize] (default 12).
  /// - CCM: size configured via [AesCcmModeBuilder.ivSize] (default 11).
  ///
  /// Example:
  /// ```dart
  /// final cipher = Fortis.aes().gcm().cipher(key);
  /// final bytes = cipher.encrypt('hello fortis');
  /// ```
  ///
  /// Throws [FortisConfigException] if [plaintext] is not a [String] or
  /// [Uint8List], or if [iv] has the wrong size for the mode.
  Uint8List encrypt(Object plaintext, {Uint8List? iv}) {
    return _encryptBytes(_toBytes(plaintext), iv: iv);
  }

  /// Encrypts [plaintext] and returns the result as a Base64-encoded string.
  ///
  /// See [encrypt] for accepted [plaintext] types and [iv] behavior.
  ///
  /// Example:
  /// ```dart
  /// final cipher = Fortis.aes().gcm().cipher(key);
  /// final base64 = cipher.encryptToString('hello fortis');
  /// ```
  String encryptToString(Object plaintext, {Uint8List? iv}) {
    return base64Encode(encrypt(plaintext, iv: iv));
  }

  /// Decrypts [input] and returns the plaintext as raw bytes.
  ///
  /// [input] accepts:
  ///
  /// - [Uint8List]: the combined buffer (see class-level "Buffer layouts").
  /// - [String]: a Base64-encoded version of the combined buffer.
  /// - [Map<String, String>]: a map with Base64-encoded fields. Must contain
  ///   either `'iv'` or `'nonce'` (not both) plus `'data'`. Authenticated
  ///   modes also require `'tag'`.
  /// - [AesAuthPayload]: only on [AesAuthCipher] (GCM/CCM).
  /// - [AesPayload]: only on [AesStandardCipher] (CBC/CTR/CFB/OFB).
  ///
  /// Example:
  /// ```dart
  /// final cipher = Fortis.aes().gcm().cipher(key);
  /// final bytes = cipher.decrypt(ciphertext); // Uint8List, String, Map, or payload
  /// ```
  ///
  /// Throws [FortisConfigException] for unsupported input types, missing
  /// fields, or a payload type that doesn't match the cipher's mode.
  Uint8List decrypt(Object input) {
    if (input is Uint8List) {
      return _decryptBytes(input);
    }

    if (input is String) {
      return _decryptBytes(_decodeBase64(input, 'ciphertext'));
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
  ///
  /// Example:
  /// ```dart
  /// final cipher = Fortis.aes().gcm().cipher(key);
  /// final text = cipher.decryptToString(ciphertext);
  /// ```
  String decryptToString(Object input) {
    return utf8.decode(decrypt(input));
  }

  Uint8List _encryptBytes(Uint8List plaintext, {Uint8List? iv}) {
    try {
      return switch (_mode) {
        AesMode.ecb => _encryptEcb(plaintext, iv),
        AesMode.cbc => _encryptCbc(plaintext, iv),
        AesMode.ctr => _encryptCtr(plaintext, iv),
        AesMode.cfb => _encryptCfb(plaintext, iv),
        AesMode.ofb => _encryptOfb(plaintext, iv),
        AesMode.gcm => _encryptGcm(plaintext, iv),
        AesMode.ccm => _encryptCcm(plaintext, iv),
      };
    } on FortisEncryptionException {
      rethrow;
    } on FortisConfigException {
      rethrow;
    } catch (e) {
      throw FortisEncryptionException('AES encryption failed: $e');
    }
  }

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

    final ivKey = hasIv ? 'iv' : 'nonce';
    final ivBytes = _decodeBase64(map[ivKey]!, ivKey);
    final dataBytes = _decodeBase64(map['data']!, 'data');

    if (isAuth) {
      final tagBytes = _decodeBase64(map['tag']!, 'tag');

      return Uint8List.fromList([...ivBytes, ...dataBytes, ...tagBytes]);
    }

    return Uint8List.fromList([...ivBytes, ...dataBytes]);
  }

  Uint8List _decodeBase64(String input, String field) {
    try {
      return base64Decode(input);
    } on FormatException catch (e) {
      throw FortisConfigException("Invalid Base64 in '$field': ${e.message}");
    }
  }

  Uint8List _encryptEcb(Uint8List plaintext, Uint8List? iv) {
    if (iv != null) {
      throw FortisConfigException('ECB mode does not use an IV.');
    }

    final padding = _padding!;

    if (padding == AesPadding.noPadding &&
        plaintext.length % aesBlockSize != 0) {
      throw FortisConfigException(
        'AesPadding.noPadding requires data length to be a multiple of $aesBlockSize bytes, '
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

  Uint8List _encryptCbc(Uint8List plaintext, Uint8List? iv) {
    final padding = _padding!;

    if (padding == AesPadding.noPadding &&
        plaintext.length % aesBlockSize != 0) {
      throw FortisConfigException(
        'AesPadding.noPadding requires data length to be a multiple of $aesBlockSize bytes, '
        'got ${plaintext.length}.',
      );
    }

    final resolvedIv = _resolveIv(standardIvSize, iv, 'CBC');
    final cipher = _paddedBlockCipher(padding, CBCBlockCipher(AESEngine()));

    cipher.init(
      true,
      PaddedBlockCipherParameters(
        ParametersWithIV(KeyParameter(_key.toBytes()), resolvedIv),
        null,
      ),
    );

    return _prepend(resolvedIv, cipher.process(plaintext));
  }

  Uint8List _encryptCtr(Uint8List plaintext, Uint8List? iv) {
    final resolvedIv = _resolveIv(standardIvSize, iv, 'CTR');
    final cipher = CTRStreamCipher(AESEngine());
    cipher.init(
      true,
      ParametersWithIV(KeyParameter(_key.toBytes()), resolvedIv),
    );
    final ciphertext = Uint8List(plaintext.length);
    cipher.processBytes(plaintext, 0, plaintext.length, ciphertext, 0);
    return _prepend(resolvedIv, ciphertext);
  }

  Uint8List _encryptCfb(Uint8List plaintext, Uint8List? iv) {
    final resolvedIv = _resolveIv(standardIvSize, iv, 'CFB');
    final cipher = CFBBlockCipher(AESEngine(), aesBlockSize);

    cipher.init(
      true,
      ParametersWithIV(KeyParameter(_key.toBytes()), resolvedIv),
    );

    return _prepend(resolvedIv, _processStreamBlockCipher(cipher, plaintext));
  }

  Uint8List _encryptOfb(Uint8List plaintext, Uint8List? iv) {
    final resolvedIv = _resolveIv(standardIvSize, iv, 'OFB');
    final cipher = OFBBlockCipher(AESEngine(), aesBlockSize);

    cipher.init(
      true,
      ParametersWithIV(KeyParameter(_key.toBytes()), resolvedIv),
    );

    return _prepend(resolvedIv, _processStreamBlockCipher(cipher, plaintext));
  }

  Uint8List _encryptGcm(Uint8List plaintext, Uint8List? iv) {
    final resolvedIv = _resolveIv(_ivSize, iv, 'GCM'); // NIST SP 800-38D
    final cipher = GCMBlockCipher(AESEngine());

    cipher.init(
      true,
      AEADParameters(
        KeyParameter(_key.toBytes()),
        _tagSizeBits,
        resolvedIv,
        _aad ?? Uint8List(0),
      ),
    );

    // process() returns ciphertext || auth_tag (PointyCastle appends the tag)
    return _prepend(resolvedIv, cipher.process(plaintext));
  }

  Uint8List _encryptCcm(Uint8List plaintext, Uint8List? iv) {
    final resolvedIv = _resolveIv(_ivSize, iv, 'CCM'); // NIST SP 800-38C
    final cipher = CCMBlockCipher(AESEngine());

    cipher.init(
      true,
      AEADParameters(
        KeyParameter(_key.toBytes()),
        _tagSizeBits,
        resolvedIv,
        _aad ?? Uint8List(0),
      ),
    );

    return _prepend(resolvedIv, cipher.process(plaintext));
  }

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
    if (ciphertext.length < standardIvSize) {
      throw FortisEncryptionException(
        'Ciphertext too short for CBC mode '
        '(expected at least $standardIvSize bytes for IV, got ${ciphertext.length}).',
      );
    }

    final iv = ciphertext.sublist(0, standardIvSize);
    final body = ciphertext.sublist(standardIvSize);
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

  Uint8List _decryptCtr(Uint8List ciphertext) {
    if (ciphertext.length < standardIvSize) {
      throw FortisEncryptionException(
        'Ciphertext too short for CTR mode '
        '(expected at least $standardIvSize bytes for IV, got ${ciphertext.length}).',
      );
    }

    final iv = ciphertext.sublist(0, standardIvSize);
    final body = ciphertext.sublist(standardIvSize);
    final cipher = CTRStreamCipher(AESEngine());

    cipher.init(false, ParametersWithIV(KeyParameter(_key.toBytes()), iv));

    final output = Uint8List(body.length);

    cipher.processBytes(body, 0, body.length, output, 0);

    return output;
  }

  Uint8List _decryptCfb(Uint8List ciphertext) {
    if (ciphertext.length < standardIvSize) {
      throw FortisEncryptionException(
        'Ciphertext too short for CFB mode '
        '(expected at least $standardIvSize bytes for IV, got ${ciphertext.length}).',
      );
    }

    final iv = ciphertext.sublist(0, standardIvSize);
    final body = ciphertext.sublist(standardIvSize);
    final cipher = CFBBlockCipher(AESEngine(), aesBlockSize);

    cipher.init(false, ParametersWithIV(KeyParameter(_key.toBytes()), iv));

    return _processStreamBlockCipher(cipher, body);
  }

  Uint8List _decryptOfb(Uint8List ciphertext) {
    if (ciphertext.length < standardIvSize) {
      throw FortisEncryptionException(
        'Ciphertext too short for OFB mode '
        '(expected at least $standardIvSize bytes for IV, got ${ciphertext.length}).',
      );
    }

    final iv = ciphertext.sublist(0, standardIvSize);
    final body = ciphertext.sublist(standardIvSize);
    final cipher = OFBBlockCipher(AESEngine(), aesBlockSize);

    cipher.init(false, ParametersWithIV(KeyParameter(_key.toBytes()), iv));

    return _processStreamBlockCipher(cipher, body);
  }

  Uint8List _decryptGcm(Uint8List ciphertext) {
    if (ciphertext.length < _ivSize) {
      throw FortisEncryptionException(
        'Ciphertext too short for GCM mode '
        '(expected at least $_ivSize bytes for IV, got ${ciphertext.length}).',
      );
    }

    final iv = ciphertext.sublist(0, _ivSize); // NIST SP 800-38D
    final body = ciphertext.sublist(_ivSize); // ciphertext + auth tag
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
    if (ciphertext.length < _ivSize) {
      throw FortisEncryptionException(
        'Ciphertext too short for CCM mode '
        '(expected at least $_ivSize bytes for IV, got ${ciphertext.length}).',
      );
    }

    final iv = ciphertext.sublist(0, _ivSize); // NIST SP 800-38C
    final body = ciphertext.sublist(_ivSize);
    final cipher = CCMBlockCipher(AESEngine());

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
        'CCM authentication failed. The ciphertext may have been tampered with, '
        'or the AAD does not match what was used during encryption. ($e)',
      );
    }
  }

  Uint8List _toBytes(Object plaintext) {
    if (plaintext is Uint8List) return plaintext;

    if (plaintext is String) {
      return Uint8List.fromList(utf8.encode(plaintext));
    }

    throw FortisConfigException(
      'Unsupported plaintext type: ${plaintext.runtimeType}. '
      'Expected String or Uint8List.',
    );
  }

  Uint8List _resolveIv(int expectedSize, Uint8List? provided, String mode) {
    if (provided != null && provided.length != expectedSize) {
      throw FortisConfigException(
        '$mode IV must be $expectedSize bytes, got ${provided.length}.',
      );
    }

    return provided ?? _randomBytes(expectedSize);
  }

  Uint8List _processStreamBlockCipher(BlockCipher cipher, Uint8List input) {
    final output = Uint8List(input.length);
    var offset = 0;

    while (offset + aesBlockSize <= input.length) {
      cipher.processBlock(input, offset, output, offset);
      offset += aesBlockSize;
    }

    if (offset < input.length) {
      final remaining = input.length - offset;
      final tmp = Uint8List(aesBlockSize)
        ..setRange(0, remaining, input, offset);
      final tmpOut = Uint8List(aesBlockSize);

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
    AesPadding.zeroPadding => ZeroBytePaddingImpl(),
    AesPadding.noPadding => NoPaddingImpl(),
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

/// A cipher for AES in [AesMode.ecb] mode.
///
/// ⚠️ ECB is insecure for most use cases — identical plaintext blocks produce
/// identical ciphertext blocks, revealing patterns. Only use for legacy
/// interoperability. Prefer [AesAuthCipher] (GCM) in new designs.
///
/// ECB does not use an IV and does not support payload encoding, so
/// `encryptToPayload` is intentionally absent from this class.
///
/// Built via:
/// ```dart
/// final cipher = Fortis.aes().ecb().cipher(key); // AesEcbCipher
/// final ciphertext = cipher.encrypt(dataAlignedTo16Bytes);
/// ```
final class AesEcbCipher extends AesCipher {
  /// Creates a cipher for AES-ECB with the given [padding]. Prefer the
  /// builder: `Fortis.aes().ecb().padding(AesPadding.pkcs7).cipher(key)`.
  ///
  /// Example:
  /// ```dart
  /// final cipher = AesEcbCipher(key: key, padding: AesPadding.pkcs7);
  /// ```
  AesEcbCipher({required super.key, required AesPadding padding})
    : super._(mode: AesMode.ecb, padding: padding);
}

/// A cipher for AES modes that use an IV but do not authenticate:
/// [AesMode.cbc], [AesMode.ctr], [AesMode.cfb], [AesMode.ofb].
///
/// These modes guarantee confidentiality but not integrity. For authenticated
/// encryption (recommended for most use cases) see [AesAuthCipher].
///
/// Built via the matching mode builder:
/// ```dart
/// final cipher = Fortis.aes().cbc().cipher(key); // AesStandardCipher
/// final payload = cipher.encryptToPayload('hello'); // AesPayload
/// final plaintext = cipher.decryptToString(payload);
/// ```
///
/// This class is the only place where [encryptToPayload] returns [AesPayload]
/// (as opposed to [AesAuthPayload] on [AesAuthCipher]), so the return type is
/// statically inferred — no cast required.
final class AesStandardCipher extends AesCipher {
  /// Creates a standard (non-authenticated) AES cipher for CBC, CTR, CFB,
  /// or OFB. Prefer the builder:
  ///
  /// ```dart
  /// final cipher = Fortis.aes().cbc().cipher(key); // or .ctr() / .cfb() / .ofb()
  /// ```
  ///
  /// [padding] is required for [AesMode.cbc] and must be `null` for stream
  /// modes ([AesMode.ctr], [AesMode.cfb], [AesMode.ofb]).
  ///
  /// Throws [FortisConfigException] if [mode] is not one of CBC/CTR/CFB/OFB,
  /// if CBC is used without a [padding], or if a stream mode is combined
  /// with a non-null [padding].
  factory AesStandardCipher({
    required AesMode mode,
    required FortisAesKey key,
    AesPadding? padding,
  }) {
    const streamModes = {AesMode.ctr, AesMode.cfb, AesMode.ofb};
    if (mode != AesMode.cbc && !streamModes.contains(mode)) {
      throw FortisConfigException(
        'AesStandardCipher only supports CBC, CTR, CFB, or OFB, '
        'got ${mode.name.toUpperCase()}.',
      );
    }
    if (mode == AesMode.cbc && padding == null) {
      throw const FortisConfigException(
        'CBC mode requires a padding scheme. Pass an AesPadding value.',
      );
    }
    if (streamModes.contains(mode) && padding != null) {
      throw FortisConfigException(
        'Stream mode ${mode.name.toUpperCase()} does not use padding; '
        'pass padding: null.',
      );
    }
    return AesStandardCipher._internal(mode: mode, key: key, padding: padding);
  }

  AesStandardCipher._internal({
    required super.mode,
    required super.key,
    super.padding,
  }) : super._();

  /// Encrypts [plaintext] and returns a structured [AesPayload].
  ///
  /// The payload carries the IV and ciphertext as Base64 strings — handy for
  /// transports that want separate fields (JSON, DB columns, headers).
  ///
  /// Example:
  /// ```dart
  /// final cipher = Fortis.aes().cbc().cipher(key); // AesStandardCipher
  /// final payload = cipher.encryptToPayload('hello'); // AesPayload (no cast!)
  /// final json = jsonEncode(payload.toMap());
  /// ```
  ///
  /// See [encrypt] for accepted [plaintext] types and [iv] behavior.
  AesPayload encryptToPayload(Object plaintext, {Uint8List? iv}) {
    final buffer = encrypt(plaintext, iv: iv);

    final ivB64 = base64Encode(buffer.sublist(0, standardIvSize));
    final data = base64Encode(buffer.sublist(standardIvSize));

    return AesPayload(iv: ivB64, data: data);
  }
}

/// A cipher for AES authenticated modes: [AesMode.gcm], [AesMode.ccm].
///
/// Authenticated Encryption with Associated Data (AEAD) provides both
/// confidentiality and integrity. On decrypt, Fortis verifies the auth tag
/// automatically and throws [FortisEncryptionException] if the ciphertext or
/// AAD has been tampered with.
///
/// Built via the matching mode builder:
/// ```dart
/// final cipher = Fortis.aes().gcm().cipher(key); // AesAuthCipher
/// final payload = cipher.encryptToPayload('hello'); // AesAuthPayload
/// print(payload.tag);                              // ✓ typed, no cast
/// ```
///
/// Use [AesGcmModeBuilder] for GCM (aad, ivSize; tag fixed at 128 bits) or
/// [AesCcmModeBuilder] for CCM (aad, ivSize, tagSize) to customize before
/// building.
final class AesAuthCipher extends AesCipher {
  /// Creates an authenticated AES cipher for GCM or CCM. Prefer the
  /// builder:
  ///
  /// ```dart
  /// final cipher = Fortis.aes().gcm().cipher(key); // or .ccm()
  /// ```
  ///
  /// Defaults: [tagSizeBits] = 128. [ivSize] defaults to 12 bytes for
  /// GCM and 11 bytes for CCM when `null`.
  ///
  /// Throws [FortisConfigException] if [mode] is not GCM/CCM, or if
  /// [tagSizeBits] is invalid for the chosen mode:
  /// - GCM accepts only 128 bits (PointyCastle limitation).
  /// - CCM accepts `{32, 48, 64, 80, 96, 112, 128}` per NIST SP 800-38C.
  factory AesAuthCipher({
    required AesMode mode,
    required FortisAesKey key,
    Uint8List? aad,
    int tagSizeBits = 128,
    int? ivSize,
  }) {
    if (mode != AesMode.gcm && mode != AesMode.ccm) {
      throw FortisConfigException(
        'AesAuthCipher only supports GCM or CCM, got ${mode.name.toUpperCase()}.',
      );
    }
    _validateAuthTagSize(mode, tagSizeBits);
    return AesAuthCipher._internal(
      mode: mode,
      key: key,
      aad: aad,
      tagSizeBits: tagSizeBits,
      ivSize:
          ivSize ?? (mode == AesMode.gcm ? gcmDefaultIvSize : ccmDefaultIvSize),
    );
  }

  AesAuthCipher._internal({
    required super.mode,
    required super.key,
    super.aad,
    super.tagSizeBits,
    required super.ivSize,
  }) : super._();

  /// Encrypts [plaintext] and returns a structured [AesAuthPayload].
  ///
  /// The payload carries the IV, ciphertext, and authentication tag as
  /// separate Base64 fields — matching the wire format used by .NET,
  /// Java, and OpenSSL libraries.
  ///
  /// Example:
  /// ```dart
  /// final cipher = Fortis.aes().gcm().cipher(key);
  /// final payload = cipher.encryptToPayload('hello fortis');
  ///
  /// // Send as JSON to a backend:
  /// final body = jsonEncode(payload.toMap(ivKey: 'nonce'));
  /// ```
  ///
  /// See [encrypt] for accepted [plaintext] types and [iv] behavior.
  AesAuthPayload encryptToPayload(Object plaintext, {Uint8List? iv}) {
    final buffer = encrypt(plaintext, iv: iv);

    final ivSize = _ivSize;
    final ivB64 = base64Encode(buffer.sublist(0, ivSize));
    final tag = base64Encode(buffer.sublist(buffer.length - authTagSize));
    final data = base64Encode(
      buffer.sublist(ivSize, buffer.length - authTagSize),
    );

    return AesAuthPayload(iv: ivB64, data: data, tag: tag);
  }
}

void _validateAuthTagSize(AesMode mode, int tagSizeBits) {
  if (mode == AesMode.gcm) {
    // PointyCastle only accepts 128-bit tags for GCM.
    if (tagSizeBits != 128) {
      throw FortisConfigException(
        'GCM tag size must be 128 bits, got $tagSizeBits. '
        'PointyCastle does not support other sizes for GCM.',
      );
    }
  } else {
    // CCM: NIST SP 800-38C allows {32, 48, 64, 80, 96, 112, 128}.
    const validCcmTagSizes = {32, 48, 64, 80, 96, 112, 128};
    if (!validCcmTagSizes.contains(tagSizeBits)) {
      throw FortisConfigException(
        'CCM tag size must be one of 32/48/64/80/96/112/128 bits '
        '(per NIST SP 800-38C), got $tagSizeBits.',
      );
    }
  }
}
