import 'dart:convert';
import 'dart:typed_data';

import 'package:fortis/fortis.dart';
import 'package:test/test.dart';

// Helpers para obter o tipo concreto do builder
AesBlockModeBuilder _blockMode(AesMode mode) =>
    Fortis.aes().mode(mode) as AesBlockModeBuilder;

AesAuthModeBuilder _authMode(AesMode mode) =>
    Fortis.aes().mode(mode) as AesAuthModeBuilder;

void main() {
  late FortisAesKey key;
  final plaintext = Uint8List.fromList('hello fortis'.codeUnits);

  setUpAll(() async {
    key = await Fortis.aes().keySize(256).generateKey();
  });

  group('AesEncrypter — GCM (recommended mode)', () {
    late AesEncrypter encrypter;

    setUp(() {
      encrypter = Fortis.aes().mode(AesMode.gcm).key(key).encrypter();
    });

    test('encrypt returns non-empty Uint8List', () {
      expect(encrypter.encrypt(plaintext), isNotEmpty);
    });

    test('nonce tem 12 bytes (NIST SP 800-38D)', () {
      // ciphertext = nonce(12) + encrypted_data + auth_tag(16)
      final ciphertext = encrypter.encrypt(plaintext);
      expect(ciphertext.length, equals(12 + plaintext.length + 16));
    });

    test('encrypted output differs from plaintext', () {
      expect(encrypter.encrypt(plaintext), isNot(equals(plaintext)));
    });

    test(
      'encrypting same plaintext twice produces different output (random IV)',
      () {
        final c1 = encrypter.encrypt(plaintext);
        final c2 = encrypter.encrypt(plaintext);
        expect(c1, isNot(equals(c2)));
      },
    );

    test('encryptString returns non-empty bytes', () {
      expect(encrypter.encryptString('hello fortis'), isNotEmpty);
    });

    test('encryptToBase64 returns valid non-empty Base64 string', () {
      final b64 = encrypter.encryptToBase64(plaintext);
      expect(b64, isNotEmpty);
      expect(() => base64Decode(b64), returnsNormally);
    });

    test('encryptStringToBase64 returns valid Base64 string', () {
      final b64 = encrypter.encryptStringToBase64('hello fortis');
      expect(() => base64Decode(b64), returnsNormally);
    });
  });

  group('AesEncrypter — ECB block mode', () {
    test('encrypts with ECB + pkcs7', () {
      final enc = _blockMode(
        AesMode.ecb,
      ).padding(AesPadding.pkcs7).key(key).encrypter();
      expect(enc.encrypt(plaintext), isNotEmpty);
    });

    test('encrypts with ECB + iso7816', () {
      final enc = _blockMode(
        AesMode.ecb,
      ).padding(AesPadding.iso7816).key(key).encrypter();
      expect(enc.encrypt(plaintext), isNotEmpty);
    });
  });

  group('AesEncrypter — CBC block mode', () {
    test('encrypts with CBC + pkcs7', () {
      final enc = _blockMode(
        AesMode.cbc,
      ).padding(AesPadding.pkcs7).key(key).encrypter();
      expect(enc.encrypt(plaintext), isNotEmpty);
    });

    test('encrypts with CBC + iso7816', () {
      final enc = _blockMode(
        AesMode.cbc,
      ).padding(AesPadding.iso7816).key(key).encrypter();
      expect(enc.encrypt(plaintext), isNotEmpty);
    });
  });

  group('AesEncrypter — stream modes', () {
    test('encrypts with CTR', () {
      final enc = Fortis.aes().mode(AesMode.ctr).key(key).encrypter();
      expect(enc.encrypt(plaintext), isNotEmpty);
    });

    test('encrypts with CFB', () {
      final enc = Fortis.aes().mode(AesMode.cfb).key(key).encrypter();
      expect(enc.encrypt(plaintext), isNotEmpty);
    });

    test('encrypts with OFB', () {
      final enc = Fortis.aes().mode(AesMode.ofb).key(key).encrypter();
      expect(enc.encrypt(plaintext), isNotEmpty);
    });

    test('CFB ciphertext tem tamanho IV(16) + plaintext (sem padding extra)', () {
      final enc = Fortis.aes().mode(AesMode.cfb).key(key).encrypter();
      expect(enc.encrypt(plaintext).length, equals(16 + plaintext.length));
    });

    test('OFB ciphertext tem tamanho IV(16) + plaintext (sem padding extra)', () {
      final enc = Fortis.aes().mode(AesMode.ofb).key(key).encrypter();
      expect(enc.encrypt(plaintext).length, equals(16 + plaintext.length));
    });
  });

  group('AesEncrypter — authenticated modes', () {
    test('encrypts with GCM', () {
      final enc = Fortis.aes().mode(AesMode.gcm).key(key).encrypter();
      expect(enc.encrypt(plaintext), isNotEmpty);
    });

    test('encrypts with CCM', () {
      final enc = Fortis.aes().mode(AesMode.ccm).key(key).encrypter();
      expect(enc.encrypt(plaintext), isNotEmpty);
    });

    test('encrypts with GCM + AAD', () {
      final aad = Uint8List.fromList('user-id-123'.codeUnits);
      final enc = _authMode(AesMode.gcm).aad(aad).key(key).encrypter();
      expect(enc.encrypt(plaintext), isNotEmpty);
    });

    test('encrypts with CCM + AAD', () {
      final aad = Uint8List.fromList('user-id-123'.codeUnits);
      final enc = _authMode(AesMode.ccm).aad(aad).key(key).encrypter();
      expect(enc.encrypt(plaintext), isNotEmpty);
    });
  });
}
