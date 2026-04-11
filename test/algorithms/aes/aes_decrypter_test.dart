import 'dart:convert';
import 'dart:typed_data';

import 'package:fortis/fortis.dart';
import 'package:test/test.dart';

// Helpers para obter o tipo concreto dos builders
AesBlockModeBuilder _blockMode(AesMode mode) =>
    Fortis.aes().mode(mode) as AesBlockModeBuilder;

AesAuthModeBuilder _authMode(AesMode mode) =>
    Fortis.aes().mode(mode) as AesAuthModeBuilder;

void main() {
  late FortisAesKey key;
  late FortisAesKey otherKey;
  final plaintext = Uint8List.fromList('hello fortis'.codeUnits);

  setUpAll(() async {
    key = await Fortis.aes().keySize(256).generateKey();
    otherKey = await Fortis.aes().keySize(256).generateKey();
  });

  group('AesDecrypter — GCM base', () {
    test('decrypt recovers original plaintext', () {
      final ciphertext = Fortis.aes()
          .mode(AesMode.gcm)
          .key(key)
          .encrypter()
          .encrypt(plaintext);
      final recovered = Fortis.aes()
          .mode(AesMode.gcm)
          .key(key)
          .decrypter()
          .decrypt(ciphertext);
      expect(recovered, equals(plaintext));
    });

    test(
      'end-to-end round-trip: generate → encrypt → decrypt → equal',
      () async {
        final newKey = await Fortis.aes().keySize(256).generateKey();
        final encrypter = Fortis.aes()
            .mode(AesMode.gcm)
            .key(newKey)
            .encrypter();
        final decrypter = Fortis.aes()
            .mode(AesMode.gcm)
            .key(newKey)
            .decrypter();
        expect(
          decrypter.decrypt(encrypter.encrypt(plaintext)),
          equals(plaintext),
        );
      },
    );

    test('wrong key throws FortisEncryptionException', () {
      final ciphertext = Fortis.aes()
          .mode(AesMode.gcm)
          .key(key)
          .encrypter()
          .encrypt(plaintext);
      expect(
        () => Fortis.aes()
            .mode(AesMode.gcm)
            .key(otherKey)
            .decrypter()
            .decrypt(ciphertext),
        throwsA(isA<FortisEncryptionException>()),
      );
    });

    test('decryptToString recovers UTF-8 string', () {
      const text = 'Fortis é uma biblioteca de criptografia!';
      final ciphertext = Fortis.aes()
          .mode(AesMode.gcm)
          .key(key)
          .encrypter()
          .encryptString(text);
      expect(
        Fortis.aes()
            .mode(AesMode.gcm)
            .key(key)
            .decrypter()
            .decryptToString(ciphertext),
        equals(text),
      );
    });

    test('decryptFromBase64 recovers bytes from Base64 ciphertext', () {
      final b64 = Fortis.aes()
          .mode(AesMode.gcm)
          .key(key)
          .encrypter()
          .encryptToBase64(plaintext);
      expect(
        Fortis.aes()
            .mode(AesMode.gcm)
            .key(key)
            .decrypter()
            .decryptFromBase64(b64),
        equals(plaintext),
      );
    });

    test('decryptFromBase64ToString recovers UTF-8 string from Base64', () {
      const text = 'hello fortis base64';
      final b64 = Fortis.aes()
          .mode(AesMode.gcm)
          .key(key)
          .encrypter()
          .encryptStringToBase64(text);
      expect(
        Fortis.aes()
            .mode(AesMode.gcm)
            .key(key)
            .decrypter()
            .decryptFromBase64ToString(b64),
        equals(text),
      );
    });

    test('end-to-end: encryptStringToBase64 → decryptFromBase64ToString', () {
      const text = 'round-trip via base64';
      final b64 = Fortis.aes()
          .mode(AesMode.gcm)
          .key(key)
          .encrypter()
          .encryptStringToBase64(text);
      expect(
        Fortis.aes()
            .mode(AesMode.gcm)
            .key(key)
            .decrypter()
            .decryptFromBase64ToString(b64),
        equals(text),
      );
    });
  });

  group('mode × padding matrix — block modes', () {
    final blockCombinations = [
      (AesMode.cbc, AesPadding.pkcs7),
      (AesMode.cbc, AesPadding.iso7816),
      (AesMode.cbc, AesPadding.zeroPadding),
      (AesMode.ecb, AesPadding.pkcs7),
      (AesMode.ecb, AesPadding.iso7816),
    ];

    final keySizes = [128, 192, 256];

    for (final (mode, padding) in blockCombinations) {
      for (final keySize in keySizes) {
        test('round-trip: $mode + $padding + $keySize-bit key', () async {
          final k = await Fortis.aes().keySize(keySize).generateKey();
          final encrypter = _blockMode(
            mode,
          ).padding(padding).key(k).encrypter();
          final decrypter = _blockMode(
            mode,
          ).padding(padding).key(k).decrypter();
          expect(
            decrypter.decrypt(encrypter.encrypt(plaintext)),
            equals(plaintext),
          );
        });
      }
    }
  });

  group('mode × key size matrix — stream modes', () {
    final keySizes = [128, 192, 256];

    for (final mode in [AesMode.ctr, AesMode.cfb, AesMode.ofb]) {
      for (final keySize in keySizes) {
        test('round-trip: $mode + $keySize-bit key', () async {
          final k = await Fortis.aes().keySize(keySize).generateKey();
          final encrypter = Fortis.aes().mode(mode).key(k).encrypter();
          final decrypter = Fortis.aes().mode(mode).key(k).decrypter();
          expect(
            decrypter.decrypt(encrypter.encrypt(plaintext)),
            equals(plaintext),
          );
        });
      }
    }
  });

  group('mode × key size matrix — authenticated modes', () {
    final keySizes = [128, 192, 256];

    for (final mode in [AesMode.gcm, AesMode.ccm]) {
      for (final keySize in keySizes) {
        test('round-trip: $mode + $keySize-bit key', () async {
          final k = await Fortis.aes().keySize(keySize).generateKey();
          final encrypter = Fortis.aes().mode(mode).key(k).encrypter();
          final decrypter = Fortis.aes().mode(mode).key(k).decrypter();
          expect(
            decrypter.decrypt(encrypter.encrypt(plaintext)),
            equals(plaintext),
          );
        });
      }
    }
  });

  group('GCM and CCM — AAD and auth tag', () {
    final aad = Uint8List.fromList(utf8.encode('user-id-123'));
    final otherAad = Uint8List.fromList(utf8.encode('user-id-456'));

    for (final mode in [AesMode.gcm, AesMode.ccm]) {
      group('$mode', () {
        test('matching AAD: encrypt + decrypt succeeds', () {
          final encrypter = _authMode(mode).aad(aad).key(key).encrypter();
          final decrypter = _authMode(mode).aad(aad).key(key).decrypter();
          expect(
            decrypter.decrypt(encrypter.encrypt(plaintext)),
            equals(plaintext),
          );
        });

        test('AAD mismatch throws FortisEncryptionException', () {
          final encrypter = _authMode(mode).aad(aad).key(key).encrypter();
          final decrypter = _authMode(mode).aad(otherAad).key(key).decrypter();
          expect(
            () => decrypter.decrypt(encrypter.encrypt(plaintext)),
            throwsA(isA<FortisEncryptionException>()),
          );
        });

        test(
          'AAD on encrypt, none on decrypt throws FortisEncryptionException',
          () {
            final encrypter = _authMode(mode).aad(aad).key(key).encrypter();
            final decrypter = Fortis.aes().mode(mode).key(key).decrypter();
            expect(
              () => decrypter.decrypt(encrypter.encrypt(plaintext)),
              throwsA(isA<FortisEncryptionException>()),
            );
          },
        );

        test('auth tag tampering throws FortisEncryptionException', () {
          final encrypter = Fortis.aes().mode(mode).key(key).encrypter();
          final decrypter = Fortis.aes().mode(mode).key(key).decrypter();
          final ciphertext = encrypter.encrypt(plaintext);
          // Flip a byte at the end (auth tag region)
          final tampered = Uint8List.fromList(ciphertext);
          tampered[tampered.length - 1] ^= 0xFF;
          expect(
            () => decrypter.decrypt(tampered),
            throwsA(isA<FortisEncryptionException>()),
          );
        });
      });
    }
  });
}
