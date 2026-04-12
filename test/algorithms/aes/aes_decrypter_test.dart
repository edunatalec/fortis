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
          .encrypter(key)
          .encrypt(plaintext);
      final recovered = Fortis.aes()
          .mode(AesMode.gcm)
          .decrypter(key)
          .decrypt(ciphertext);
      expect(recovered, equals(plaintext));
    });

    test(
      'end-to-end round-trip: generate → encrypt → decrypt → equal',
      () async {
        final newKey = await Fortis.aes().keySize(256).generateKey();
        final encrypter = Fortis.aes().mode(AesMode.gcm).encrypter(newKey);
        final decrypter = Fortis.aes().mode(AesMode.gcm).decrypter(newKey);
        expect(
          decrypter.decrypt(encrypter.encrypt(plaintext)),
          equals(plaintext),
        );
      },
    );

    test('wrong key throws FortisEncryptionException', () {
      final ciphertext = Fortis.aes()
          .mode(AesMode.gcm)
          .encrypter(key)
          .encrypt(plaintext);
      expect(
        () => Fortis.aes().mode(AesMode.gcm).decrypter(otherKey).decrypt(ciphertext),
        throwsA(isA<FortisEncryptionException>()),
      );
    });

    test('decryptToString recovers UTF-8 string', () {
      const text = 'Fortis é uma biblioteca de criptografia!';
      final ciphertext = Fortis.aes()
          .mode(AesMode.gcm)
          .encrypter(key)
          .encryptString(text);
      expect(
        Fortis.aes().mode(AesMode.gcm).decrypter(key).decryptToString(ciphertext),
        equals(text),
      );
    });

    test('decryptFromBase64 recovers bytes from Base64 ciphertext', () {
      final b64 = Fortis.aes()
          .mode(AesMode.gcm)
          .encrypter(key)
          .encryptToBase64(plaintext);
      expect(
        Fortis.aes().mode(AesMode.gcm).decrypter(key).decryptFromBase64(b64),
        equals(plaintext),
      );
    });

    test('decryptFromBase64ToString recovers UTF-8 string from Base64', () {
      const text = 'hello fortis base64';
      final b64 = Fortis.aes()
          .mode(AesMode.gcm)
          .encrypter(key)
          .encryptStringToBase64(text);
      expect(
        Fortis.aes().mode(AesMode.gcm).decrypter(key).decryptFromBase64ToString(b64),
        equals(text),
      );
    });

    test('end-to-end: encryptStringToBase64 → decryptFromBase64ToString', () {
      const text = 'round-trip via base64';
      final b64 = Fortis.aes()
          .mode(AesMode.gcm)
          .encrypter(key)
          .encryptStringToBase64(text);
      expect(
        Fortis.aes().mode(AesMode.gcm).decrypter(key).decryptFromBase64ToString(b64),
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
          final encrypter = _blockMode(mode).padding(padding).encrypter(k);
          final decrypter = _blockMode(mode).padding(padding).decrypter(k);
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
          final encrypter = Fortis.aes().mode(mode).encrypter(k);
          final decrypter = Fortis.aes().mode(mode).decrypter(k);
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
          final encrypter = Fortis.aes().mode(mode).encrypter(k);
          final decrypter = Fortis.aes().mode(mode).decrypter(k);
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
          final encrypter = _authMode(mode).aad(aad).encrypter(key);
          final decrypter = _authMode(mode).aad(aad).decrypter(key);
          expect(
            decrypter.decrypt(encrypter.encrypt(plaintext)),
            equals(plaintext),
          );
        });

        test('AAD mismatch throws FortisEncryptionException', () {
          final encrypter = _authMode(mode).aad(aad).encrypter(key);
          final decrypter = _authMode(mode).aad(otherAad).decrypter(key);
          expect(
            () => decrypter.decrypt(encrypter.encrypt(plaintext)),
            throwsA(isA<FortisEncryptionException>()),
          );
        });

        test(
          'AAD on encrypt, none on decrypt throws FortisEncryptionException',
          () {
            final encrypter = _authMode(mode).aad(aad).encrypter(key);
            final decrypter = Fortis.aes().mode(mode).decrypter(key);
            expect(
              () => decrypter.decrypt(encrypter.encrypt(plaintext)),
              throwsA(isA<FortisEncryptionException>()),
            );
          },
        );

        test('auth tag tampering throws FortisEncryptionException', () {
          final encrypter = Fortis.aes().mode(mode).encrypter(key);
          final decrypter = Fortis.aes().mode(mode).decrypter(key);
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

  group('AesDecrypter — decryptFields (GCM)', () {
    test('round-trip via decryptFields', () {
      final encrypter = Fortis.aes().mode(AesMode.gcm).encrypter(key);
      final decrypter = Fortis.aes().mode(AesMode.gcm).decrypter(key);
      final ciphertext = encrypter.encrypt(plaintext);
      // GCM layout: nonce(12) | data | tag(16)
      final nonce = base64Encode(ciphertext.sublist(0, 12));
      final data = base64Encode(ciphertext.sublist(12, ciphertext.length - 16));
      final tag = base64Encode(ciphertext.sublist(ciphertext.length - 16));
      expect(decrypter.decryptFields(iv: nonce, data: data, tag: tag), equals(plaintext));
    });

    test('decryptFieldsToString recovers UTF-8 string', () {
      const text = 'hello from fields';
      final encrypter = Fortis.aes().mode(AesMode.gcm).encrypter(key);
      final decrypter = Fortis.aes().mode(AesMode.gcm).decrypter(key);
      final ciphertext = encrypter.encryptString(text);
      final nonce = base64Encode(ciphertext.sublist(0, 12));
      final data = base64Encode(ciphertext.sublist(12, ciphertext.length - 16));
      final tag = base64Encode(ciphertext.sublist(ciphertext.length - 16));
      expect(
        decrypter.decryptFieldsToString(iv: nonce, data: data, tag: tag),
        equals(text),
      );
    });

    test('end-to-end: encrypt → extract fields → decryptFields → equal original', () {
      final encrypter = Fortis.aes().mode(AesMode.gcm).encrypter(key);
      final decrypter = Fortis.aes().mode(AesMode.gcm).decrypter(key);
      final ciphertext = encrypter.encrypt(plaintext);
      final fields = {
        'nonce': base64Encode(ciphertext.sublist(0, 12)),
        'data': base64Encode(ciphertext.sublist(12, ciphertext.length - 16)),
        'tag': base64Encode(ciphertext.sublist(ciphertext.length - 16)),
      };
      expect(
        decrypter.decryptFields(
          iv: fields['nonce']!,
          data: fields['data']!,
          tag: fields['tag']!,
        ),
        equals(plaintext),
      );
    });

    test(
      'end-to-end: encryptStringToBase64 → extract fields → decryptFieldsToString → equal original',
      () {
        const text = 'round-trip via fields';
        final encrypter = Fortis.aes().mode(AesMode.gcm).encrypter(key);
        final decrypter = Fortis.aes().mode(AesMode.gcm).decrypter(key);
        final rawBytes = base64Decode(encrypter.encryptStringToBase64(text));
        final nonce = base64Encode(rawBytes.sublist(0, 12));
        final data = base64Encode(rawBytes.sublist(12, rawBytes.length - 16));
        final tag = base64Encode(rawBytes.sublist(rawBytes.length - 16));
        expect(
          decrypter.decryptFieldsToString(iv: nonce, data: data, tag: tag),
          equals(text),
        );
      },
    );

    test('wrong auth tag throws FortisEncryptionException', () {
      final encrypter = Fortis.aes().mode(AesMode.gcm).encrypter(key);
      final decrypter = Fortis.aes().mode(AesMode.gcm).decrypter(key);
      final ciphertext = encrypter.encrypt(plaintext);
      final nonce = base64Encode(ciphertext.sublist(0, 12));
      final data = base64Encode(ciphertext.sublist(12, ciphertext.length - 16));
      final tag = base64Encode(Uint8List(16)); // zeroed-out tag — invalid
      expect(
        () => decrypter.decryptFields(iv: nonce, data: data, tag: tag),
        throwsA(isA<FortisEncryptionException>()),
      );
    });
  });

  group('AesDecrypter — decryptMap (GCM)', () {
    test('round-trip via decryptMap with nonce key', () {
      final encrypter = Fortis.aes().mode(AesMode.gcm).encrypter(key);
      final decrypter = Fortis.aes().mode(AesMode.gcm).decrypter(key);
      final ciphertext = encrypter.encrypt(plaintext);
      final payload = {
        'nonce': base64Encode(ciphertext.sublist(0, 12)),
        'data': base64Encode(ciphertext.sublist(12, ciphertext.length - 16)),
        'tag': base64Encode(ciphertext.sublist(ciphertext.length - 16)),
      };
      expect(decrypter.decryptMap(payload), equals(plaintext));
    });

    test('round-trip via decryptMap with iv key', () {
      final encrypter = Fortis.aes().mode(AesMode.gcm).encrypter(key);
      final decrypter = Fortis.aes().mode(AesMode.gcm).decrypter(key);
      final ciphertext = encrypter.encrypt(plaintext);
      final payload = {
        'iv': base64Encode(ciphertext.sublist(0, 12)),
        'data': base64Encode(ciphertext.sublist(12, ciphertext.length - 16)),
        'tag': base64Encode(ciphertext.sublist(ciphertext.length - 16)),
      };
      expect(decrypter.decryptMap(payload), equals(plaintext));
    });

    test('decryptMapToString recovers UTF-8 string', () {
      const text = 'hello from map';
      final encrypter = Fortis.aes().mode(AesMode.gcm).encrypter(key);
      final decrypter = Fortis.aes().mode(AesMode.gcm).decrypter(key);
      final ciphertext = encrypter.encryptString(text);
      final payload = {
        'nonce': base64Encode(ciphertext.sublist(0, 12)),
        'data': base64Encode(ciphertext.sublist(12, ciphertext.length - 16)),
        'tag': base64Encode(ciphertext.sublist(ciphertext.length - 16)),
      };
      expect(decrypter.decryptMapToString(payload), equals(text));
    });

    test("throws FortisConfigException when 'data' is missing", () {
      final decrypter = Fortis.aes().mode(AesMode.gcm).decrypter(key);
      expect(
        () => decrypter.decryptMap({'iv': 'abc==', 'tag': 'xyz=='}),
        throwsA(isA<FortisConfigException>()),
      );
    });

    test("throws FortisConfigException when both 'iv' and 'nonce' are present", () {
      final decrypter = Fortis.aes().mode(AesMode.gcm).decrypter(key);
      expect(
        () => decrypter.decryptMap({
          'iv': 'AAAA',
          'nonce': 'BBBB',
          'data': 'CCCC',
          'tag': 'DDDD',
        }),
        throwsA(isA<FortisConfigException>()),
      );
    });

    test("throws FortisConfigException when neither 'iv' nor 'nonce' is present", () {
      final decrypter = Fortis.aes().mode(AesMode.gcm).decrypter(key);
      expect(
        () => decrypter.decryptMap({'data': 'CCCC', 'tag': 'DDDD'}),
        throwsA(isA<FortisConfigException>()),
      );
    });

    test("throws FortisConfigException when 'tag' is missing", () {
      final decrypter = Fortis.aes().mode(AesMode.gcm).decrypter(key);
      expect(
        () => decrypter.decryptMap({'iv': 'abc==', 'data': 'xyz=='}),
        throwsA(isA<FortisConfigException>()),
      );
    });

    test('interop: decryptMap recovers .NET-style separated fields', () {
      final encrypter = Fortis.aes().mode(AesMode.gcm).encrypter(key);
      final decrypter = Fortis.aes().mode(AesMode.gcm).decrypter(key);
      const originalString = 'hello fortis';
      final ciphertext = encrypter.encryptString(originalString);
      // Simulate what a .NET/Java backend would return
      final nonce = ciphertext.sublist(0, 12);
      final tag = ciphertext.sublist(ciphertext.length - 16);
      final data = ciphertext.sublist(12, ciphertext.length - 16);
      final payload = {
        'nonce': base64Encode(nonce),
        'data': base64Encode(data),
        'tag': base64Encode(tag),
      };
      expect(decrypter.decryptMapToString(payload), equals(originalString));
    });
  });

  group('AesDecrypter — CCM interoperability', () {
    test('CCM round-trip with 11-byte nonce via decryptFields', () {
      final encrypter = Fortis.aes().mode(AesMode.ccm).encrypter(key);
      final decrypter = Fortis.aes().mode(AesMode.ccm).decrypter(key);
      final ciphertext = encrypter.encrypt(plaintext);
      // CCM layout: nonce(11) | data | tag(16)
      final nonce = base64Encode(ciphertext.sublist(0, 11));
      final data = base64Encode(ciphertext.sublist(11, ciphertext.length - 16));
      final tag = base64Encode(ciphertext.sublist(ciphertext.length - 16));
      expect(
        decrypter.decryptFields(iv: nonce, data: data, tag: tag),
        equals(plaintext),
      );
    });
  });
}
